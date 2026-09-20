from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from html import unescape
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlparse

from mks123_pipeline.manufacturer_evidence import (
    ManufacturerIdentity,
    classify_candidates,
    has_exact_product_page_signal,
    page_identity_text,
)

_MAX_BODY_BYTES = 500_000
_MAX_PARSER_ROWS = 10_000
_MAX_PARSER_LINKS = 1_000
_CSS_HIDDEN_RE = re.compile(r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|content-visibility\s*:\s*hidden)")
_CSS_STYLESHEET_RE = re.compile(r"(?is)<link\b[^>]*\brel\s*=\s*[\"'][^\"']*\bstylesheet\b|<link\b[^>]*\brel\s*=\s*stylesheet\b")


def _css_visibility_uncertain(body: str) -> bool:
    return bool(_CSS_STYLESHEET_RE.search(body) or _CSS_HIDDEN_RE.search(body))


_FIELD_LABELS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("dimensions", (r"\bгабарит\w*\b", r"\bразмер(?:ы|а|ов|ом|ами)?\b", r"\bdimensions?\b")),
    ("weight", (r"\bвес\w*\b", r"\bweights?\b")),
    ("resource_pages", (r"\bресурс\w*\b", r"\bresources?\b", r"\bpages?\b")),
    ("fan_diameter", (r"\bвентилятор\w*\b", r"\bfan[ -]?diameter\b")),
    ("ports", (r"\bпорт(?:ы|ов|ами)?\b", r"\bports?\b", r"\bинтерфейс\w*\b", r"\binterfaces?\b")),
    ("compatibility", (r"\bсовместим\w*\b", r"\bcompatib\w*\b")),
)


@dataclass(frozen=True)
class _Row:
    cells: tuple[str, ...]
    context: str = ""
    in_product_scope: bool = False
    table_id: int = -1


def _hidden_element(attributes: dict[str, str | None]) -> bool:
    style = (attributes.get("style") or "").casefold().replace(" ", "")
    classes = set((attributes.get("class") or "").casefold().split())
    if "inert" in attributes or re.search(r"(?:^|;)(?:display|visibility|opacity|content-visibility):", style):
        return True
    return "hidden" in attributes or (attributes.get("aria-hidden") or "").casefold() == "true" or "display:none" in style or "visibility:hidden" in style or "opacity:0" in style or "content-visibility:hidden" in style or bool(classes & {"hidden", "d-none", "visually-hidden", "sr-only", "visuallyhidden", "invisible", "collapse", "d-print-none", "opacity-0"})


@dataclass(frozen=True)
class _Link:
    text: str
    href: str
    table_id: int
    in_product_scope: bool


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[_Row] = []
        self.links: list[_Link] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._cell_tag: str | None = None
        self._cell_hidden_depth = 0
        self._row_hidden = False
        self._row_non_rendered = False
        self._link_text: list[str] | None = None
        self._link_href: str | None = None
        self._link_table_id = -1
        self._link_scope = False
        self._link_allowed = False
        self._scope_depth = 0
        self._hidden_depth = 0
        self._non_rendered_depth = 0
        self._tag_stack: list[tuple[str, bool, bool]] = []
        self._table_counter = 0
        self._table_stack: list[int] = []
        self._container_stack: list[tuple[str, str]] = []
        self._table_context = ""
        self._section_context = ""
        self._context_tag: str | None = None
        self._context_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = dict(attrs)
        hidden = _hidden_element(attributes)
        non_rendered = tag in {"script", "style", "template", "noscript"}
        self._tag_stack.append((tag, hidden, non_rendered))
        if hidden:
            self._hidden_depth += 1
        if non_rendered:
            self._non_rendered_depth += 1
        if tag == "main" or tag == "article":
            self._scope_depth += 1
        if tag in {"section", "article", "div", "form", "main"}:
            context = _clean(f"{attributes.get('id') or ''} {attributes.get('class') or ''} {attributes.get('aria-label') or ''} {attributes.get('title') or ''}")
            self._container_stack.append((tag, context))
        if tag == "table":
            self._finish_row()
            self._table_counter += 1
            self._table_stack.append(self._table_counter)
            self._table_context = _clean(f"{attributes.get('id') or ''} {attributes.get('class') or ''}")
        elif tag == "caption":
            self._context_tag = "caption"
            self._context_parts = []
        elif tag in {"h2", "h3", "h4", "h5", "h6"}:
            self._context_tag = "section"
            self._context_parts = []
        if tag == "tr":
            self._finish_row()
            self._row = []
            self._row_hidden = hidden
            self._row_non_rendered = non_rendered
        else:
            if self._row is not None:
                self._row_hidden = self._row_hidden or hidden
                self._row_non_rendered = self._row_non_rendered or non_rendered
            if tag in {"th", "td"}:
                if self._row is None:
                    self._row = []
                self._cell = []
                self._cell_tag = tag
                self._cell_hidden_depth = self._hidden_depth
            elif tag == "a":
                self._link_text = []
                self._link_href = attributes.get("href")
                self._link_table_id = self._table_stack[-1] if self._table_stack else -1
                self._link_scope = self._hidden_depth == 0 and self._non_rendered_depth == 0 and self._scope_depth > 0
                self._link_allowed = self._link_scope

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "a" and self._link_text is not None:
            text = _clean("".join(self._link_text))
            href = self._link_href or ""
            if href and self._link_allowed:
                if len(self.links) >= _MAX_PARSER_LINKS:
                    raise ValueError("HTML link count exceeds bounded limit")
                self.links.append(_Link(text, href, self._link_table_id, self._link_scope))
            self._link_text = None
            self._link_href = None
            self._link_allowed = False
        elif tag in {"th", "td"} and self._cell is not None and self._cell_tag == tag:
            self._row = self._row or []
            self._row.append(_clean("".join(self._cell)))
            self._cell = None
            self._cell_tag = None
        elif tag == "tr":
            self._finish_row()
        elif tag == "caption" and self._context_tag == "caption":
            self._table_context = _clean(f"{self._table_context} {' '.join(self._context_parts)}")
            self._context_tag = None
            self._context_parts = []
        elif tag in {"h2", "h3", "h4", "h5", "h6"} and self._context_tag == "section":
            self._section_context = _clean("".join(self._context_parts))
            self._context_tag = None
            self._context_parts = []
        elif tag == "table":
            self._finish_row()
            if self._table_stack:
                self._table_stack.pop()
            self._table_context = ""
        elif tag == "main" or tag == "article":
            self._scope_depth = max(0, self._scope_depth - 1)
        if tag in {"section", "article", "div", "form", "main"}:
            for index in range(len(self._container_stack) - 1, -1, -1):
                if self._container_stack[index][0] == tag:
                    self._container_stack.pop(index)
                    break
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index][0] == tag:
                _tag, hidden, non_rendered = self._tag_stack.pop(index)
                if hidden:
                    self._hidden_depth = max(0, self._hidden_depth - 1)
                if non_rendered:
                    self._non_rendered_depth = max(0, self._non_rendered_depth - 1)
                break

    def handle_data(self, data: str) -> None:
        if self._cell is not None and self._non_rendered_depth == 0 and self._hidden_depth <= self._cell_hidden_depth:
            self._cell.append(data)
        if self._hidden_depth > 0 or self._non_rendered_depth > 0:
            return
        if self._link_text is not None:
            self._link_text.append(data)
        if self._context_tag is not None:
            self._context_parts.append(data)

    def close(self) -> None:
        super().close()
        self._finish_row()

    def _finish_row(self) -> None:
        if self._row:
            container_context = " ".join(context for _tag, context in self._container_stack if context)
            context = _clean(f"{self._section_context} {self._table_context} {container_context}")
            table_id = self._table_stack[-1] if self._table_stack else -1
            if len(self.rows) >= _MAX_PARSER_ROWS:
                raise ValueError("HTML row count exceeds bounded limit")
            self.rows.append(_Row(tuple(self._row), context, self._scope_depth > 0 and self._hidden_depth == 0 and self._non_rendered_depth == 0 and not self._row_hidden and not self._row_non_rendered, table_id))
        self._row = None
        self._cell = None
        self._cell_tag = None
        self._row_hidden = False
        self._row_non_rendered = False


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", unescape(value)).strip()


def _label_field(label: str) -> str | None:
    normalized = _clean(label).casefold()
    for field, patterns in _FIELD_LABELS:
        if any(re.search(pattern, normalized) for pattern in patterns):
            return field
    return None


def _packaging_context(value: str) -> bool:
    return bool(re.search(r"\b(упаков\w*|package\w*|packaging\w*|shipping\w*|gross\w*|брутто\w*|короб\w*|related\w*|comparison\w*|сравн\w*|похож\w*|рекоменд\w*|друг(?:ие|их|ой)?\s+товар\w*)\b", value.casefold()))


_SENSITIVE_PATH_RE = re.compile(r"(?i)^(?:token|secret|session(?:[-_]?id)?|auth|credential|signature|password|passwd|api[-_]?key|access[-_]?token|bearer)$")


def _sensitive_url_parts(parsed) -> bool:
    path_parts = [unquote(part) for part in parsed.path.split("/") if part]
    return bool(parsed.fragment or parsed.query or any(_SENSITIVE_PATH_RE.fullmatch(part) or len(part) > 128 for part in path_parts))


def _safe_same_host_url(source_url: str, href: str) -> tuple[str | None, str | None]:
    try:
        source = urlparse(source_url)
        source_port = source.port
    except (TypeError, ValueError):
        return None, "source URL has malformed port"
    if source.scheme != "https" or not source.hostname or source.username or source.password:
        return None, "invalid source URL for document link"
    if source_port not in ({None, 80} if source.scheme == "http" else {None, 443}) or _sensitive_url_parts(source):
        return None, "source URL uses a disallowed port or sensitive query/fragment"
    try:
        target = urlparse(urljoin(source_url, href))
        target_port = target.port
    except (TypeError, ValueError):
        return None, "document link has malformed port"
    if target.scheme != "https" or not target.hostname or target.username or target.password:
        return None, "document link is not a safe HTTPS URL"
    if target.scheme != source.scheme:
        return None, "document link changes URL scheme"
    if target_port not in ({None, 80} if target.scheme == "http" else {None, 443}) or _sensitive_url_parts(target):
        return None, "document link uses a disallowed port or sensitive query/fragment"
    source_host = source.hostname.lower().removeprefix("www.").rstrip(".")
    target_host = target.hostname.lower().removeprefix("www.").rstrip(".")
    if source_host != target_host:
        return None, "document link leaves source host family"
    return target.geturl(), None


def _link_field(text: str, href: str) -> str | None:
    label = _clean(text).casefold()
    try:
        href_path = urlparse(href).path.casefold()
    except (TypeError, ValueError):
        return None
    filename = href_path.rsplit("/", 1)[-1]
    extension = filename.rsplit(".", 1)[-1] if "." in filename else ""
    driver_label = bool(re.search(r"\bдрайвер\w*\b|\bdrivers?\b", label))
    manual_label = bool(re.search(r"\b(инструк\w*|руковод\w*)\b|\b(manual|instruction|datasheet)s?\b", label))
    allowed_extensions = {"pdf", "zip", "rar", "7z"}
    if extension not in allowed_extensions:
        return None
    if driver_label:
        return "driver_url"
    if manual_label:
        return "manual_url"
    return None


def _identity_table_sets(parser: _PageParser, identity: ManufacturerIdentity | None = None) -> tuple[set[int], set[int], set[int]]:
    model_tables: set[int] = set()
    mpn_tables: set[int] = set()
    ean_tables: set[int] = set()
    competing_model_tables: set[int] = set()
    competing_mpn_tables: set[int] = set()
    competing_ean_tables: set[int] = set()
    for row in parser.rows:
        if not row.in_product_scope or _packaging_context(f"{row.context} {' '.join(row.cells)}") or len(row.cells) != 2 or row.table_id < 0:
            continue
        label = _clean(row.cells[0]).casefold()
        value = _clean(row.cells[1])
        is_model = bool(re.search(r"\b(модель|model)\b", label))
        is_mpn = bool(re.search(r"\b(mpn|part[ -]?number|артикул|код\s*товара|product\s*code)\b", label))
        is_ean = bool(re.search(r"\b(ean|штрихкод|баркод|barcode)\b", label))
        if is_model and is_mpn:
            continue
        if identity is None:
            if is_model:
                model_tables.add(row.table_id)
            if is_mpn:
                mpn_tables.add(row.table_id)
            if is_ean:
                ean_tables.add(row.table_id)
            continue
        if is_model:
            if _exact_value(value, identity.model):
                model_tables.add(row.table_id)
            else:
                competing_model_tables.add(row.table_id)
        if is_mpn and identity.mpn:
            if _exact_value(value, identity.mpn):
                mpn_tables.add(row.table_id)
            else:
                competing_mpn_tables.add(row.table_id)
        if is_ean and identity.ean:
            if _exact_value(value, identity.ean):
                ean_tables.add(row.table_id)
            else:
                competing_ean_tables.add(row.table_id)
    if identity is not None:
        ambiguous = competing_model_tables | competing_mpn_tables | competing_ean_tables
        model_tables -= ambiguous
        mpn_tables -= ambiguous
        ean_tables -= ambiguous
    return model_tables, mpn_tables, ean_tables


def _identity_row_signals(body: str, identity: ManufacturerIdentity) -> tuple[bool, bool]:
    if _css_visibility_uncertain(body):
        return False, False
    parser = _PageParser()
    parser.feed(body)
    parser.close()
    model_tables, mpn_tables, ean_tables = _identity_table_sets(parser, identity)
    strong_tables = model_tables & mpn_tables if identity.mpn else model_tables
    if identity.ean:
        strong_tables &= ean_tables
    return bool(model_tables), bool(strong_tables)


def _exact_value(actual: str, expected: str) -> bool:
    return bool(re.fullmatch(re.escape(expected.strip()), actual.strip(), flags=re.IGNORECASE))


def has_labeled_identity(body: str, identity: ManufacturerIdentity) -> bool:
    try:
        model_signal, mpn_signal = _identity_row_signals(body, identity)
    except (IndexError, TypeError, ValueError, UnicodeError):
        return False
    return model_signal and mpn_signal


def extract_field_evidence(body_text: str, source_url: str, retrieved_at: str, body_sha256: str, identity: ManufacturerIdentity | None = None) -> tuple[list[dict], list[str]]:
    if not isinstance(body_text, str) or not body_text.strip():
        return [], ["source body is missing"]
    if len(body_text) > _MAX_BODY_BYTES:
        return [], ["source body exceeds bounded size"]
    if _css_visibility_uncertain(body_text):
        return [], ["source body has unverified CSS visibility"]
    if not isinstance(retrieved_at, str) or not retrieved_at.strip():
        return [], ["retrieval timestamp is missing"]
    if not isinstance(body_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", body_sha256):
        return [], ["source body hash is missing or malformed"]
    if not isinstance(source_url, str) or not source_url:
        return [], ["source_url: source URL is missing or malformed"]
    safe_source_url, source_error = _safe_same_host_url(source_url, "")
    if source_error:
        return [], [f"source_url: {source_error}"]
    source_url = safe_source_url
    parser = _PageParser()
    try:
        parser.feed(body_text)
        parser.close()
    except (IndexError, TypeError, ValueError) as exc:
        return [], [f"HTML parse failed: {type(exc).__name__}"]
    values: list[dict] = []
    exceptions: list[str] = []
    model_tables, mpn_tables, ean_tables = _identity_table_sets(parser, identity)
    identity_table_ids = model_tables & mpn_tables if identity and identity.mpn else model_tables
    if identity and identity.ean:
        identity_table_ids &= ean_tables
    for row in parser.rows:
        if len(row.cells) < 2:
            continue
        field = _label_field(row.cells[0])
        if not row.in_product_scope:
            if field:
                exceptions.append(f"{field}: row is outside product scope")
            continue
        if field and row.table_id not in identity_table_ids:
            exceptions.append(f"{field}: row is not bound to the identity table")
            continue
        if _packaging_context(f"{row.context} {row.cells[0]} {row.cells[1]}"):
            if field:
                exceptions.append(f"{field}: packaging/shipping context requires review")
            continue
        if len(row.cells) > 2:
            if field:
                exceptions.append(f"{field}: multi-cell row requires review")
            continue
        value = _clean(row.cells[1])
        if field and value:
            values.append({"field": field, "value": value, "quote": f"{row.cells[0]}: {value}", "source_url": source_url, "retrieved_at": retrieved_at, "body_sha256": body_sha256})
    for link in parser.links:
        field = _link_field(link.text, link.href)
        if not field:
            document_label = _clean(link.text).casefold()
            if re.search(r"\bдрайвер\w*\b|\bdrivers?\b", document_label):
                exceptions.append("driver_url: labeled link is not an allowed static document")
            elif re.search(r"\b(инструк\w*|руковод\w*)\b|\b(manual|instruction|datasheet)s?\b", document_label):
                exceptions.append("manual_url: labeled link is not an allowed static document")
            continue
        if not link.in_product_scope:
            exceptions.append(f"{field}: document link is outside product scope")
            continue
        if link.table_id not in identity_table_ids:
            exceptions.append(f"{field}: document link is not bound to the identity table")
            continue
        resolved, error = _safe_same_host_url(source_url, link.href)
        if error:
            exceptions.append(f"{field}: {error}")
            continue
        values.append({"field": field, "value": resolved, "quote": f"{link.text}: {link.href}", "source_url": source_url, "retrieved_at": retrieved_at, "body_sha256": body_sha256})
    return values, exceptions


def _value_key(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _identity(item: dict) -> ManufacturerIdentity:
    raw = item.get("identity")
    if not isinstance(raw, dict):
        raise TypeError("fetch item identity must be an object")
    values = {}
    for field in ("manufacturer", "model"):
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise TypeError(f"identity.{field} must be a non-empty string")
        values[field] = value.strip()
    for field in ("mpn", "ean"):
        value = raw.get(field)
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise TypeError(f"identity.{field} must be a non-empty string when present")
            values[field] = value.strip()
    return ManufacturerIdentity(**values)


def _safe_verified_source_url(url: object, verified_domains: set[str]) -> bool:
    if not isinstance(url, str) or not url or len(url) > 4096 or any(ord(char) < 32 for char in url):
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False
    if port not in ({None, 80} if parsed.scheme == "http" else {None, 443}) or _sensitive_url_parts(parsed):
        return False
    host = parsed.hostname.casefold().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        if address.version == 6 and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not (address.is_global and not address.is_private and not address.is_loopback and not address.is_link_local and not address.is_reserved and not address.is_multicast and not address.is_unspecified):
            return False
    except ValueError:
        pass
    return any(host == domain or host.endswith(f".{domain}") for domain in verified_domains)


def _verified_exact(entry: object, identity: ManufacturerIdentity, verified_domains: set[str]) -> tuple[bool, str | None]:
    if not isinstance(entry, dict):
        return False, "fetch entry is not an object"
    if entry.get("status") != "ok" or entry.get("http_status") != 200:
        return False, "source response is not HTTP 200"
    if entry.get("content_type") not in {"text/html", "application/xhtml+xml", "text/plain", "application/xml", "text/xml"}:
        return False, "source response is not a supported textual page"
    if entry.get("too_large") is not False or entry.get("redirect_location") not in {None, ""} or entry.get("error") not in {None, ""}:
        return False, "source response metadata is inconsistent"
    if entry.get("sensitive_content") is True or entry.get("body_persisted") is False:
        return False, "source body was screened and is not available for exact resolution"
    body = entry.get("body_text")
    if not isinstance(body, str) or not body.strip():
        return False, "source body is missing"
    if len(body) > _MAX_BODY_BYTES:
        return False, "source body exceeds bounded size"
    try:
        calculated_text_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        return False, "source textual body contains invalid Unicode"
    body_text_hash = entry.get("body_text_sha256")
    if not isinstance(body_text_hash, str) or body_text_hash.casefold() != calculated_text_hash:
        return False, "source textual body hash does not match body_text"
    raw_b64 = entry.get("body_b64")
    if not isinstance(raw_b64, str) or len(raw_b64) > 4 * ((_MAX_BODY_BYTES + 2) // 3) + 4:
        return False, "raw source body exceeds bounded size"
    try:
        raw_body = base64.b64decode(raw_b64, validate=True)
        decoded_body = raw_body.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return False, "raw source body is malformed or not UTF-8"
    if len(raw_body) > _MAX_BODY_BYTES:
        return False, "raw source body exceeds bounded size"
    body_hash = entry.get("body_sha256")
    if not isinstance(body_hash, str) or body_hash.casefold() != hashlib.sha256(raw_body).hexdigest():
        return False, "raw source body hash does not match body_b64"
    if decoded_body != body:
        return False, "raw source body and body_text differ"
    if not _valid_timestamp(entry.get("retrieved_at")):
        return False, "retrieval timestamp is malformed"
    url = entry.get("url")
    if not _safe_verified_source_url(url, verified_domains):
        return False, "source URL is missing, unsafe, or outside verified domains"
    try:
        title_text, heading_text = page_identity_text(body)
        page_candidate = classify_candidates(identity, [{"title": "", "url": "", "description": f"{title_text} {heading_text}"}], official_domains=set()).candidates[0]
        url_candidate = classify_candidates(identity, [{"title": "", "url": url, "description": ""}], official_domains=verified_domains).candidates[0]
        product_signal = has_exact_product_page_signal(url, body, identity.model)
    except (IndexError, TypeError, ValueError, UnicodeError):
        return False, "source identity parsing failed"
    exact = url_candidate.official_domain and page_candidate.manufacturer_match and page_candidate.exact_model and has_labeled_identity(body, identity) and product_signal
    if not exact:
        return False, "source failed verified-domain/body-local exact identity checks"
    return True, None


def resolve_fetch_item(item: dict, *, verified_domains: set[str]) -> dict:
    sku = item.get("catalog_sku")
    if not isinstance(sku, str) or not sku.strip() or sku != sku.strip():
        return {"catalog_sku": sku, "status": "invalid_input", "auto_apply": False, "proposal_candidates": [], "exceptions": ["catalog_sku must be a non-empty trimmed string"]}
    if not isinstance(verified_domains, set) or any(not isinstance(domain, str) or not domain.strip() for domain in verified_domains):
        return {"catalog_sku": sku, "status": "invalid_input", "auto_apply": False, "proposal_candidates": [], "exceptions": ["verified_domains must be a set of strings"]}
    try:
        identity = _identity(item)
    except (TypeError, ValueError) as exc:
        return {"catalog_sku": sku, "status": "invalid_input", "auto_apply": False, "proposal_candidates": [], "exceptions": [str(exc)]}
    fetched = item.get("fetched")
    if not isinstance(fetched, list):
        return {"catalog_sku": sku, "status": "invalid_input", "auto_apply": False, "proposal_candidates": [], "exceptions": ["fetched must be a list"]}
    exact_entries: list[dict] = []
    rejection_reasons: list[str] = []
    for entry in fetched:
        exact, reason = _verified_exact(entry, identity, verified_domains)
        if exact:
            exact_entries.append(entry)
        elif reason:
            rejection_reasons.append(reason)
    if not exact_entries:
        return {"catalog_sku": sku, "status": "no_exact_source", "auto_apply": False, "proposal_candidates": [], "exceptions": ["no exact product-page manufacturer evidence"] if not rejection_reasons else ["no exact product-page manufacturer evidence", *sorted(set(rejection_reasons))]}
    all_values: dict[str, dict[str, dict]] = {}
    exceptions: list[str] = []
    rejected_fields: set[str] = set()
    for entry in exact_entries:
        fields, field_errors = extract_field_evidence(entry["body_text"], entry["url"], entry["retrieved_at"], entry["body_sha256"], identity)
        exceptions.extend(field_errors)
        rejected_fields.update(error.split(":", 1)[0] for error in field_errors if ":" in error)
        for field in fields:
            if field["field"] not in rejected_fields:
                all_values.setdefault(field["field"], {})[_value_key(field["value"])] = field
    for field in rejected_fields:
        all_values.pop(field, None)
    proposals: list[dict] = []
    for field, values in all_values.items():
        if len(values) == 1:
            proposals.append(next(iter(values.values())))
        else:
            exceptions.append(f"{field}: conflicting exact-source values require review")
    if proposals:
        status = "proposal_candidates"
    elif exceptions:
        status = "source_body_unusable"
    else:
        status = "no_supported_fields"
    return {"catalog_sku": sku, "status": status, "auto_apply": False, "compatibility_relations": 0, "proposal_candidates": sorted(proposals, key=lambda value: (value["field"], value["value"])), "exceptions": sorted(set(exceptions))}
