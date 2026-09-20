from __future__ import annotations

import hashlib
import html
import ipaddress
import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse


class EvidenceStatus(str, Enum):
    OFFICIAL_IDENTITY_CANDIDATE = "official_identity_candidate"
    OFFICIAL_FAMILY_ONLY = "official_family_only"
    SECONDARY_ONLY = "secondary_only"
    UNCONFIRMED = "unconfirmed"


@dataclass(frozen=True)
class ManufacturerIdentity:
    manufacturer: str
    model: str
    mpn: str | None = None
    ean: str | None = None

    def __post_init__(self) -> None:
        limits = {"manufacturer": 256, "model": 256, "mpn": 256, "ean": 64}
        for field, limit in limits.items():
            value = getattr(self, field)
            if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(char) < 32 for char in value)):
                raise ValueError(f"{field} must be a bounded non-empty string when present")
        if not isinstance(self.manufacturer, str) or not self.manufacturer.strip():
            raise ValueError("manufacturer must be a non-empty string")
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must be a non-empty string")


@dataclass(frozen=True)
class EvidenceCandidate:
    title: str
    url: str
    description: str
    official_domain: bool
    manufacturer_match: bool
    exact_model: bool
    exact_mpn: bool
    exact_ean: bool


@dataclass(frozen=True)
class EvidenceResult:
    identity: ManufacturerIdentity
    status: EvidenceStatus
    candidates: tuple[EvidenceCandidate, ...]
    auto_publish: bool = False


_PSL_SHA256 = "4b673689999dbaca60b93fa3e1da5752505ef9717b1c4dc44acbfdafd35679ea"
TRUSTED_DOMAIN_REGISTRY_SHA256 = "ac72e8ea348aa72bf67bf7badc52c202258d50f1b4c8000007d9a9472c9aac5e"
_RESERVED_DOMAIN_SUFFIXES = {"example", "invalid", "localhost", "test", "local", "internal", "arpa"}
_MAX_PSL_BYTES = 5_000_000
_CSS_HIDDEN_RE = re.compile(r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)|content-visibility\s*:\s*hidden)")
_CSS_STYLESHEET_RE = re.compile(r"(?is)<link\b[^>]*\brel\s*=\s*[\"'][^\"']*\bstylesheet\b|<link\b[^>]*\brel\s*=\s*stylesheet\b")


def _read_psl_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("public suffix list cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size < 0 or info.st_size > _MAX_PSL_BYTES:
            raise RuntimeError("public suffix list is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise RuntimeError("public suffix list ended before declared size")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if not os.path.samestat(info, after) or after.st_size != info.st_size:
            raise RuntimeError("public suffix list changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _load_psl() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    path = Path(__file__).with_name("data") / "public_suffix_list.dat"
    raw = _read_psl_bytes(path)
    if hashlib.sha256(raw).hexdigest() != _PSL_SHA256:
        raise RuntimeError("public suffix list integrity check failed")
    exact: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()
    for line in raw.decode("utf-8").splitlines():
        rule = line.strip().casefold()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        elif rule.startswith("*."):
            wildcards.add(rule[2:])
        else:
            exact.add(rule)
    if not exact:
        raise RuntimeError("public suffix list is empty")
    return frozenset(exact), frozenset(wildcards), frozenset(exceptions)


_PSL_EXACT, _PSL_WILDCARDS, _PSL_EXCEPTIONS = _load_psl()


def _public_suffix(domain: str) -> str | None:
    labels = domain.split(".")
    exception_matches = [rule for rule in _PSL_EXCEPTIONS if domain == rule or domain.endswith(f".{rule}")]
    if exception_matches:
        rule = max(exception_matches, key=lambda value: value.count("."))
        rule_labels = rule.split(".")
        return ".".join(labels[-(len(rule_labels) - 1):])
    exact_matches = [rule for rule in _PSL_EXACT if domain == rule or domain.endswith(f".{rule}")]
    wildcard_matches = [rule for rule in _PSL_WILDCARDS if domain == rule or domain.endswith(f".{rule}")]
    candidates = [(".".join(rule.split(".")), len(rule.split("."))) for rule in exact_matches]
    candidates.extend((".".join(labels[-(len(rule.split(".")) + 1):]), len(rule.split(".")) + 1) for rule in wildcard_matches if len(labels) > len(rule.split(".")))
    if not candidates:
        return None
    return max(candidates, key=lambda value: value[1])[0]


def _valid_registry_domain(domain: str) -> bool:
    if not isinstance(domain, str) or not domain.strip() or any(ord(char) < 32 for char in domain):
        return False
    candidate = domain.casefold().strip().rstrip(".")
    if candidate.startswith("www."):
        return False
    if candidate in _RESERVED_DOMAIN_SUFFIXES or candidate.endswith(tuple(f".{suffix}" for suffix in _RESERVED_DOMAIN_SUFFIXES)):
        return False
    parts = candidate.split(".")
    if "." not in candidate or ".." in candidate or len(parts) < 2 or any(len(part) == 0 or len(part) > 63 or part[0] == "-" or part[-1] == "-" for part in parts):
        return False
    if any(not re.fullmatch(r"[a-z0-9-]+", part) for part in parts):
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return False
    suffix = _public_suffix(candidate)
    return bool(suffix and candidate != suffix and candidate.endswith(f".{suffix}"))


def load_domain_registry(raw: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, Mapping) or raw.get("registry_version") != "manufacturer-domains-v1" or not isinstance(raw.get("entries"), list):
        raise TypeError("domain registry must contain the pinned registry_version and entries list")
    registry: dict[str, dict[str, Any]] = {}
    domain_owners: dict[str, str] = {}
    for entry in raw["entries"]:
        if not isinstance(entry, Mapping):
            raise TypeError("domain registry entries must be objects")
        manufacturer = entry.get("manufacturer")
        domains = entry.get("domains")
        trust_status = entry.get("trust_status")
        aliases = entry.get("aliases", [])
        if not isinstance(manufacturer, str) or not manufacturer.strip() or not isinstance(domains, list) or not domains:
            raise ValueError("domain registry entry has invalid manufacturer/domains")
        if not isinstance(aliases, list) or any(not isinstance(alias, str) or not alias.strip() for alias in aliases):
            raise ValueError("domain registry entry has invalid aliases")
        if trust_status not in {"candidate", "verified"} or any(not _valid_registry_domain(domain) for domain in domains):
            raise ValueError("domain registry entry has invalid trust status/domains")
        basis = entry.get("basis")
        if not isinstance(basis, str) or not basis.strip() or len(basis) > 512 or any(ord(char) < 32 for char in basis):
            raise ValueError("domain registry entry has invalid basis")
        if trust_status == "verified" and not basis.casefold().startswith("operator_approved:"):
            raise ValueError("verified domain entry lacks operator-approved basis")
        keys = [manufacturer.casefold().strip(), *(alias.casefold().strip() for alias in aliases)]
        if len(keys) != len(set(keys)):
            raise ValueError(f"duplicate manufacturer alias: {manufacturer}")
        if any(key in registry for key in keys):
            raise ValueError(f"duplicate manufacturer registry entry: {manufacturer}")
        normalized_domains = {domain.casefold().rstrip(".") for domain in domains}
        canonical_key = keys[0]
        for domain in normalized_domains:
            for existing, owner in domain_owners.items():
                if owner != canonical_key and (domain == existing or domain.endswith(f".{existing}") or existing.endswith(f".{domain}")):
                    raise ValueError(f"overlapping domain ownership: {domain}")
            domain_owners[domain] = canonical_key
        value = {"domains": normalized_domains, "trust_status": trust_status}
        for key in keys:
            registry[key] = value
    return registry


def registry_domains(registry: Mapping[str, Mapping[str, Any]], manufacturer: str, *, trusted_only: bool) -> set[str]:
    entry = registry.get(manufacturer.casefold().strip())
    if not entry or (trusted_only and entry.get("trust_status") != "verified"):
        return set()
    return set(entry.get("domains", set()))


def _safe_http_url(url: str) -> bool:
    if not isinstance(url, str) or not url or len(url) > 4096 or any(ord(char) < 32 for char in url):
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        return False
    if (parsed.scheme == "http" and port not in {None, 80}) or (parsed.scheme == "https" and port not in {None, 443}):
        return False
    return not parsed.fragment and not parsed.query


def _host_allowed(url: str, official_domains: set[str]) -> bool:
    if not _safe_http_url(url):
        return False
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in official_domains)


def _exact_token(text: str, value: str | None) -> bool:
    if not isinstance(value, str) or not value.strip() or not isinstance(text, str):
        return False
    escaped = re.escape(value.strip())
    return bool(re.search(rf"(?<![\w.+-]){escaped}(?![\w.+-])", text, flags=re.IGNORECASE))


def _css_visibility_uncertain(body: str) -> bool:
    return bool(_CSS_STYLESHEET_RE.search(body) or _CSS_HIDDEN_RE.search(body))


def _hidden_element(attributes: dict[str, str | None]) -> bool:
    style = (attributes.get("style") or "").casefold().replace(" ", "")
    classes = set((attributes.get("class") or "").casefold().split())
    if "inert" in attributes or re.search(r"(?:^|;)(?:display|visibility|opacity|content-visibility):", style):
        return True
    return "hidden" in attributes or (attributes.get("aria-hidden") or "").casefold() == "true" or "display:none" in style or "visibility:hidden" in style or "opacity:0" in style or "content-visibility:hidden" in style or bool(classes & {"hidden", "d-none", "visually-hidden", "sr-only", "visuallyhidden", "invisible", "collapse", "d-print-none", "opacity-0"})


class _PageSignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.heading_parts: list[str] = []
        self._active: str | None = None
        self._parts: list[str] = []
        self._hidden_depth = 0
        self._non_rendered_depth = 0
        self._tag_stack: list[tuple[str, bool, bool]] = []

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
        if self._hidden_depth == 0 and self._non_rendered_depth == 0 and tag in {"title", "h1"} and self._active is None:
            self._active = tag
            self._parts = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == self._active:
            value = html.unescape(re.sub(r"\s+", " ", "".join(self._parts))).strip()
            if self._active == "title":
                self.title_parts.append(value)
            else:
                self.heading_parts.append(value)
            self._active = None
            self._parts = []
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index][0] == tag:
                _tag, hidden, non_rendered = self._tag_stack.pop(index)
                if hidden:
                    self._hidden_depth = max(0, self._hidden_depth - 1)
                if non_rendered:
                    self._non_rendered_depth = max(0, self._non_rendered_depth - 1)
                break

    def handle_data(self, data: str) -> None:
        if self._active is not None and self._hidden_depth == 0 and self._non_rendered_depth == 0:
            self._parts.append(data)


def _page_identity_text(body_text: str) -> tuple[str, str]:
    parser = _PageSignalParser()
    parser.feed(body_text)
    parser.close()
    return " ".join(parser.title_parts), " ".join(parser.heading_parts)


def page_identity_text(body_text: str) -> tuple[str, str]:
    return _page_identity_text(body_text)


def has_exact_product_page_signal(url: str, body_text: str, model: str) -> bool:
    if not isinstance(body_text, str) or not body_text.strip() or _css_visibility_uncertain(body_text):
        return False
    try:
        parsed = urlparse(url)
        path = unquote(parsed.path)
    except (TypeError, ValueError):
        return False
    path_parts = {part.casefold() for part in path.split("/") if part}
    search_markers = {"search", "query", "find", "results"}
    if path_parts & search_markers or not path_parts:
        return False
    try:
        title_text, heading_text = _page_identity_text(body_text)
    except (IndexError, TypeError, ValueError, UnicodeError):
        return False
    body_model_signal = _exact_token(title_text, model) or _exact_token(heading_text, model)
    query_model_signal = any(key.casefold() in {"model", "mpn", "sku", "part", "product"} and _exact_token(value, model) for key, value in parse_qsl(parsed.query, keep_blank_values=True))
    return body_model_signal and (_exact_token(path, model) or query_model_signal)


def _candidate(identity: ManufacturerIdentity, raw: Mapping[str, Any], official_domains: set[str]) -> EvidenceCandidate:
    if not isinstance(raw, Mapping):
        raise TypeError("manufacturer search candidate must be an object")
    title = raw.get("title") if isinstance(raw.get("title"), str) else ""
    url = raw.get("url") if isinstance(raw.get("url"), str) else ""
    description = raw.get("description") if isinstance(raw.get("description"), str) else ""
    text = f"{title} {description}"
    manufacturer_match = _exact_token(text, identity.manufacturer)
    exact_model = _exact_token(text, identity.model)
    exact_mpn = _exact_token(text, identity.mpn)
    exact_ean = _exact_token(text, identity.ean)
    return EvidenceCandidate(
        title=title,
        url=url,
        description=description,
        official_domain=_host_allowed(url, official_domains),
        manufacturer_match=manufacturer_match,
        exact_model=exact_model,
        exact_mpn=exact_mpn,
        exact_ean=exact_ean,
    )


def classify_candidates(
    identity: ManufacturerIdentity,
    raw_candidates: Iterable[Mapping[str, Any]],
    *,
    official_domains: set[str],
) -> EvidenceResult:
    domains = {domain.lower().rstrip(".") for domain in official_domains if isinstance(domain, str)}
    candidates = tuple(_candidate(identity, raw, domains) for raw in raw_candidates)
    exact_official = tuple(
        candidate
        for candidate in candidates
        if candidate.official_domain and candidate.manufacturer_match and candidate.exact_model and (not identity.mpn or candidate.exact_mpn)
    )
    official = tuple(candidate for candidate in candidates if candidate.official_domain)
    secondary = tuple(candidate for candidate in candidates if not candidate.official_domain)
    if exact_official:
        status = EvidenceStatus.OFFICIAL_IDENTITY_CANDIDATE
        ordered = exact_official + tuple(candidate for candidate in candidates if candidate not in exact_official)
    elif official:
        status = EvidenceStatus.OFFICIAL_FAMILY_ONLY
        ordered = candidates
    elif secondary:
        status = EvidenceStatus.SECONDARY_ONLY
        ordered = candidates
    else:
        status = EvidenceStatus.UNCONFIRMED
        ordered = ()
    return EvidenceResult(identity=identity, status=status, candidates=ordered, auto_publish=False)


def build_exact_queries(identity: ManufacturerIdentity) -> list[str]:
    queries = [f'"{identity.manufacturer}" "{identity.model}"']
    if identity.ean:
        queries.append(f'"{identity.model}" "{identity.ean}"')
    return queries
