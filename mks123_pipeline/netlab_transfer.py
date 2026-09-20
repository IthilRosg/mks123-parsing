"""Direct Netlab snapshot transfer planning and staging SQL rendering.

This module intentionally does not open a database connection.  It converts one
committed Netlab normalized CSV plus its committed match map into an explicit,
reviewable plan.  The only mutating SQL mode is ``apply_staging`` and that mode
is additionally enabled by the caller's staging-only configuration.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, DecimalException, InvalidOperation
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, ClassVar

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAX_ROW_BYTES = 2 * 1024 * 1024
_MAX_TEXT_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_AGE = timedelta(hours=24)
_MAX_SOURCE_FUTURE_SKEW = timedelta(minutes=15)
_MOSCOW_TZ = timezone(timedelta(hours=3))
_TARGET_PRICE_QUANTUM = Decimal("0.0001")
_TARGET_PRICE_MAX = Decimal("99999999999.9999")


class TransferError(ValueError):
    """Raised when a transfer input or safety boundary is invalid."""


def validate_source_freshness(
    value: str,
    *,
    label: str = "source fetched_at",
    now: datetime | None = None,
) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TransferError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise TransferError(f"{label} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_MOSCOW_TZ)
    parsed_utc = parsed.astimezone(UTC)
    reference = now or datetime.now(UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    reference = reference.astimezone(UTC)
    age = reference - parsed_utc
    if age > _MAX_SOURCE_AGE:
        raise TransferError(f"{label} is older than 24 hours")
    if age < -_MAX_SOURCE_FUTURE_SKEW:
        raise TransferError(f"{label} is more than 15 minutes in the future")
    return parsed_utc


@dataclass(frozen=True)
class TransferConfig:
    """Explicit policy for one transfer plan.

    ``allow_staging_apply`` is deliberately false by default.  The incomplete
    feed override is accepted only when both staging flags are true; it can
    never authorize a production target because the apply CLI separately
    restricts its database identity.
    """

    usd_rub_rate: str | None = None
    markup_multiplier: str = "1.1"
    feed_complete: bool = True
    allow_staging_apply: bool = False
    allow_incomplete_feed_for_staging: bool = False
    enforce_source_freshness: bool = False
    language_id: int = 1
    table_prefix: str = "oc_"
    run_id: str | None = None
    transferred_at: str | None = None
    source_artifact_sha256: str | None = None
    source_artifact_path: str | None = None
    run_manifest_sha256: str | None = None
    run_manifest_provenance: Mapping[str, Any] | None = None
    attribute_mapping_sha256: str | None = None
    attribute_mapping_path: str | None = None
    attribute_mapping_artifact_sha256: str | None = None
    attribute_mapping_database: str | None = None
    attribute_mapping_language_id: int | None = None
    attribute_mapping_scope_skus: frozenset[str] | None = None
    bounded_canary_supplier_item_ids: frozenset[str] | None = None
    require_complete_attribute_mapping: bool = False
    selected_supplier_item_ids: frozenset[str] | None = None
    selection_manifest_sha256: str | None = None
    selection_manifest_supplier_item_ids: frozenset[str] | None = None
    selection_record_bindings: Mapping[str, Mapping[str, Any]] | None = None
    attribute_mapping: Mapping[str, int] | None = None


def _deterministic_transferred_at(
    policy: TransferConfig,
    explicit: str | None = None,
) -> str:
    selected = explicit or policy.transferred_at
    if selected:
        return selected
    provenance = policy.run_manifest_provenance or {}
    fetched_at = provenance.get("fetched_at")
    if not isinstance(fetched_at, str) or not fetched_at.strip():
        if (
            getattr(policy, "allow_staging_apply", False)
            and not getattr(policy, "enforce_source_freshness", False)
        ):
            return "1970-01-01 00:00:00"
        raise TransferError("candidate requires deterministic transferred_at from trusted provenance")
    try:
        parsed = datetime.fromisoformat(fetched_at.strip())
    except ValueError as exc:
        raise TransferError("trusted run-manifest fetched_at is not valid ISO-8601") from exc
    if parsed.tzinfo is None:
        raise TransferError("trusted run-manifest fetched_at must include timezone")
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class MatchRecord:
    supplier_item_id: str
    catalog_sku: str
    catalog_product_id: int | None
    status: str
    confidence: str
    matched_by: str
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class SourceItem:
    values: dict[str, str]
    source_snapshot_json: str
    payload_sha256: str

    @property
    def supplier_item_id(self) -> str:
        return self.values["supplier_item_id"]

    @property
    def catalog_sku(self) -> str:
        return self.values["catalog_sku"]


@dataclass(frozen=True)
class TransferRecord:
    action: str
    source: SourceItem
    match: MatchRecord
    target_product_id: int | None
    target_sku: str
    target_payload: dict[str, Any]
    source_properties_json: str
    source_images_json: str
    source_category_json: str
    attribute_rows: tuple[tuple[int, str], ...] = ()
    unmapped_attribute_names: tuple[str, ...] = ()

    @property
    def verification_status(self) -> str:
        return "transferred_unverified"


@dataclass(frozen=True)
class TransferException:
    supplier_item_id: str
    catalog_sku: str
    reason: str
    detail: str


@dataclass(frozen=True)
class TransferPlan:
    source_path: Path
    matches_path: Path
    source_artifact_sha256: str
    matches_artifact_sha256: str
    run_id: str
    policy: TransferConfig
    updates: tuple[TransferRecord, ...]
    creates: tuple[TransferRecord, ...]
    exceptions: tuple[TransferException, ...]
    feed_override: str | None = None
    source_record_count: int = 0
    match_record_count: int = 0

    @property
    def update_count(self) -> int:
        return len(self.updates)

    @property
    def create_count(self) -> int:
        return len(self.creates)

    @property
    def relations_created(self) -> int:
        return sum(
            isinstance(record.target_payload.get("target_category_id"), int)
            for record in (*self.updates, *self.creates)
        )

    @property
    def media_assignments(self) -> int:
        return 0

    @property
    def attribute_assignments(self) -> int:
        return sum(len(record.attribute_rows) for record in (*self.updates, *self.creates))

    @property
    def unmapped_attribute_names(self) -> tuple[str, ...]:
        return tuple(sorted({name for record in (*self.updates, *self.creates) for name in record.unmapped_attribute_names}))

    @property
    def write_count(self) -> int:
        return self.update_count + self.create_count


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise TransferError(f"cannot read transfer input: {path}") from exc
    return digest.hexdigest()


def _json_cell(raw: str, *, field_name: str, row_id: str) -> Any:
    if raw == "":
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TransferError(f"invalid {field_name} JSON for source item {row_id}") from exc


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _validate_sha(value: str, *, label: str) -> str:
    if not _SHA256.fullmatch(value):
        raise TransferError(f"{label} must be a SHA-256 hex digest")
    return value.lower()


def validate_attribute_mapping_payload(
    payload: Mapping[str, Any],
    *,
    expected_language_id: int | None = None,
) -> tuple[dict[str, int], dict[str, Any]]:
    """Validate the self-describing source-backed attribute artifact."""
    if not isinstance(payload, Mapping):
        raise TransferError("attribute mapping JSON must be an object")
    embedded = payload.get("artifact_sha256")
    if not isinstance(embedded, str) or not _SHA256.fullmatch(embedded):
        raise TransferError("attribute mapping artifact_sha256 is invalid")
    unsigned = dict(payload)
    del unsigned["artifact_sha256"]
    expected_embedded = hashlib.sha256(
        (json.dumps(unsigned, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    ).hexdigest()
    if embedded != expected_embedded:
        raise TransferError("attribute mapping artifact_sha256 does not match content")
    if payload.get("schema_version") != 1:
        raise TransferError("attribute mapping schema_version is unsupported")
    database = payload.get("database")
    if not isinstance(database, str) or not database or not re.fullmatch(
        r"mks123_stage(?:_[A-Za-z0-9]+)*", database
    ):
        raise TransferError("attribute mapping database identity is invalid")
    language_id = payload.get("language_id")
    if isinstance(language_id, bool) or not isinstance(language_id, int) or language_id <= 0:
        raise TransferError("attribute mapping language_id is invalid")
    if expected_language_id is not None and language_id != expected_language_id:
        raise TransferError("attribute mapping language_id does not match transfer policy")
    ambiguous = payload.get("ambiguous_names")
    if not isinstance(ambiguous, Mapping) or ambiguous:
        raise TransferError("attribute mapping contains ambiguous names")
    scope = payload.get("product_scope_skus")
    if (
        not isinstance(scope, list)
        or any(not isinstance(sku, str) or not sku for sku in scope)
        or len(set(scope)) != len(scope)
    ):
        raise TransferError("attribute mapping product scope is invalid")
    mapping = payload.get("attributes")
    definitions = payload.get("attribute_definitions")
    if not isinstance(mapping, Mapping) or not isinstance(definitions, Mapping) or set(mapping) != set(definitions):
        raise TransferError("attribute mapping definitions do not match attributes")
    result: dict[str, int] = {}
    seen_ids: set[int] = set()
    for name, attribute_id in mapping.items():
        if not isinstance(name, str) or not name.strip():
            raise TransferError("attribute mapping names must be non-empty strings")
        if isinstance(attribute_id, bool) or not isinstance(attribute_id, int) or not (1 <= attribute_id <= 2147483647):
            raise TransferError(f"attribute mapping ID is invalid for {name!r}")
        if attribute_id in seen_ids:
            raise TransferError(f"attribute mapping reuses target ID: {attribute_id}")
        definition_rows = definitions[name]
        if (
            not isinstance(definition_rows, list)
            or len(definition_rows) != 1
            or not isinstance(definition_rows[0], Mapping)
            or definition_rows[0].get("attribute_id") != attribute_id
        ):
            raise TransferError(f"attribute mapping definition disagrees for {name!r}")
        seen_ids.add(attribute_id)
        result[name] = attribute_id
    if payload.get("mapped_property_name_count") != len(result):
        raise TransferError("attribute mapping count is inconsistent")
    return result, {
        "artifact_sha256": embedded,
        "database": database,
        "language_id": language_id,
        "scope_skus": frozenset(scope),
    }


def _validate_text(
    value: str,
    *,
    label: str,
    max_bytes: int | None = _MAX_TEXT_BYTES,
    max_chars: int | None = None,
    utf8mb3: bool = False,
) -> str:
    if "\x00" in value:
        raise TransferError(f"{label} contains NUL byte")
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise TransferError(f"{label} exceeds byte limit")
    if max_chars is not None and len(value) > max_chars:
        raise TransferError(f"{label} exceeds {max_chars} characters")
    if utf8mb3 and any(ord(char) > 0xFFFF for char in value):
        raise TransferError(f"{label} contains utf8mb3-incompatible character")
    return value


def _decimal(value: str, *, label: str, default: Decimal | None = None) -> Decimal:
    if value.strip() == "":
        if default is None:
            raise TransferError(f"{label} is empty")
        return default
    try:
        parsed = Decimal(value.strip())
    except InvalidOperation as exc:
        raise TransferError(f"{label} is not a decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise TransferError(f"{label} is not a non-negative finite decimal")
    return parsed


def _integer(value: str, *, label: str, default: int = 0) -> int:
    if value.strip() == "":
        return default
    try:
        parsed = int(value.strip())
    except ValueError as exc:
        raise TransferError(f"{label} is not an integer") from exc
    if parsed < 0:
        raise TransferError(f"{label} is negative")
    return parsed


def _bool_cell(value: str, *, label: str) -> bool:
    normalized = value.strip().casefold()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no", ""}:
        return False
    raise TransferError(f"{label} is not a boolean")


class _DescriptionSanitizer(HTMLParser):
    _ALLOWED: ClassVar[set[str]] = {"b", "strong", "i", "em", "u", "p", "ul", "ol", "li", "br"}
    _DROP: ClassVar[set[str]] = {
        "script",
        "style",
        "iframe",
        "object",
        "embed",
        "svg",
        "math",
        "img",
        "input",
        "meta",
        "link",
        "base",
        "area",
        "col",
        "param",
        "source",
        "track",
        "wbr",
    }
    _DROP_VOID: ClassVar[set[str]] = {
        "embed",
        "img",
        "input",
        "meta",
        "link",
        "base",
        "area",
        "col",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._drop_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.casefold()
        if self._drop_depth:
            if tag in self._DROP and tag not in self._DROP_VOID:
                self._drop_depth += 1
            return
        if tag in self._DROP_VOID:
            return
        if tag in self._DROP:
            self._drop_depth = 1
            return
        if tag in self._ALLOWED:
            self.parts.append(f"<{tag}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() in self._ALLOWED and tag.casefold() != "br":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if self._drop_depth:
            if tag in self._DROP:
                self._drop_depth -= 1
            return
        if tag in self._ALLOWED and tag != "br":
            self.parts.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._drop_depth:
            self.parts.append(escape(data, quote=False))


def _sanitize_description_html(value: str) -> str:
    parser = _DescriptionSanitizer()
    parser.feed(value)
    parser.close()
    return "".join(parser.parts)


def _target_payload(source: SourceItem, config: TransferConfig) -> dict[str, Any]:
    values = source.values
    source_price = _decimal(values.get("source_price", ""), label="source_price", default=Decimal(0))
    currency = values.get("currency", "").strip().upper()
    try:
        if currency == "USD":
            if config.usd_rub_rate is None:
                raise TransferError("USD source requires an explicit embedded USD/RUB rate")
            rate = _decimal(config.usd_rub_rate, label="usd_rub_rate")
            multiplier = _decimal(config.markup_multiplier, label="markup_multiplier")
            price = source_price * rate * multiplier
        elif currency in {"RUB", "RUR"}:
            price = source_price * _decimal(config.markup_multiplier, label="markup_multiplier")
        elif source_price == 0:
            price = Decimal(0)
        else:
            raise TransferError(f"unsupported source currency: {currency or '<empty>'}")
        price = price.quantize(_TARGET_PRICE_QUANTUM, rounding=ROUND_HALF_UP)
    except DecimalException as exc:
        raise TransferError("calculated target price cannot fit DECIMAL(15,4)") from exc
    if price > _TARGET_PRICE_MAX:
        raise TransferError("calculated target price exceeds DECIMAL(15,4)")

    model = values.get("model", "").strip() or values.get("mpn", "").strip()
    model = model or values.get("supplier_sku", "").strip() or source.catalog_sku
    model = _validate_text(model, label="model", max_bytes=None, max_chars=64, utf8mb3=True)
    name = _validate_text(values.get("name", ""), label="name", max_bytes=None, max_chars=255, utf8mb3=True)
    if not name:
        raise TransferError(f"empty name for source item {source.supplier_item_id}")
    description = values.get("description_html", "") or values.get("description", "")
    description = _validate_text(description, label="description")
    description = _sanitize_description_html(description)
    source_mpn = _validate_text(values.get("mpn", ""), label="mpn", max_bytes=None, max_chars=64, utf8mb3=True)
    source_ean = _validate_text(values.get("ean", ""), label="ean", max_bytes=None, max_chars=64, utf8mb3=True)
    source_manufacturer = _validate_text(
        values.get("manufacturer", ""), label="manufacturer", max_bytes=255
    )
    dimensions = values.get("dimensions", "")
    dimension_parts = [part.strip() for part in re.split(r"\s*[xх×]\s*", dimensions) if part.strip()]
    length = _decimal(dimension_parts[0], label="length", default=Decimal(0)) if dimension_parts else Decimal(0)
    width = _decimal(dimension_parts[1], label="width", default=Decimal(0)) if len(dimension_parts) > 1 else Decimal(0)
    height = _decimal(dimension_parts[2], label="height", default=Decimal(0)) if len(dimension_parts) > 2 else Decimal(0)
    weight = _decimal(values.get("weight", ""), label="weight", default=Decimal(0))
    quantity = _integer(values.get("quantity", ""), label="quantity")
    available = _bool_cell(values.get("available", ""), label="available")
    if not available:
        quantity = 0

    return {
        "model": model,
        "name": name,
        "description": description,
        "mpn": source_mpn,
        "ean": source_ean,
        "manufacturer": source_manufacturer,
        "quantity": quantity,
        "available": available,
        "price": format(price, "f"),
        "source_price": format(source_price, "f"),
        "source_currency": currency,
        "weight": format(weight, "f"),
        "length": format(length, "f"),
        "width": format(width, "f"),
        "height": format(height, "f"),
        "source_url": values.get("source_url", ""),
        "fetched_at": _validate_text(
            values.get("fetched_at", ""),
            label="fetched_at",
            max_bytes=64,
            max_chars=64,
            utf8mb3=True,
        ),
        "raw_hash": _validate_sha(values.get("raw_hash", ""), label="source raw_hash"),
        "source_fields": {
            "manufacturer": source_manufacturer,
            "model": values.get("model", ""),
            "mpn": source_mpn,
            "ean": source_ean,
            "category_id": values.get("category_id", ""),
            "category_path": _json_cell(
                values.get("category_path", ""), field_name="category_path", row_id=source.supplier_item_id
            ),
        },
    }


def _source_item(values: dict[str, str]) -> SourceItem:
    required = ("supplier", "supplier_item_id", "catalog_sku")
    for field_name in required:
        if not values.get(field_name, "").strip():
            raise TransferError(f"source row missing {field_name}")
    if values["supplier"].strip().casefold() != "netlab":
        raise TransferError(f"unexpected supplier: {values['supplier']}")
    item_id = values["supplier_item_id"].strip()
    # Parse every structured cell now, before any SQL is rendered.
    for field_name in ("identity_warnings", "category_path", "image_urls", "properties", "attributes"):
        _json_cell(values.get(field_name, ""), field_name=field_name, row_id=item_id)
    raw_hash = _validate_sha(values.get("raw_hash", ""), label="source raw_hash")
    values = {key: _validate_text(value, label=f"{key} for {item_id}") for key, value in values.items()}
    snapshot = _canonical_json(values)
    payload_hash = hashlib.sha256(snapshot.encode("utf-8")).hexdigest()
    if values["raw_hash"].casefold() != raw_hash:
        raise TransferError("source raw_hash changed during row validation")
    return SourceItem(values=values, source_snapshot_json=snapshot, payload_sha256=payload_hash)


def _read_matches(path: Path) -> tuple[dict[str, MatchRecord], int]:
    records: dict[str, MatchRecord] = {}
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise TransferError(f"cannot read matches input: {path}") from exc
    with handle:
        reader = csv.DictReader(handle)
        required = {"supplier_item_id", "catalog_sku", "catalog_product_id", "status", "confidence", "matched_by", "warnings"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise TransferError("matches CSV has an unsupported header")
        count = 0
        for row in reader:
            count += 1
            item_id = (row.get("supplier_item_id") or "").strip()
            if not item_id or item_id in records:
                raise TransferError(f"duplicate or empty match supplier_item_id: {item_id or '<empty>'}")
            status = (row.get("status") or "").strip()
            warnings_raw = row.get("warnings") or "[]"
            warnings = _json_cell(warnings_raw, field_name="warnings", row_id=item_id)
            if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
                raise TransferError(f"warnings must be a string list for source item {item_id}")
            product_id_raw = (row.get("catalog_product_id") or "").strip()
            product_id = None
            if product_id_raw:
                try:
                    product_id = int(product_id_raw)
                except ValueError as exc:
                    raise TransferError(f"invalid catalog_product_id for source item {item_id}") from exc
                if product_id <= 0:
                    raise TransferError(f"catalog_product_id must be positive for source item {item_id}")
            records[item_id] = MatchRecord(
                supplier_item_id=item_id,
                catalog_sku=(row.get("catalog_sku") or "").strip(),
                catalog_product_id=product_id,
                status=status,
                confidence=(row.get("confidence") or "").strip(),
                matched_by=(row.get("matched_by") or "").strip(),
                warnings=tuple(warnings),
            )
    return records, count


def _is_target_schema_limit(error: TransferError) -> bool:
    detail = str(error)
    return (
        "exceeds byte limit" in detail
        or "exceeds 64 characters" in detail
        or "exceeds 255 characters" in detail
        or "utf8mb3-incompatible" in detail
    )


def _source_attribute_rows(
    source_properties_json: str,
    attribute_mapping: Mapping[str, int] | None,
) -> tuple[tuple[tuple[int, str], ...], tuple[str, ...]]:
    """Map only exact source property names; never infer attribute IDs."""
    if attribute_mapping is None:
        return (), ()
    if not isinstance(attribute_mapping, Mapping):
        raise TransferError("attribute_mapping must be a mapping")
    normalized_mapping: dict[str, int] = {}
    for name, attribute_id in attribute_mapping.items():
        if not isinstance(name, str) or not name.strip():
            raise TransferError("attribute mapping names must be non-empty strings")
        if not isinstance(attribute_id, int) or attribute_id <= 0:
            raise TransferError(f"attribute mapping ID is invalid for {name!r}")
        if name in normalized_mapping and normalized_mapping[name] != attribute_id:
            raise TransferError(f"attribute mapping contains duplicate name: {name}")
        normalized_mapping[name] = attribute_id
    try:
        properties = json.loads(source_properties_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TransferError("source properties JSON is invalid") from exc
    if not isinstance(properties, list):
        raise TransferError("source properties JSON must be a list")
    rows: list[tuple[int, str]] = []
    unmapped: list[str] = []
    seen_attribute_ids: set[int] = set()
    for item in properties:
        if not isinstance(item, Mapping):
            raise TransferError("source property row must be an object")
        if item.get("missing") is True or item.get("definition_missing") is True:
            # Unknown property definitions remain in provenance; they cannot
            # be bound to an OpenCart attribute ID safely.
            continue
        name = item.get("property_name")
        value = item.get("value")
        if not isinstance(name, str) or not name.strip():
            raise TransferError("source property name is invalid")
        if name == "Описание" or name.lstrip().startswith("<b>"):
            continue
        if not isinstance(value, str) or not value.strip() or value.strip() == "-":
            continue
        attribute_id = normalized_mapping.get(name)
        if attribute_id is None:
            unmapped.append(name)
            continue
        if attribute_id in seen_attribute_ids:
            raise TransferError(f"multiple source properties map to attribute ID {attribute_id}")
        seen_attribute_ids.add(attribute_id)
        rows.append((attribute_id, _validate_text(value, label=f"attribute {name}")))
    return tuple(rows), tuple(unmapped)


def _record_for(
    source: SourceItem,
    match: MatchRecord,
    config: TransferConfig,
    *,
    selection_binding: Mapping[str, Any] | None = None,
) -> TransferRecord:
    _validate_text(
        source.supplier_item_id,
        label="supplier_item_id",
        max_bytes=None,
        max_chars=64,
        utf8mb3=True,
    )
    _validate_text(
        source.catalog_sku,
        label="catalog_sku",
        max_bytes=None,
        max_chars=64,
        utf8mb3=True,
    )
    payload = _target_payload(source, config)
    payload = dict(payload)
    payload["language_id"] = config.language_id
    if selection_binding is not None:
        payload["target_category_id"] = selection_binding["target_category_id"]
        payload["root_category_id"] = selection_binding["root_category_id"]
    if match.status == "exact" and not payload["description"]:
        payload = dict(payload)
        payload["preserve_fields"] = ["description"]
    properties = _json_cell(source.values.get("properties", ""), field_name="properties", row_id=source.supplier_item_id)
    images = _json_cell(source.values.get("image_urls", ""), field_name="image_urls", row_id=source.supplier_item_id)
    category = _json_cell(source.values.get("category_path", ""), field_name="category_path", row_id=source.supplier_item_id)
    attribute_rows, unmapped_attribute_names = _source_attribute_rows(
        _canonical_json(properties), config.attribute_mapping
    )
    return TransferRecord(
        action="update" if match.status == "exact" else "create",
        source=source,
        match=match,
        target_product_id=match.catalog_product_id if match.status == "exact" else None,
        target_sku=source.catalog_sku,
        target_payload=payload,
        source_properties_json=_canonical_json(properties),
        source_images_json=_canonical_json(images),
        source_category_json=_canonical_json(category),
        attribute_rows=attribute_rows,
        unmapped_attribute_names=unmapped_attribute_names,
    )


def select_supplier_item_ids(
    matches_path: Path,
    *,
    max_updates: int,
    max_creates: int,
) -> frozenset[str]:
    """Select deterministic exact/unmatched IDs for a bounded canary."""
    if max_updates < 0 or max_creates < 0:
        raise TransferError("canary limits must be non-negative")
    match_map, _ = _read_matches(Path(matches_path))
    selected: list[str] = []
    selected.extend(
        item_id for item_id, record in match_map.items() if record.status == "exact"
    )
    selected_updates = selected[:max_updates]
    selected_creates = [
        item_id for item_id, record in match_map.items() if record.status == "unmatched"
    ][:max_creates]
    return frozenset(selected_updates + selected_creates)


def build_transfer_plan(
    source_path: Path,
    matches_path: Path,
    *,
    config: TransferConfig,
) -> TransferPlan:
    """Build a fail-closed plan from one source/match pair."""
    if not config.feed_complete:
        if not (config.allow_staging_apply and config.allow_incomplete_feed_for_staging):
            raise TransferError("incomplete feed requires explicit staging override")
        feed_override = "staging_only_incomplete_feed"
    else:
        feed_override = None
    if config.language_id <= 0 or isinstance(config.language_id, bool):
        raise TransferError("language_id must be a positive integer")
    mapping_fields = (
        config.attribute_mapping,
        config.attribute_mapping_sha256,
        config.attribute_mapping_path,
        config.attribute_mapping_artifact_sha256,
        config.attribute_mapping_database,
        config.attribute_mapping_language_id,
        config.attribute_mapping_scope_skus,
    )
    if any(value is not None for value in mapping_fields) and not all(value is not None for value in mapping_fields):
        raise TransferError("attribute mapping and all provenance fields are required together")
    if config.attribute_mapping is not None:
        _validate_sha(config.attribute_mapping_sha256 or "", label="attribute mapping file hash")
        _validate_sha(config.attribute_mapping_artifact_sha256 or "", label="attribute mapping artifact hash")
        if not isinstance(config.attribute_mapping_path, str) or not config.attribute_mapping_path.strip():
            raise TransferError("attribute mapping path is required")
        if not isinstance(config.attribute_mapping_database, str) or not re.fullmatch(
            r"mks123_stage(?:_[A-Za-z0-9]+)*", config.attribute_mapping_database
        ):
            raise TransferError("attribute mapping database identity is invalid")
        if config.attribute_mapping_language_id != config.language_id:
            raise TransferError("attribute mapping language does not match transfer policy")
        if not isinstance(config.attribute_mapping_scope_skus, frozenset) or not config.attribute_mapping_scope_skus:
            raise TransferError("attribute mapping product scope is required")
        seen_attribute_ids: set[int] = set()
        for name, attribute_id in config.attribute_mapping.items():
            if not isinstance(name, str) or not name.strip():
                raise TransferError("attribute mapping names must be non-empty strings")
            if isinstance(attribute_id, bool) or not isinstance(attribute_id, int) or not (1 <= attribute_id <= 2147483647):
                raise TransferError(f"attribute mapping ID is invalid for {name!r}")
            if attribute_id in seen_attribute_ids:
                raise TransferError(f"attribute mapping reuses target ID: {attribute_id}")
            seen_attribute_ids.add(attribute_id)
    if not _SAFE_IDENTIFIER.fullmatch(config.table_prefix.rstrip("_")) and config.table_prefix != "oc_":
        raise TransferError("unsafe table prefix")
    if config.run_manifest_sha256 is not None:
        _validate_sha(config.run_manifest_sha256, label="run manifest hash")
    if config.selection_manifest_sha256 is None:
        if config.selection_manifest_supplier_item_ids is not None or config.selection_record_bindings is not None:
            raise TransferError("selection metadata requires a selection hash")
    else:
        _validate_sha(config.selection_manifest_sha256, label="selection manifest hash")
        if config.selected_supplier_item_ids is None:
            raise TransferError("selection hash requires explicit selection IDs")
        if config.selection_manifest_supplier_item_ids is None:
            raise TransferError("selection manifest IDs are required with a selection hash")
        if config.selection_manifest_supplier_item_ids != config.selected_supplier_item_ids:
            raise TransferError("selection manifest IDs do not match explicit selection")
        bindings = config.selection_record_bindings
        if bindings is None or set(bindings) != set(config.selected_supplier_item_ids):
            raise TransferError("selection record bindings do not match explicit selection IDs")
        for supplier_item_id, binding in bindings.items():
            if not isinstance(binding, Mapping):
                raise TransferError(f"selection binding is not an object: {supplier_item_id}")
            for field in ("source_row_sha256", "matches_row_sha256", "category_mapping_row_sha256"):
                _validate_sha(str(binding.get(field, "")), label=f"selection binding {field}")
            proposal_hash = binding.get("product_proposal_row_sha256")
            if proposal_hash is not None:
                _validate_sha(str(proposal_hash), label="selection binding product_proposal_row_sha256")
            for field in ("target_category_id", "root_category_id"):
                value = binding.get(field)
                if not isinstance(value, int) or value <= 0:
                    raise TransferError(f"selection binding {field} is invalid")

    if config.bounded_canary_supplier_item_ids is not None:
        if config.selection_manifest_sha256 is None or config.selected_supplier_item_ids != config.bounded_canary_supplier_item_ids:
            raise TransferError("bounded canary IDs must equal the explicit scoped selection")
        if not config.bounded_canary_supplier_item_ids:
            raise TransferError("bounded canary IDs cannot be empty")
    source_path = Path(source_path)
    matches_path = Path(matches_path)
    source_hash = _sha256_file(source_path)
    matches_hash = _sha256_file(matches_path)
    source_artifact_hash = _validate_sha(
        config.source_artifact_sha256 or source_hash, label="source artifact hash"
    )
    match_map, match_count = _read_matches(matches_path)
    seen_ids: set[str] = set()
    seen_skus: set[str] = set()
    updates: list[TransferRecord] = []
    creates: list[TransferRecord] = []
    exceptions: list[TransferException] = []
    source_count = 0
    try:
        handle = source_path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise TransferError(f"cannot read source input: {source_path}") from exc
    with handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "supplier_item_id" not in reader.fieldnames or "catalog_sku" not in reader.fieldnames:
            raise TransferError("source CSV has an unsupported header")
        for row in reader:
            source_count += 1
            source = _source_item({key: value or "" for key, value in row.items() if key is not None})
            if source.supplier_item_id in seen_ids:
                raise TransferError(f"duplicate source supplier_item_id: {source.supplier_item_id}")
            if source.catalog_sku in seen_skus:
                raise TransferError(f"duplicate source catalog_sku: {source.catalog_sku}")
            seen_ids.add(source.supplier_item_id)
            seen_skus.add(source.catalog_sku)
            selected = config.selected_supplier_item_ids
            if selected is not None and source.supplier_item_id not in selected:
                continue
            if config.enforce_source_freshness:
                validate_source_freshness(
                    source.values.get("fetched_at", ""),
                    label=f"source fetched_at for {source.supplier_item_id}",
                )
            match = match_map.get(source.supplier_item_id)
            if match is None:
                exceptions.append(
                    TransferException(source.supplier_item_id, source.catalog_sku, "match_missing", "no match row")
                )
                continue
            if match.catalog_sku and match.catalog_sku != source.catalog_sku:
                raise TransferError(
                    f"source/match SKU mismatch for {source.supplier_item_id}: "
                    f"{source.catalog_sku} != {match.catalog_sku}"
                )
            if match.status == "exact":
                if match.catalog_product_id is None or match.warnings:
                    raise TransferError(f"exact match is not warning-free for {source.supplier_item_id}")
                try:
                    updates.append(
                        _record_for(
                            source,
                            match,
                            config,
                            selection_binding=(config.selection_record_bindings or {}).get(
                                source.supplier_item_id
                            ),
                        )
                    )
                except TransferError as exc:
                    if not _is_target_schema_limit(exc):
                        raise
                    exceptions.append(
                        TransferException(
                            source.supplier_item_id,
                            source.catalog_sku,
                            "target_schema_limit",
                            str(exc),
                        )
                    )
            elif match.status == "unmatched":
                try:
                    creates.append(
                        _record_for(
                            source,
                            match,
                            config,
                            selection_binding=(config.selection_record_bindings or {}).get(
                                source.supplier_item_id
                            ),
                        )
                    )
                except TransferError as exc:
                    if not _is_target_schema_limit(exc):
                        raise
                    exceptions.append(
                        TransferException(
                            source.supplier_item_id,
                            source.catalog_sku,
                            "target_schema_limit",
                            str(exc),
                        )
                    )
            elif match.status in {"conflict", "ambiguous", "high_confidence"}:
                exceptions.append(
                    TransferException(
                        source.supplier_item_id,
                        source.catalog_sku,
                        match.status,
                        ",".join(match.warnings) or "match not exact",
                    )
                )
            else:
                exceptions.append(
                    TransferException(
                        source.supplier_item_id, source.catalog_sku, "unsupported_match_status", match.status
                    )
                )
    if source_count == 0:
        raise TransferError("source CSV is empty")
    if config.selected_supplier_item_ids:
        missing_selection = set(config.selected_supplier_item_ids) - seen_ids
        if missing_selection:
            raise TransferError("selected source item is absent from source CSV")
    if config.require_complete_attribute_mapping:
        incomplete = {
            record.target_sku: sorted(record.unmapped_attribute_names)
            for record in (*updates, *creates)
            if record.unmapped_attribute_names
        }
        if incomplete:
            raise TransferError(f"complete attribute mapping required; unmapped properties remain: {incomplete}")
    if config.attribute_mapping is not None:
        planned_scope = frozenset(
            record.target_sku for record in (*updates, *creates)
        ) | frozenset(exception.catalog_sku for exception in exceptions if exception.catalog_sku)
        if planned_scope != config.attribute_mapping_scope_skus:
            raise TransferError("attribute mapping product scope does not match selected candidate scope")
    selection_material = {
        "mode": "all" if config.selected_supplier_item_ids is None else "explicit",
        "supplier_item_ids": sorted(config.selected_supplier_item_ids or ())
        if config.selected_supplier_item_ids is not None
        else None,
        "selection_manifest_sha256": config.selection_manifest_sha256,
    }
    run_material = {
        "source_sha256": source_hash,
        "matches_sha256": matches_hash,
        "policy": {
            "usd_rub_rate": config.usd_rub_rate,
            "markup_multiplier": config.markup_multiplier,
            "feed_complete": config.feed_complete,
            "feed_override": feed_override,
            "enforce_source_freshness": config.enforce_source_freshness,
            "language_id": config.language_id,
            "table_prefix": config.table_prefix,
            "run_manifest_sha256": config.run_manifest_sha256,
            "attribute_mapping_sha256": config.attribute_mapping_sha256,
            "attribute_mapping_path": config.attribute_mapping_path,
            "attribute_mapping_artifact_sha256": config.attribute_mapping_artifact_sha256,
            "attribute_mapping_database": config.attribute_mapping_database,
            "attribute_mapping_language_id": config.attribute_mapping_language_id,
            "attribute_mapping_scope_skus": sorted(config.attribute_mapping_scope_skus or ()),
            "bounded_canary_supplier_item_ids": sorted(config.bounded_canary_supplier_item_ids or ()),
            "require_complete_attribute_mapping": config.require_complete_attribute_mapping,
            "run_manifest_provenance": config.run_manifest_provenance,
        },
        "selection": selection_material,
    }
    run_hash = hashlib.sha256(_canonical_json(run_material).encode("utf-8")).hexdigest()
    derived_run_id = f"netlab-transfer-{run_hash[:16]}"
    if config.run_id is not None and config.run_id != derived_run_id:
        raise TransferError("explicit run_id must equal the selection-bound derived run_id")
    run_id = config.run_id or derived_run_id
    return TransferPlan(
        source_path=source_path,
        matches_path=matches_path,
        source_artifact_sha256=source_artifact_hash,
        matches_artifact_sha256=matches_hash,
        run_id=run_id,
        policy=config,
        updates=tuple(updates),
        creates=tuple(creates),
        exceptions=tuple(exceptions),
        feed_override=feed_override,
        source_record_count=source_count,
        match_record_count=match_count,
    )


def _sql_text(value: str) -> str:
    _validate_text(value, label="SQL text")
    if value == "":
        return "''"
    return f"CONVERT(0x{value.encode('utf-8').hex()} USING utf8mb4)"


def _sql_json(value: str) -> str:
    return _sql_text(value)


def _sql_decimal(value: str) -> str:
    parsed = _decimal(value, label="SQL decimal")
    return format(parsed, "f")


def _table(prefix: str, name: str) -> str:
    if not prefix.endswith("_") or not _SAFE_IDENTIFIER.fullmatch(prefix[:-1] or "_"):
        raise TransferError("unsafe SQL table prefix")
    if not _SAFE_IDENTIFIER.fullmatch(name):
        raise TransferError("unsafe SQL table name")
    return f"`{prefix}{name}`"


def _source_after_json(record: TransferRecord) -> str:
    return _canonical_json(
        {
            "target": record.target_payload,
            "source_kind": "netlab",
            "verification_status": record.verification_status,
            "manufacturer_verified": False,
            "source_snapshot": json.loads(record.source.source_snapshot_json),
            "attributes": {
                "mapped": [{"attribute_id": aid, "text": text} for aid, text in record.attribute_rows],
                "unmapped_property_names": list(record.unmapped_attribute_names),
            },
        }
    )


def _category_relation_insert(
    record: TransferRecord,
    *,
    prefix: str,
    product_id: str,
) -> str | None:
    category_id = record.target_payload.get("target_category_id")
    if category_id is None:
        return None
    if not isinstance(category_id, int) or category_id <= 0:
        raise TransferError("target category ID must be a positive integer")
    return (
        f"INSERT INTO {_table(prefix, 'product_to_category')} "
        "(`product_id`, `category_id`) "
        f"SELECT {product_id}, {category_id} "
        "WHERE @netlab_transfer_product_rows=1 "
        "AND @netlab_transfer_description_rows=1 "
        "ON DUPLICATE KEY UPDATE `category_id`=VALUES(`category_id`);"
    )


def _guarded_target_id(product_id: str) -> str:
    return (
        "IF(@netlab_transfer_product_rows=1 AND "
        "@netlab_transfer_description_rows=1, "
        f"{product_id}, NULL)"
    )


def _attribute_inserts(
    record: TransferRecord,
    *,
    prefix: str,
    product_id: str,
) -> list[str]:
    statements: list[str] = []
    guarded_target_id = _guarded_target_id(product_id)
    for attribute_id, text in record.attribute_rows:
        statements.append(
            f"INSERT INTO {_table(prefix, 'product_attribute')} "
            "(`product_id`, `attribute_id`, `language_id`, `text`) "
            f"SELECT {guarded_target_id}, {attribute_id}, {record.target_payload.get('language_id', 1)}, {_sql_text(text)} "
            "WHERE @netlab_transfer_product_rows=1 "
            "AND @netlab_transfer_description_rows=1 "
            "ON DUPLICATE KEY UPDATE `text`=VALUES(`text`);"
        )
    return statements


def _render_update(
    record: TransferRecord,
    *,
    prefix: str,
    language_id: int,
    transferred_at: str,
    run_id: str,
    source_artifact_path: str,
    source_artifact_sha256: str,
    matches_artifact_sha256: str,
) -> str:
    assert record.target_product_id is not None
    payload = record.target_payload
    preserve_fields = set(payload.get("preserve_fields", []))
    assignments = [
        f"`model`={_sql_text(payload['model'])}",
        f"`quantity`={int(payload['quantity'])}",
        f"`price`={_sql_decimal(payload['price'])}",
        f"`weight`={_sql_decimal(payload['weight'])}",
        f"`length`={_sql_decimal(payload['length'])}",
        f"`width`={_sql_decimal(payload['width'])}",
        f"`height`={_sql_decimal(payload['height'])}",
        f"`date_modified`={_sql_text(transferred_at)}",
    ]
    # Empty source identifiers do not erase existing target identifiers.
    if payload["mpn"]:
        assignments.append(f"`mpn`={_sql_text(payload['mpn'])}")
    if payload["ean"]:
        assignments.append(f"`ean`={_sql_text(payload['ean'])}")
    source_sku = record.target_sku
    description = payload["description"]
    name = payload["name"]
    description_assignments = [f"`name`={_sql_text(name)}"]
    if "description" not in preserve_fields:
        description_assignments.append(f"`description`={_sql_text(description)}")
    after_json = _source_after_json(record)
    relation_insert = _category_relation_insert(
        record,
        prefix=prefix,
        product_id=str(record.target_product_id),
    )
    guarded_target_id = _guarded_target_id(str(record.target_product_id))
    return "\n".join(
        [
            (
                f"UPDATE {_table(prefix, 'product')} SET {', '.join(assignments)} "
                f"WHERE `product_id`={record.target_product_id} AND `sku`={_sql_text(source_sku)};"
            ),
            (
                "SET @netlab_transfer_product_rows = (SELECT COUNT(*) FROM "
                f"{_table(prefix, 'product')} WHERE `product_id`={record.target_product_id} "
                f"AND `sku`={_sql_text(source_sku)});"
            ),
            (
                f"UPDATE {_table(prefix, 'product_description')} SET {', '.join(description_assignments)} "
                f"WHERE `product_id`={record.target_product_id} "
                f"AND `language_id`={language_id} "
                f"AND @netlab_transfer_product_rows=1 "
                f"AND EXISTS (SELECT 1 FROM {_table(prefix, 'product')} AS p "
                f"WHERE p.`product_id`={record.target_product_id} "
                f"AND p.`sku`={_sql_text(source_sku)});"
            ),
            (
                "SET @netlab_transfer_description_rows = (SELECT COUNT(*) FROM "
                f"{_table(prefix, 'product_description')} WHERE `product_id`={record.target_product_id} "
                f"AND `language_id`={language_id} AND @netlab_transfer_product_rows=1);"
            ),
            *_attribute_inserts(record, prefix=prefix, product_id=str(record.target_product_id)),
            *([relation_insert] if relation_insert is not None else []),
            _audit_insert(
                record,
                prefix=prefix,
                language_id=language_id,
                target_id=guarded_target_id,
                transferred_at=transferred_at,
                run_id=run_id,
                after_json=after_json,
                source_artifact_path=source_artifact_path,
                source_artifact_sha256=source_artifact_sha256,
                matches_artifact_sha256=matches_artifact_sha256,
            ),
        ]
    )


def _render_create(
    record: TransferRecord,
    *,
    prefix: str,
    language_id: int,
    transferred_at: str,
    run_id: str,
    source_artifact_path: str,
    source_artifact_sha256: str,
    matches_artifact_sha256: str,
) -> str:
    payload = record.target_payload
    # New products are deliberately disabled/noindex until a separate
    # publication decision.  A scoped selection also writes its allowlisted
    # category relation; source images and raw attributes stay in the audit table.
    columns = (
        "`model`, `sku`, `upc`, `ean`, `jan`, `isbn`, `mpn`, `location`, `quantity`, "
        "`stock_status_id`, `image`, `manufacturer_id`, `shipping`, `price`, `cost`, `points`, "
        "`tax_class_id`, `date_available`, `weight`, `weight_class_id`, `length`, `width`, `height`, "
        "`length_class_id`, `subtract`, `minimum`, `sort_order`, `status`, `viewed`, `date_added`, "
        "`date_modified`, `noindex`, `oct_stickers`, `dn_id`, `suppler_code`, `suppler_type`"
    )
    values = (
        f"{_sql_text(payload['model'])}, {_sql_text(record.target_sku)}, '', {_sql_text(payload['ean'])}, "
        f"'', '', {_sql_text(payload['mpn'])}, '', {int(payload['quantity'])}, 5, NULL, 0, 1, "
        f"{_sql_decimal(payload['price'])}, 0, 0, 0, {_sql_text(transferred_at[:10])}, "
        f"{_sql_decimal(payload['weight'])}, 1, {_sql_decimal(payload['length'])}, "
        f"{_sql_decimal(payload['width'])}, {_sql_decimal(payload['height'])}, 1, 0, 1, 0, 0, 0, "
        f"{_sql_text(transferred_at)}, {_sql_text(transferred_at)}, 1, '', 0, 0, 0"
    )
    after_json = _source_after_json(record)
    relation_insert = _category_relation_insert(
        record,
        prefix=prefix,
        product_id="@netlab_transfer_product_id",
    )
    guarded_target_id = _guarded_target_id("@netlab_transfer_product_id")
    return "\n".join(
        [
            f"INSERT INTO {_table(prefix, 'product')} ({columns}) VALUES ({values});",
            "SET @netlab_transfer_product_rows = ROW_COUNT();",
            "SET @netlab_transfer_product_id = LAST_INSERT_ID();",
            (
                f"INSERT INTO {_table(prefix, 'product_description')} "
                "(`product_id`, `language_id`, `name`, `description`, `tag`, `meta_title`, "
                "`meta_description`, `meta_keyword`, `meta_h1`) SELECT "
                f"@netlab_transfer_product_id, {language_id}, {_sql_text(payload['name'])}, "
                f"{_sql_text(payload['description'])}, '', '', '', '', NULL "
                "WHERE @netlab_transfer_product_rows=1;"
            ),
            "SET @netlab_transfer_description_rows = ROW_COUNT();",
            *_attribute_inserts(record, prefix=prefix, product_id="@netlab_transfer_product_id"),
            *([relation_insert] if relation_insert is not None else []),
            _audit_insert(
                record,
                prefix=prefix,
                language_id=language_id,
                target_id=guarded_target_id,
                transferred_at=transferred_at,
                run_id=run_id,
                after_json=after_json,
                source_artifact_path=source_artifact_path,
                source_artifact_sha256=source_artifact_sha256,
                matches_artifact_sha256=matches_artifact_sha256,
            ),
        ]
    )


def _audit_insert(
    record: TransferRecord,
    *,
    prefix: str,
    language_id: int,
    target_id: str,
    transferred_at: str,
    run_id: str,
    after_json: str,
    source_artifact_path: str,
    source_artifact_sha256: str,
    matches_artifact_sha256: str,
) -> str:
    source = record.source
    values = [
        _sql_text(run_id),
        _sql_text(source.supplier_item_id),
        _sql_text(record.target_sku),
        target_id,
        _sql_text(record.action),
        _sql_text("netlab"),
        _sql_text(record.verification_status),
        "0",
        _sql_text(record.target_payload["source_url"]),
        _sql_text(record.target_payload["raw_hash"]),
        _sql_text(record.target_payload["fetched_at"]),
        _sql_text(source_artifact_path),
        _sql_text(source_artifact_sha256),
        _sql_text(matches_artifact_sha256),
        _sql_text(record.source.source_snapshot_json),
        _sql_json(record.source_properties_json),
        _sql_json(record.source_images_json),
        _sql_json(record.source_category_json),
        _sql_text(after_json),
        _sql_text(transferred_at),
    ]
    columns = (
        "`run_id`, `supplier_item_id`, `source_sku`, `target_product_id`, `action`, `source_kind`, "
        "`verification_status`, `manufacturer_verified`, `source_url`, `source_raw_hash`, "
        "`source_fetched_at`, `source_artifact_path`, `source_artifact_sha256`, "
        "`matches_artifact_sha256`, `source_snapshot_json`, `properties_json`, `image_urls_json`, "
        "`category_json`, `after_json`, `transferred_at`"
    )
    return (
        f"INSERT INTO {_table(prefix, 'netlab_transfer_audit')} ({columns}) "
        f"SELECT {', '.join(values)} "
        "WHERE @netlab_transfer_product_rows=1 "
        "AND @netlab_transfer_description_rows=1;"
    )


def render_sql(plan: TransferPlan, *, mode: str, transferred_at: str | None = None) -> str:
    """Render an explicit staging transaction; preview mode renders no DML."""
    if mode not in {"preview", "apply_staging"}:
        raise TransferError("mode must be preview or apply_staging")
    if mode == "preview":
        raise TransferError("mutating SQL requires mode=apply_staging")
    if not plan.policy.allow_staging_apply:
        raise TransferError("apply_staging requires explicit allow_staging_apply")
    if plan.policy.table_prefix != "oc_":
        raise TransferError("only the OpenCart oc_ prefix is supported by staging writer")
    effective_transferred_at = _deterministic_transferred_at(plan.policy, transferred_at)
    _validate_text(effective_transferred_at, label="transferred_at", max_bytes=64)
    source_artifact_path = plan.policy.source_artifact_path or str(plan.source_path)
    _validate_text(source_artifact_path, label="source_artifact_path")
    audit = _table(plan.policy.table_prefix, "netlab_transfer_audit")
    statements = [
        "SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE';",
        "SET NAMES utf8mb4;",
        (
            f"CREATE TABLE {audit} ("
            "`transfer_id` BIGINT NOT NULL AUTO_INCREMENT,"
            "`run_id` VARCHAR(128) NOT NULL,"
            "`supplier_item_id` VARCHAR(64) NOT NULL,"
            "`source_sku` VARCHAR(64) NOT NULL,"
            "`target_product_id` INT NOT NULL,"
            "`action` VARCHAR(16) NOT NULL,"
            "`source_kind` VARCHAR(32) NOT NULL,"
            "`verification_status` VARCHAR(64) NOT NULL,"
            "`manufacturer_verified` TINYINT(1) NOT NULL,"
            "`source_url` TEXT NOT NULL,"
            "`source_raw_hash` CHAR(64) NOT NULL,"
            "`source_fetched_at` VARCHAR(64) NOT NULL,"
            "`source_artifact_path` TEXT NOT NULL,"
            "`source_artifact_sha256` CHAR(64) NOT NULL,"
            "`matches_artifact_sha256` CHAR(64) NOT NULL,"
            "`source_snapshot_json` LONGTEXT NOT NULL,"
            "`properties_json` LONGTEXT NOT NULL,"
            "`image_urls_json` LONGTEXT NOT NULL,"
            "`category_json` LONGTEXT NOT NULL,"
            "`after_json` LONGTEXT NOT NULL,"
            "`transferred_at` DATETIME NOT NULL,"
            "PRIMARY KEY (`transfer_id`),"
            "UNIQUE KEY `uq_netlab_transfer_run_sku` (`run_id`, `source_sku`),"
            "KEY `idx_netlab_transfer_target` (`target_product_id`)"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;"
        ),
        f"SET @netlab_transfer_run_id = {_sql_text(plan.run_id)};",
    ]
    statements.extend(
        _render_update(
            record,
            prefix=plan.policy.table_prefix,
            language_id=plan.policy.language_id,
            transferred_at=effective_transferred_at,
            run_id=plan.run_id,
            source_artifact_path=source_artifact_path,
            source_artifact_sha256=plan.source_artifact_sha256,
            matches_artifact_sha256=plan.matches_artifact_sha256,
        )
        for record in plan.updates
    )
    statements.extend(
        _render_create(
            record,
            prefix=plan.policy.table_prefix,
            language_id=plan.policy.language_id,
            transferred_at=effective_transferred_at,
            run_id=plan.run_id,
            source_artifact_path=source_artifact_path,
            source_artifact_sha256=plan.source_artifact_sha256,
            matches_artifact_sha256=plan.matches_artifact_sha256,
        )
        for record in plan.creates
    )
    statements.extend(
        [
            (
                "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, "
                "COUNT(*) AS audit_rows FROM `oc_netlab_transfer_audit` "
                f"WHERE `run_id`={_sql_text(plan.run_id)};"
            ),
            (
                "SELECT 'NETLAB_TRANSFER_RELATIONS_CREATED' AS marker, "
                f"{plan.relations_created} AS value;"
            ),
            "SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;",
            "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;",
        ]
    )
    return "\n".join(statement.rstrip(";") + ";" for statement in statements) + "\n"


def plan_summary(plan: TransferPlan) -> dict[str, Any]:
    """Return a JSON-safe, non-secret summary for a preview/report."""
    return {
        "mode": "netlab_snapshot_transfer",
        "run_id": plan.run_id,
        "source_path": str(plan.source_path),
        "matches_path": str(plan.matches_path),
        "source_artifact_sha256": plan.source_artifact_sha256,
        "matches_artifact_sha256": plan.matches_artifact_sha256,
        "source_record_count": plan.source_record_count,
        "match_record_count": plan.match_record_count,
        "update_count": plan.update_count,
        "create_count": plan.create_count,
        "exception_count": len(plan.exceptions),
        "relations_created": plan.relations_created,
        "media_assignments": plan.media_assignments,
        "attribute_assignments": plan.attribute_assignments,
        "attribute_mapping_sha256": plan.policy.attribute_mapping_sha256,
        "attribute_mapping_artifact_sha256": plan.policy.attribute_mapping_artifact_sha256,
        "attribute_mapping_database": plan.policy.attribute_mapping_database,
        "attribute_mapping_language_id": plan.policy.attribute_mapping_language_id,
        "attribute_mapping_scope_skus": sorted(plan.policy.attribute_mapping_scope_skus or ()),
        "bounded_canary_supplier_item_ids": sorted(plan.policy.bounded_canary_supplier_item_ids or ()),
        "require_complete_attribute_mapping": plan.policy.require_complete_attribute_mapping,
        "unmapped_attribute_names": list(plan.unmapped_attribute_names),
        "production_writes": 0,
        "publication_enabled": False,
        "feed_override": plan.feed_override,
        "selection_mode": "all" if plan.policy.selected_supplier_item_ids is None else "explicit",
        "selection_manifest_sha256": plan.policy.selection_manifest_sha256,
        "attribute_mapping_path": plan.policy.attribute_mapping_path,
        "verification_status": "transferred_unverified",
    }
