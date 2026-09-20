"""Fail-closed selector for the approved two-root Netlab staging pilot."""

from __future__ import annotations

import codecs
import csv
import hashlib
import io
import json
import os
import re
import stat
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SELECTOR_SCHEMA_VERSION = 1
_MAX_CSV_BYTES = 1024 * 1024 * 1024
_MAX_SQL_BYTES = 256 * 1024 * 1024
_MAX_SELECTOR_ROWS = 100_000
_EXPECTED_ROOTS = {
    456: "Ноутбуки и компьютеры",
    537: "Смартфоны,ТВ и электроника",
}
_SELECTOR_POLICY_VERSION = "two-category-strong-v1"
_CATEGORY_COLUMNS = (
    "category_id",
    "image",
    "oct_image",
    "parent_id",
    "top",
    "column",
    "sort_order",
    "status",
    "page_group_links",
    "date_added",
    "date_modified",
    "noindex",
)
_CATEGORY_DESCRIPTION_COLUMNS = (
    "category_id",
    "language_id",
    "name",
    "description",
    "meta_title",
    "meta_description",
    "meta_keyword",
    "meta_h1",
)
_MATCH_FIELDS = {
    "supplier_item_id",
    "catalog_sku",
    "catalog_product_id",
    "status",
    "confidence",
    "matched_by",
    "warnings",
}
_CATEGORY_MAPPING_FIELDS = {
    "source_category_path",
    "source_total",
    "source_only_products",
    "exact_support",
    "suggested_category_ids",
    "suggested_categories",
    "dominant_support",
    "dominance_pct",
    "alternatives",
    "mapping_status",
    "publication_eligible",
}
_PRODUCT_PROPOSAL_FIELDS = {
    "supplier_item_id",
    "catalog_sku",
    "name",
    "source_category_path",
    "suggested_category_ids",
    "suggested_categories",
    "mapping_status",
    "proposal_status",
    "publication_eligible",
}
_SOURCE_FIELDS = (
    "supplier",
    "supplier_item_id",
    "catalog_sku",
    "supplier_sku",
    "manufacturer",
    "model",
    "mpn",
    "ean",
    "identity_warnings",
    "name",
    "category_id",
    "category_path",
    "source_price",
    "old_price",
    "currency",
    "quantity",
    "available",
    "store",
    "pickup",
    "delivery",
    "source_url",
    "image_urls",
    "description",
    "description_html",
    "properties",
    "content_provenance",
    "sales_notes",
    "manufacturer_warranty",
    "warranty_days",
    "vat",
    "weight",
    "dimensions",
    "attributes",
    "fetched_at",
    "raw_hash",
)
_SOURCE_REQUIRED_FIELDS = set(_SOURCE_FIELDS)


class CategorySelectorError(ValueError):
    """Raised when category scope or selector provenance is invalid."""


@dataclass(frozen=True)
class CategoryRoot:
    category_id: int
    name: str
    descendant_ids: tuple[int, ...]


@dataclass(frozen=True)
class CategoryTreeSnapshot:
    snapshot_sha256: str
    roots: tuple[CategoryRoot, ...]
    descendant_ids: tuple[int, ...]
    allowlist_sha256: str
    category_names: tuple[tuple[int, str], ...]
    all_category_names: tuple[tuple[int, str], ...]

    @property
    def root_for_category(self) -> dict[int, int]:
        result: dict[int, int] = {}
        for root in self.roots:
            for category_id in root.descendant_ids:
                if category_id in result and result[category_id] != root.category_id:
                    raise CategorySelectorError(
                        f"category {category_id} belongs to multiple approved roots"
                    )
                result[category_id] = root.category_id
        return result

    @property
    def names(self) -> dict[int, str]:
        return dict(self.category_names)

    def as_manifest(self) -> dict[str, Any]:
        return {
            "snapshot_sha256": self.snapshot_sha256,
            "allowlist_sha256": self.allowlist_sha256,
            "roots": [
                {
                    "category_id": root.category_id,
                    "name": root.name,
                    "descendant_ids": list(root.descendant_ids),
                    "descendant_count": len(root.descendant_ids),
                }
                for root in self.roots
            ],
            "descendant_category_ids": list(self.descendant_ids),
        }


@dataclass(frozen=True)
class CategorySelection:
    selected_supplier_item_ids: frozenset[str]
    selection_manifest: tuple[dict[str, Any], ...]
    selected_root_counts: dict[str, int]
    exclusion_counts: dict[str, int]
    mapping_status_counts: dict[str, int]
    source_rows_scanned: int
    source_sha256: str
    matches_sha256: str
    category_mapping_sha256: str
    product_proposals_sha256: str
    category_snapshot: CategoryTreeSnapshot
    selection_manifest_sha256: str

    @property
    def selected_count(self) -> int:
        return len(self.selection_manifest)

    def as_manifest(self) -> dict[str, Any]:
        return {
            "selector_schema_version": _SELECTOR_SCHEMA_VERSION,
            "selector_policy_version": _SELECTOR_POLICY_VERSION,
            "policy": {
                "allowed_mapping_status": "strong_candidate",
                "source_category_id_namespace": "netlab",
                "target_category_id_namespace": "opencart",
                "unmatched_requires_item_proposal": True,
            },
            "category_scope": self.category_snapshot.as_manifest(),
            "inputs": {
                "normalized_source_sha256": self.source_sha256,
                "matches_sha256": self.matches_sha256,
                "category_mapping_proposals_sha256": self.category_mapping_sha256,
                "product_category_proposals_sha256": self.product_proposals_sha256,
            },
            "counts": {
                "source_rows_scanned": self.source_rows_scanned,
                "selected_total": self.selected_count,
                "selected_root_counts": dict(self.selected_root_counts),
                "exclusions": dict(self.exclusion_counts),
                "mapping_status_counts": dict(self.mapping_status_counts),
            },
            "selection_manifest_sha256": self.selection_manifest_sha256,
        }


class _HashingReader(io.RawIOBase):
    def __init__(
        self,
        raw: Any,
        *,
        maximum: int,
        label: str,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        self._raw = raw
        self._maximum = maximum
        self._label = label
        self._deadline_check = deadline_check
        self._digest = hashlib.sha256()
        self.size = 0
        self._closed = False

    @property
    def digest(self) -> str:
        return self._digest.hexdigest()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        self._record(data)
        return data

    def readinto(self, buffer: bytearray) -> int:
        count = self._raw.readinto(buffer)
        if count:
            self._record(bytes(memoryview(buffer)[:count]))
        return count

    def _record(self, data: bytes) -> None:
        if not data:
            return
        if self._deadline_check is not None:
            self._deadline_check()
        self.size += len(data)
        if self.size > self._maximum:
            raise CategorySelectorError(f"{self._label} exceeds byte limit")
        self._digest.update(data)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._raw.close()
        super().close()


@contextmanager
def _csv_reader(
    path: Path,
    *,
    label: str,
    required_fields: set[str],
    exact_fields: bool = False,
    expected_order: tuple[str, ...] | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> Iterator[tuple[csv.DictReader[str], _HashingReader]]:
    path = _regular_file(path, label=label)
    try:
        before_path_stat = os.lstat(path)
        raw = path.open("rb")
        before_handle_stat = os.fstat(raw.fileno())
        if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
            before_handle_stat.st_dev,
            before_handle_stat.st_ino,
            before_handle_stat.st_size,
        ):
            raw.close()
            raise CategorySelectorError(f"{label} changed before parsing")
    except OSError as exc:
        raise CategorySelectorError(f"cannot read {label}: {path}") from exc
    hashing = _HashingReader(raw, maximum=_MAX_CSV_BYTES, label=label, deadline_check=deadline_check)
    buffered = io.BufferedReader(hashing)
    text = io.TextIOWrapper(buffered, encoding="utf-8-sig", newline="")
    try:
        reader = csv.DictReader(text)
        fields = reader.fieldnames
        if not fields or any(field is None or not field for field in fields):
            raise CategorySelectorError(f"{label} has an invalid header")
        if len(set(fields)) != len(fields):
            raise CategorySelectorError(f"{label} has duplicate header fields")
        field_set = set(fields)
        if not required_fields.issubset(field_set):
            missing = sorted(required_fields - field_set)
            raise CategorySelectorError(f"{label} is missing fields: {missing}")
        if exact_fields and field_set != required_fields:
            raise CategorySelectorError(f"{label} has an unsupported header")
        if expected_order is not None and tuple(fields) != expected_order:
            raise CategorySelectorError(f"{label} has an unsupported header order")
        yield reader, hashing
    except csv.Error as exc:
        raise CategorySelectorError(f"invalid CSV in {label}") from exc
    finally:
        try:
            after_path_stat = os.lstat(path)
            after_handle_stat = os.fstat(raw.fileno())
            if (after_path_stat.st_dev, after_path_stat.st_ino, after_path_stat.st_size) != (
                before_path_stat.st_dev,
                before_path_stat.st_ino,
                before_path_stat.st_size,
            ) or (after_handle_stat.st_dev, after_handle_stat.st_ino, after_handle_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise CategorySelectorError(f"{label} changed during parsing")
        except OSError as exc:
            raise CategorySelectorError(f"cannot recheck {label} after parsing") from exc
        finally:
            try:
                text.close()
            except (OSError, ValueError):
                raw.close()


def _regular_file(path: Path, *, label: str) -> Path:
    try:
        path = Path(path)
        file_stat = os.lstat(path)
        if path.is_symlink() or not stat.S_ISREG(file_stat.st_mode):
            raise CategorySelectorError(f"{label} is not a regular file")
        return path
    except OSError as exc:
        raise CategorySelectorError(f"cannot inspect {label}: {path}") from exc


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _row_values(row: dict[str | None, str | None], *, label: str) -> dict[str, str]:
    if None in row:
        raise CategorySelectorError(f"{label} contains a row with extra columns")
    result: dict[str, str] = {}
    for key, value in row.items():
        if key is None:
            raise CategorySelectorError(f"{label} contains a null column name")
        if value is None:
            raise CategorySelectorError(f"{label} contains a null value")
        if "\x00" in value:
            raise CategorySelectorError(f"{label} contains a NUL byte")
        result[key] = value
    return result


def _row_hash(row: dict[str, str]) -> str:
    return hashlib.sha256(_canonical_json(row).encode("utf-8")).hexdigest()


def _parse_source_category(raw: str, *, label: str) -> tuple[str, ...]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CategorySelectorError(f"{label} has invalid category_path JSON") from exc
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise CategorySelectorError(f"{label} category_path must be a non-empty string list")
    if any("\x00" in item for item in value):
        raise CategorySelectorError(f"{label} category_path contains NUL")
    return tuple(value)


def _canonical_source_category(raw: str, *, label: str) -> str:
    return _canonical_json(list(_parse_source_category(raw, label=label)))


def _parse_int(value: str, *, label: str, positive: bool = False) -> int:
    if not re.fullmatch(r"[0-9]+", value.strip()):
        raise CategorySelectorError(f"{label} must be a decimal integer")
    parsed = int(value)
    if positive and parsed <= 0:
        raise CategorySelectorError(f"{label} must be positive")
    return parsed


def _parse_target_id(raw: str, *, label: str) -> tuple[int | None, str | None]:
    value = raw.strip()
    if not value or value == "0":
        return None, "target_zero"
    if not re.fullmatch(r"[0-9]+", value):
        if any(separator in value for separator in (",", ";", "[", "]")):
            return None, "target_multi"
        return None, "target_malformed"
    parsed = int(value)
    if parsed <= 0:
        return None, "target_zero"
    return parsed, None


def _extract_insert_statements(
    sql: str,
    table: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> list[str]:
    marker = f"INSERT INTO `{table}`"
    statements: list[str] = []
    position = 0
    while True:
        if deadline_check is not None:
            deadline_check()
        start = sql.find(marker, position)
        if start < 0:
            return statements
        index = start
        quoted = False
        escaped = False
        while index < len(sql):
            if deadline_check is not None and (index & 4095) == 0:
                deadline_check()
            char = sql[index]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    quoted = False
            elif char == "'":
                quoted = True
            elif char == ";":
                statements.append(sql[start : index + 1])
                position = index + 1
                break
            index += 1
        else:
            raise CategorySelectorError(f"unterminated INSERT for {table}")


def _parse_sql_literal(
    sql: str,
    index: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str | None, int]:
    while index < len(sql) and sql[index].isspace():
        if deadline_check is not None and (index & 4095) == 0:
            deadline_check()
        index += 1
    if index >= len(sql):
        raise CategorySelectorError("truncated SQL value")
    if sql[index] == "'":
        index += 1
        chars: list[str] = []
        while index < len(sql):
            if deadline_check is not None and (index & 4095) == 0:
                deadline_check()
            char = sql[index]
            if char == "\\":
                if index + 1 >= len(sql):
                    raise CategorySelectorError("truncated SQL escape")
                escaped = sql[index + 1]
                chars.append({"n": "\n", "r": "\r", "t": "\t", "0": "\x00", "Z": "\x1a"}.get(escaped, escaped))
                index += 2
                continue
            if char == "'":
                if index + 1 < len(sql) and sql[index + 1] == "'":
                    chars.append("'")
                    index += 2
                    continue
                return "".join(chars), index + 1
            chars.append(char)
            index += 1
        raise CategorySelectorError("unterminated SQL string")
    end = index
    while end < len(sql) and sql[end] not in ",)":
        if deadline_check is not None and (end & 4095) == 0:
            deadline_check()
        end += 1
    token = sql[index:end].strip()
    return (None if token.upper() == "NULL" else token), end


def _declared_table_columns(
    sql: str,
    table: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str, ...]:
    if deadline_check is not None:
        deadline_check()
    marker = f"CREATE TABLE `{table}` ("
    start = sql.find(marker)
    if start < 0:
        raise CategorySelectorError(f"category snapshot lacks DDL for {table}")
    end_match = re.search(r"\)\s+ENGINE=", sql[start + len(marker) :])
    if end_match is None:
        raise CategorySelectorError(f"category snapshot has truncated DDL for {table}")
    body = sql[start + len(marker) : start + len(marker) + end_match.start()]
    columns_list: list[str] = []
    for line in body.splitlines():
        if deadline_check is not None:
            deadline_check()
        match = re.match(r"\s*`([^`]+)`\s+", line)
        if match is not None:
            columns_list.append(match.group(1))
    columns = tuple(columns_list)
    if len(columns) != len(set(columns)):
        raise CategorySelectorError(f"category snapshot DDL repeats a column for {table}")
    return columns


def _parse_sql_rows(
    statement: str,
    *,
    deadline_check: Callable[[], None] | None = None,
    max_rows: int | None = None,
) -> list[list[str | None]]:
    values_index = statement.find("VALUES")
    if values_index < 0:
        raise CategorySelectorError("category snapshot INSERT has no VALUES")
    header = statement[:values_index]
    if re.search(r"INSERT\s+INTO\s+`[^`]+`\s*\(", header, flags=re.IGNORECASE):
        raise CategorySelectorError("category snapshot INSERT has unsupported column list")
    index = values_index + len("VALUES")
    rows: list[list[str | None]] = []
    while index < len(statement):
        if deadline_check is not None and (index & 4095) == 0:
            deadline_check()
        while index < len(statement) and (statement[index].isspace() or statement[index] == ","):
            if deadline_check is not None and (index & 4095) == 0:
                deadline_check()
            index += 1
        if index >= len(statement) or statement[index] == ";":
            break
        if statement[index] != "(":
            raise CategorySelectorError("unsupported category snapshot SQL tuple")
        index += 1
        row: list[str | None] = []
        while True:
            value, index = _parse_sql_literal(
                statement,
                index,
                deadline_check=deadline_check,
            )
            row.append(value)
            while index < len(statement) and statement[index].isspace():
                if deadline_check is not None and (index & 4095) == 0:
                    deadline_check()
                index += 1
            if index >= len(statement):
                raise CategorySelectorError("truncated category snapshot tuple")
            if statement[index] == ",":
                index += 1
                continue
            if statement[index] == ")":
                index += 1
                break
            raise CategorySelectorError("unsupported category snapshot tuple separator")
        if max_rows is not None and len(rows) >= max_rows:
            raise CategorySelectorError("category snapshot exceeds row-count limit")
        rows.append(row)
    return rows


def _read_snapshot_bytes(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str, str]:
    path = _regular_file(path, label="category snapshot")
    try:
        before_path_stat = os.lstat(path)
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise CategorySelectorError("category snapshot changed before parsing")
            chunks = bytearray()
            total = 0
            while total <= _MAX_SQL_BYTES:
                if deadline_check is not None:
                    deadline_check()
                chunk = handle.read(min(1024 * 1024, _MAX_SQL_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.extend(chunk)
                total += len(chunk)
            data = chunks
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
    except OSError as exc:
        raise CategorySelectorError(f"cannot read category snapshot: {path}") from exc
    if (
        len(data) > _MAX_SQL_BYTES
        or len(data) != after_handle_stat.st_size
        or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size)
        != (after_handle_stat.st_dev, after_handle_stat.st_ino, after_handle_stat.st_size)
        or (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size)
        != (after_path_stat.st_dev, after_path_stat.st_ino, after_path_stat.st_size)
    ):
        raise CategorySelectorError("category snapshot changed during parsing")
    try:
        if deadline_check is not None:
            deadline_check()
        decoder = codecs.getincrementaldecoder("utf-8")()
        decoded_parts: list[str] = []
        for offset in range(0, len(data), 1024 * 1024):
            if deadline_check is not None:
                deadline_check()
            decoded_parts.append(decoder.decode(data[offset : offset + 1024 * 1024], final=False))
        decoded_parts.append(decoder.decode(b"", final=True))
        decoded = "".join(decoded_parts)
        digest = hashlib.sha256()
        for offset in range(0, len(data), 1024 * 1024):
            if deadline_check is not None:
                deadline_check()
            digest.update(data[offset : offset + 1024 * 1024])
        return decoded, digest.hexdigest()
    except UnicodeDecodeError as exc:
        raise CategorySelectorError("category snapshot is not UTF-8") from exc


def build_category_tree_snapshot(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> CategoryTreeSnapshot:
    sql, snapshot_sha256 = _read_snapshot_bytes(path, deadline_check=deadline_check)
    if _declared_table_columns(sql, "oc_category", deadline_check=deadline_check) != _CATEGORY_COLUMNS:
        raise CategorySelectorError("category snapshot oc_category DDL does not match approved column order")
    if _declared_table_columns(
        sql,
        "oc_category_description",
        deadline_check=deadline_check,
    ) != _CATEGORY_DESCRIPTION_COLUMNS:
        raise CategorySelectorError(
            "category snapshot oc_category_description DDL does not match approved column order"
        )
    category_rows: list[list[str | None]] = []
    for statement in _extract_insert_statements(
        sql,
        "oc_category",
        deadline_check=deadline_check,
    ):
        if deadline_check is not None:
            deadline_check()
        category_rows.extend(
            _parse_sql_rows(
                statement,
                deadline_check=deadline_check,
                max_rows=_MAX_SELECTOR_ROWS,
            )
        )
        if len(category_rows) > _MAX_SELECTOR_ROWS:
            raise CategorySelectorError("category snapshot exceeds row-count limit")
    description_rows: list[list[str | None]] = []
    for statement in _extract_insert_statements(
        sql,
        "oc_category_description",
        deadline_check=deadline_check,
    ):
        if deadline_check is not None:
            deadline_check()
        description_rows.extend(
            _parse_sql_rows(
                statement,
                deadline_check=deadline_check,
                max_rows=_MAX_SELECTOR_ROWS,
            )
        )
        if len(description_rows) > _MAX_SELECTOR_ROWS:
            raise CategorySelectorError("category snapshot exceeds row-count limit")
    if not category_rows or not description_rows:
        raise CategorySelectorError("category snapshot lacks required tables")

    parents: dict[int, int] = {}
    for row in category_rows:
        if deadline_check is not None:
            deadline_check()
        if len(row) != 12 or row[0] is None or row[3] is None:
            raise CategorySelectorError("category snapshot has an unsupported oc_category schema")
        category_id = _parse_int(str(row[0]), label="category_id", positive=True)
        parent_id = _parse_int(str(row[3]), label=f"parent_id for {category_id}")
        if category_id in parents:
            raise CategorySelectorError(f"duplicate category_id in snapshot: {category_id}")
        parents[category_id] = parent_id

    names: dict[int, str] = {}
    for row in description_rows:
        if deadline_check is not None:
            deadline_check()
        if len(row) != 8 or row[0] is None or row[1] is None or row[2] is None:
            raise CategorySelectorError("category snapshot has an unsupported oc_category_description schema")
        category_id = _parse_int(str(row[0]), label="description category_id", positive=True)
        language_id = _parse_int(str(row[1]), label="description language_id", positive=True)
        if language_id != 1:
            continue
        name = str(row[2])
        if category_id in names and names[category_id] != name:
            raise CategorySelectorError(f"conflicting category name for {category_id}")
        names[category_id] = name

    children: dict[int, list[int]] = defaultdict(list)
    for category_id, parent_id in parents.items():
        children[parent_id].append(category_id)

    root_objects: list[CategoryRoot] = []
    all_descendants: set[int] = set()
    for root_id, expected_name in _EXPECTED_ROOTS.items():
        if root_id not in parents:
            raise CategorySelectorError(f"missing approved root category {root_id}")
        if parents[root_id] != 0:
            raise CategorySelectorError(f"approved root {root_id} is not top-level")
        if names.get(root_id) != expected_name:
            raise CategorySelectorError(f"approved root {root_id} has unexpected root name")
        descendants: list[int] = []
        stack: list[tuple[int, tuple[int, ...]]] = [(root_id, ())]
        while stack:
            if deadline_check is not None:
                deadline_check()
            current, ancestry = stack.pop()
            if current in ancestry:
                raise CategorySelectorError(f"category cycle reaches root {root_id}")
            descendants.append(current)
            all_descendants.add(current)
            next_ancestry = (*ancestry, current)
            for child in sorted(children.get(current, []), reverse=True):
                if deadline_check is not None:
                    deadline_check()
                stack.append((child, next_ancestry))
        if any(category_id not in names for category_id in descendants):
            raise CategorySelectorError(f"approved root {root_id} has an unnamed descendant")
        root_objects.append(CategoryRoot(root_id, expected_name, tuple(sorted(descendants))))

    if len(all_descendants) != sum(len(root.descendant_ids) for root in root_objects):
        raise CategorySelectorError("approved category trees overlap")
    descendant_ids = tuple(sorted(all_descendants))
    allowlist_material = _canonical_json(list(descendant_ids)).encode("utf-8")
    return CategoryTreeSnapshot(
        snapshot_sha256=snapshot_sha256,
        roots=tuple(root_objects),
        descendant_ids=descendant_ids,
        allowlist_sha256=hashlib.sha256(allowlist_material).hexdigest(),
        category_names=tuple(sorted((category_id, names[category_id]) for category_id in all_descendants)),
        all_category_names=tuple(sorted(names.items())),
    )


_ALLOWED_MATCH_STATUSES = {"exact", "unmatched", "conflict", "high_confidence", "ambiguous"}
_ALLOWED_MATCHED_BY = {"sku", "ean_unique", "manufacturer_model_unique", "catalog_product_reused", "identity_candidate"}
_ALLOWED_MAPPING_STATUSES = {"strong_candidate", "review_candidate", "ambiguous", "unmapped"}
_ALLOWED_PROPOSAL_STATUSES = {"review_only", "blocked_unmapped", "blocked_ambiguous_category"}


def _parse_warning_list(raw: str, *, label: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CategorySelectorError(f"{label} warnings are not valid JSON") from error
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CategorySelectorError(f"{label} warnings must be a JSON string list")
    return value


def _validate_match_row(row: dict[str, str]) -> None:
    status = row["status"].strip()
    if status not in _ALLOWED_MATCH_STATUSES:
        raise CategorySelectorError(f"unsupported match status: {status or '<empty>'}")
    product_id = row["catalog_product_id"].strip()
    if product_id and not re.fullmatch(r"[1-9][0-9]*", product_id):
        raise CategorySelectorError("match catalog_product_id must be a positive decimal")
    confidence = row["confidence"].strip()
    if not re.fullmatch(r"(?:0|1|0?\.[0-9]+|1\.0+)", confidence):
        raise CategorySelectorError("match confidence is not a bounded decimal")
    warnings = _parse_warning_list(row["warnings"], label=f"{status} match")
    matched_by = row["matched_by"].strip()
    if matched_by and matched_by not in _ALLOWED_MATCHED_BY:
        raise CategorySelectorError("match matched_by is outside the allowlist")
    if status == "exact":
        if confidence != "1.00" or not product_id or warnings or matched_by != "sku":
            raise CategorySelectorError("exact match warnings or identity fields are inconsistent")
    elif status == "unmatched" and (product_id or warnings or matched_by or confidence != "0"):
        raise CategorySelectorError("unmatched match identity fields are inconsistent")
    elif status in {"conflict", "high_confidence"} and (not product_id or not matched_by):
        raise CategorySelectorError("candidate match identity fields are inconsistent")
    elif status == "ambiguous" and product_id:
        raise CategorySelectorError("ambiguous match must not carry a product ID")


def _validate_proposal_row(row: dict[str, str], *, product: bool) -> None:
    status = row["mapping_status"].strip()
    if status not in _ALLOWED_MAPPING_STATUSES:
        raise CategorySelectorError(f"unsupported mapping status: {status or '<empty>'}")
    if row["publication_eligible"].strip() != "False":
        raise CategorySelectorError("publication_eligible must be literal False for staging")
    target = row["suggested_category_ids"].strip()
    if target and not re.fullmatch(r"[1-9][0-9]*", target):
        raise CategorySelectorError("suggested_category_ids must be one positive decimal ID")
    if status == "strong_candidate" and not target:
        raise CategorySelectorError("strong_candidate proposal must have a target category")
    if not target and row["suggested_categories"].strip():
        raise CategorySelectorError("suggested_categories must be empty without a target")
    if not product:
        for field in ("source_total", "source_only_products", "exact_support", "dominant_support"):
            if not re.fullmatch(r"0|[1-9][0-9]*", row[field].strip()):
                raise CategorySelectorError(f"category proposal {field} is not a nonnegative integer")
        dominance = row["dominance_pct"].strip()
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?", dominance):
            raise CategorySelectorError("category proposal dominance_pct is not numeric")
        if float(dominance) < 0 or float(dominance) > 100:
            raise CategorySelectorError("category proposal dominance_pct is outside 0..100")
        try:
            alternatives = json.loads(row["alternatives"])
        except json.JSONDecodeError as error:
            raise CategorySelectorError("category proposal alternatives are not valid JSON") from error
        if not isinstance(alternatives, list):
            raise CategorySelectorError("category proposal alternatives must be a JSON list")
        for alternative in alternatives:
            if not isinstance(alternative, dict):
                raise CategorySelectorError("category proposal alternative must be an object")
            category_name = alternative.get("categories")
            category_ids = alternative.get("category_ids")
            if not isinstance(category_name, str) or not isinstance(category_ids, str):
                raise CategorySelectorError("category proposal alternative has invalid category fields")
            if category_name == "" and category_ids == "":
                pass
            elif not re.fullmatch(r"[1-9][0-9]*", category_ids):
                raise CategorySelectorError("category proposal alternative has invalid category fields")
            if not isinstance(alternative.get("support"), int) or alternative["support"] < 0:
                raise CategorySelectorError("category proposal alternative has invalid support")
        if status == "strong_candidate":
            if (
                row["dominance_pct"].strip() != "100.0"
                or int(row["exact_support"]) < 1
                or row["dominant_support"].strip() != row["exact_support"].strip()
                or len(alternatives) != 1
            ):
                raise CategorySelectorError("strong_candidate support semantics are inconsistent")
            alternative = alternatives[0]
            if (
                alternative["category_ids"] != target
                or alternative["categories"] != row["suggested_categories"].strip()
                or alternative["support"] != int(row["dominant_support"])
            ):
                raise CategorySelectorError("strong_candidate alternative is inconsistent")
    if product:
        proposal_status = row["proposal_status"].strip()
        if proposal_status not in _ALLOWED_PROPOSAL_STATUSES:
            raise CategorySelectorError("unsupported product proposal status")
        expected = {
            "strong_candidate": "review_only",
            "review_candidate": "review_only",
            "ambiguous": "blocked_ambiguous_category",
            "unmapped": "blocked_unmapped",
        }[status]
        if proposal_status != expected:
            raise CategorySelectorError("product proposal status contradicts mapping status")


def _load_matches(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, dict[str, str]], str]:
    result: dict[str, dict[str, str]] = {}
    with _csv_reader(
        path,
        label="matches",
        required_fields=_MATCH_FIELDS,
        exact_fields=True,
        deadline_check=deadline_check,
    ) as (reader, hashing):
        for raw_row in reader:
            if deadline_check is not None:
                deadline_check()
            if len(result) >= _MAX_SELECTOR_ROWS:
                raise CategorySelectorError("matches exceeds row-count limit")
            row = _row_values(raw_row, label="matches")
            _validate_match_row(row)
            supplier_id = row["supplier_item_id"].strip()
            if not supplier_id or supplier_id in result:
                raise CategorySelectorError(f"duplicate or empty match supplier_item_id: {supplier_id or '<empty>'}")
            result[supplier_id] = {**row, "row_sha256": _row_hash(row)}
    return result, hashing.digest


def _load_unique_mapping(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, dict[str, str]], str]:
    result: dict[str, dict[str, str]] = {}
    with _csv_reader(
        path,
        label="category mapping proposals",
        required_fields=_CATEGORY_MAPPING_FIELDS,
        exact_fields=True,
        deadline_check=deadline_check,
    ) as (reader, hashing):
        for raw_row in reader:
            if deadline_check is not None:
                deadline_check()
            if len(result) >= _MAX_SELECTOR_ROWS:
                raise CategorySelectorError("category mapping proposals exceeds row-count limit")
            row = _row_values(raw_row, label="category mapping proposals")
            _validate_proposal_row(row, product=False)
            key = _canonical_source_category(row["source_category_path"], label="category mapping proposal")
            if key in result:
                raise CategorySelectorError(f"duplicate category mapping source path: {key}")
            result[key] = {**row, "canonical_source_category_path": key, "row_sha256": _row_hash(row)}
    return result, hashing.digest


def _load_product_proposals(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, dict[str, str]], str]:
    result: dict[str, dict[str, str]] = {}
    with _csv_reader(
        path,
        label="product category proposals",
        required_fields=_PRODUCT_PROPOSAL_FIELDS,
        exact_fields=True,
        deadline_check=deadline_check,
    ) as (reader, hashing):
        for raw_row in reader:
            if deadline_check is not None:
                deadline_check()
            if len(result) >= _MAX_SELECTOR_ROWS:
                raise CategorySelectorError("product category proposals exceeds row-count limit")
            row = _row_values(raw_row, label="product category proposals")
            _validate_proposal_row(row, product=True)
            supplier_id = row["supplier_item_id"].strip()
            if not supplier_id:
                raise CategorySelectorError("product category proposal has empty supplier_item_id")
            if supplier_id in result:
                raise CategorySelectorError(f"duplicate product category proposal: {supplier_id}")
            key = _canonical_source_category(row["source_category_path"], label="product category proposal")
            result[supplier_id] = {
                **row,
                "canonical_source_category_path": key,
                "row_sha256": _row_hash(row),
            }
    return result, hashing.digest


def _validate_strong_target_name(
    row: dict[str, str],
    target_id: int | None,
    *,
    category_names: dict[int, str],
    label: str,
) -> None:
    if row["mapping_status"].strip() != "strong_candidate":
        return
    if target_id is None or target_id not in category_names:
        raise CategorySelectorError(f"{label} strong target is absent from category snapshot")
    if row["suggested_categories"].strip() != category_names[target_id].strip():
        raise CategorySelectorError(f"{label} suggested_categories disagrees with category snapshot")


def _selection_reason(
    target_raw: str,
    *,
    target_namespace: dict[int, int],
    label: str,
) -> tuple[int | None, str | None, int | None]:
    target_id, reason = _parse_target_id(target_raw, label=label)
    if reason:
        return None, reason, None
    assert target_id is not None
    root_id = target_namespace.get(target_id)
    if root_id is None:
        return target_id, "target_outside_allowlist", None
    return target_id, None, root_id


def select_two_category_items(
    source_path: Path,
    matches_path: Path,
    category_mapping_path: Path,
    product_proposals_path: Path,
    category_snapshot_path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> CategorySelection:
    """Select exact/unmatched source rows whose site mapping is in the two roots."""
    snapshot = build_category_tree_snapshot(category_snapshot_path, deadline_check=deadline_check)
    matches, matches_sha256 = _load_matches(matches_path, deadline_check=deadline_check)
    category_mappings, category_mapping_sha256 = _load_unique_mapping(
        category_mapping_path,
        deadline_check=deadline_check,
    )
    product_proposals, product_proposals_sha256 = _load_product_proposals(
        product_proposals_path,
        deadline_check=deadline_check,
    )
    root_namespace = snapshot.root_for_category
    category_names = dict(snapshot.all_category_names)

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    selected_root_counts = {str(root.category_id): 0 for root in snapshot.roots}
    exclusions: dict[str, int] = defaultdict(int)
    mapping_status_counts: dict[str, int] = defaultdict(int)
    seen_source_ids: set[str] = set()
    source_rows_scanned = 0

    with _csv_reader(
        source_path,
        label="normalized source",
        required_fields=_SOURCE_REQUIRED_FIELDS,
        exact_fields=True,
        expected_order=_SOURCE_FIELDS,
        deadline_check=deadline_check,
    ) as (reader, source_hashing):
        for raw_row in reader:
            if deadline_check is not None:
                deadline_check()
            if source_rows_scanned >= _MAX_SELECTOR_ROWS:
                raise CategorySelectorError("normalized source exceeds row-count limit")
            row = _row_values(raw_row, label="normalized source")
            source_rows_scanned += 1
            supplier_id = row["supplier_item_id"].strip()
            catalog_sku = row["catalog_sku"].strip()
            if not supplier_id or supplier_id in seen_source_ids:
                raise CategorySelectorError(f"duplicate or empty source supplier_item_id: {supplier_id or '<empty>'}")
            seen_source_ids.add(supplier_id)
            source_path_key = _canonical_source_category(
                row["category_path"], label=f"source item {supplier_id}"
            )
            match = matches.get(supplier_id)
            if match is None:
                exclusions["match_missing"] += 1
                continue
            if match["catalog_sku"].strip() and match["catalog_sku"].strip() != catalog_sku:
                exclusions["match_sku_mismatch"] += 1
                continue
            if match["status"] not in {"exact", "unmatched"}:
                exclusions["match_not_transferable"] += 1
                continue

            mapping = category_mappings.get(source_path_key)
            if mapping is None:
                exclusions["mapping_missing"] += 1
                continue
            mapping_status = mapping["mapping_status"].strip()
            mapping_status_counts[mapping_status] += 1
            if mapping_status != "strong_candidate":
                exclusions["mapping_not_strong_candidate"] += 1
                continue
            target_id, reason, root_id = _selection_reason(
                mapping["suggested_category_ids"],
                target_namespace=root_namespace,
                label=f"mapping for source item {supplier_id}",
            )
            _validate_strong_target_name(
                mapping,
                target_id,
                category_names=category_names,
                label=f"mapping for source item {supplier_id}",
            )
            if reason:
                exclusions[reason] += 1
                continue

            proposal: dict[str, str] | None = None
            if match["status"] == "unmatched":
                proposal = product_proposals.get(supplier_id)
                if proposal is None:
                    exclusions["proposal_missing"] += 1
                    continue
                if proposal["catalog_sku"].strip() != catalog_sku:
                    exclusions["proposal_sku_mismatch"] += 1
                    continue
                if proposal["canonical_source_category_path"] != source_path_key:
                    exclusions["source_path_mismatch"] += 1
                    continue
                proposal_status = proposal["mapping_status"].strip()
                mapping_status_counts[f"product:{proposal_status}"] += 1
                if proposal_status != "strong_candidate":
                    exclusions["proposal_not_strong_candidate"] += 1
                    continue
                proposal_target, proposal_reason, proposal_root = _selection_reason(
                    proposal["suggested_category_ids"],
                    target_namespace=root_namespace,
                    label=f"proposal for source item {supplier_id}",
                )
                _validate_strong_target_name(
                    proposal,
                    proposal_target,
                    category_names=category_names,
                    label=f"proposal for source item {supplier_id}",
                )
                if proposal_reason:
                    exclusions[proposal_reason] += 1
                    continue
                if proposal_target != target_id or proposal_root != root_id:
                    exclusions["target_conflict"] += 1
                    continue

            assert target_id is not None and root_id is not None
            selected_ids.add(supplier_id)
            if len(selected) >= _MAX_SELECTOR_ROWS:
                raise CategorySelectorError("selected rows exceed row-count limit")
            selected_root_counts[str(root_id)] += 1
            selected.append(
                {
                    "supplier_item_id": supplier_id,
                    "catalog_sku": catalog_sku,
                    "source_category_path": source_path_key,
                    "source_row_sha256": _row_hash(row),
                    "matches_row_sha256": match["row_sha256"],
                    "category_mapping_row_sha256": mapping["row_sha256"],
                    "product_proposal_row_sha256": proposal["row_sha256"] if proposal else None,
                    "mapping_status": "strong_candidate",
                    "mapping_origin": "category_mapping+product_proposal" if proposal else "category_mapping",
                    "target_category_id": target_id,
                    "root_category_id": root_id,
                }
            )

    if len(selected_ids) != len(selected):
        raise CategorySelectorError("selected supplier_item_id is not unique")
    if source_rows_scanned != len(selected) + sum(exclusions.values()):
        raise CategorySelectorError("selector exclusion counts do not conserve source rows")
    if len(selected) != sum(selected_root_counts.values()):
        raise CategorySelectorError("selector root counts do not conserve selected rows")

    if deadline_check is not None:
        deadline_check()
    selected.sort(key=lambda item: item["supplier_item_id"])
    if deadline_check is not None:
        deadline_check()
    selection_digest = hashlib.sha256()
    for row in selected:
        if deadline_check is not None:
            deadline_check()
        selection_digest.update((json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
    selection_manifest_sha256 = selection_digest.hexdigest()
    return CategorySelection(
        selected_supplier_item_ids=frozenset(selected_ids),
        selection_manifest=tuple(selected),
        selected_root_counts=dict(selected_root_counts),
        exclusion_counts=dict(sorted(exclusions.items())),
        mapping_status_counts=dict(sorted(mapping_status_counts.items())),
        source_rows_scanned=source_rows_scanned,
        source_sha256=source_hashing.digest,
        matches_sha256=matches_sha256,
        category_mapping_sha256=category_mapping_sha256,
        product_proposals_sha256=product_proposals_sha256,
        category_snapshot=snapshot,
        selection_manifest_sha256=selection_manifest_sha256,
    )
