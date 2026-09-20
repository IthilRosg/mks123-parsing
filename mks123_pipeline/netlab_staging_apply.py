"""Loopback-only application of a Netlab candidate into isolated staging."""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal, DecimalException, InvalidOperation
from pathlib import Path
from types import TracebackType
from typing import Any, BinaryIO, Self

from mks123_pipeline.integrity import IntegrityDeadlineExceeded, load_sealed_run
from mks123_pipeline.netlab_transfer import (
    TransferError,
    validate_attribute_mapping_payload,
    validate_source_freshness,
)
from mks123_pipeline.trusted_run import TrustedRunError, load_trusted_run_manifest
from mks123_pipeline.two_category_selector import (
    CategorySelectorError,
    select_two_category_items,
)


def _load_candidate_trusted_manifest(
    trusted_run_manifest: Path,
    *,
    candidate_root: Path | None = None,
    expected_seal_sha256: str | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if expected_seal_sha256 is None:
        raise StagingApplyError("external trusted run seal digest is required")
    try:
        trusted_manifest, trusted_identity, seal_metadata = load_trusted_run_manifest(
            trusted_run_manifest,
            expected_seal_sha256=expected_seal_sha256,
            deadline_check=deadline_check,
        )
    except IntegrityDeadlineExceeded:
        raise
    except TrustedRunError as exc:
        raise StagingApplyError(str(exc)) from exc
    if trusted_manifest.get("supplier") != "netlab":
        raise StagingApplyError("trusted run manifest provenance is invalid")
    if candidate_root is not None:
        try:
            if deadline_check is not None:
                deadline_check()
            trusted_root = Path(seal_metadata["run_root"]).resolve(strict=True)
            if deadline_check is not None:
                deadline_check()
            current_root = candidate_root.resolve(strict=True)
            if deadline_check is not None:
                deadline_check()
        except (OSError, KeyError, TypeError, ValueError) as exc:
            raise StagingApplyError("trusted run root identity cannot be resolved") from exc
        if current_root == trusted_root or current_root.is_relative_to(trusted_root):
            raise StagingApplyError("candidate must not be inside trusted run root")
    return trusted_manifest, trusted_identity, seal_metadata


def _trusted_sealed_input_path(
    input_entry: dict[str, Any],
    *,
    role: str,
    seal_metadata: dict[str, Any],
    deadline_check: Callable[[], None] | None = None,
) -> Path:
    paths = input_entry.get("paths")
    if deadline_check is not None:
        deadline_check()
    trusted_root = Path(str(seal_metadata.get("run_root", ""))).resolve(strict=True)
    if deadline_check is not None:
        deadline_check()
    sealed_files = seal_metadata.get("files")
    if not isinstance(paths, list) or not isinstance(sealed_files, dict):
        raise StagingApplyError(f"candidate trusted input is malformed: {role}")
    for raw_path in paths:
        if deadline_check is not None:
            deadline_check()
        if not isinstance(raw_path, str):
            continue
        path = Path(raw_path)
        try:
            raw_stat = os.lstat(path)
            resolved = path.resolve(strict=True)
            relative = resolved.relative_to(trusted_root).as_posix()
        except (OSError, ValueError):
            continue
        if stat.S_ISLNK(raw_stat.st_mode) or not stat.S_ISREG(raw_stat.st_mode):
            continue
        sealed_record = sealed_files.get(relative)
        if not isinstance(sealed_record, dict):
            continue
        identity = _file_identity(path, deadline_check=deadline_check)
        if identity != {
            "size": sealed_record.get("size"),
            "sha256": sealed_record.get("sha256"),
        }:
            raise StagingApplyError(f"candidate trusted input changed after seal: {role}")
        return path
    raise StagingApplyError(f"candidate trusted input is outside sealed run: {role}")


def _revalidate_candidate_source_freshness(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    trusted_run_manifest: Path | None,
    *,
    candidate_root: Path | None = None,
    expected_seal_sha256: str | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    trusted_fetched_at: str | None = None
    trusted_manifest_bound = trusted_run_manifest is not None
    if trusted_run_manifest is not None:
        trusted_manifest, trusted_identity, _ = _load_candidate_trusted_manifest(
            Path(trusted_run_manifest),
            candidate_root=candidate_root,
            expected_seal_sha256=expected_seal_sha256,
            deadline_check=deadline_check,
        )
        input_entry = manifest.get("inputs", {}).get("run_manifest")
        if not isinstance(input_entry, dict):
            raise StagingApplyError("candidate run manifest input is missing")
        expected_identity = {"size": input_entry.get("size"), "sha256": input_entry.get("sha256")}
        if trusted_identity != expected_identity:
            raise StagingApplyError("trusted run manifest changed after candidate validation")
        trusted_fetched_at = trusted_manifest.get("fetched_at")
    _validate_candidate_source_freshness(
        manifest,
        records,
        trusted_fetched_at=trusted_fetched_at,
        trusted_manifest_bound=trusted_manifest_bound,
        deadline_check=deadline_check,
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


class StagingApplyError(RuntimeError):
    """Raised when staging identity, candidate, or read-back is unsafe."""


class _CandidatePreparationTimeout(StagingApplyError, IntegrityDeadlineExceeded):
    """Raised when pre-DB candidate preparation exceeds its outer deadline."""


class StagingSessionStateError(StagingApplyError):
    """Raised when session cleanup cannot prove the final database state."""

    def __init__(self, status: str, message: str, *, commit_state: str, lock_state: str) -> None:
        super().__init__(message)
        self.status = status
        self.commit_state = commit_state
        self.lock_state = lock_state


@dataclass(frozen=True)
class StagingTarget:
    host: str = "127.0.0.1"
    port: int = 3306
    database: str = "mks123_stage"
    socket: str | None = None
    mariadb_bin: str = "mariadb"
    timeout_seconds: int = 900


@dataclass(frozen=True)
class _CandidatePreparationDeadline:
    expires_at: float

    @classmethod
    def from_target(cls, target: StagingTarget) -> Self:
        return cls(expires_at=time.monotonic() + target.timeout_seconds)

    def check(self) -> None:
        if time.monotonic() >= self.expires_at:
            raise _CandidatePreparationTimeout(
                "candidate preparation exceeded staging timeout before database session"
            )


def validate_staging_target(target: StagingTarget) -> None:
    if target.host not in {"127.0.0.1", "::1"}:
        raise StagingApplyError("staging target must be loopback")
    if not (1 <= target.port <= 65535):
        raise StagingApplyError("staging port is invalid")
    if not re.fullmatch(r"mks123_stage(?:_[A-Za-z0-9]+)*", target.database):
        raise StagingApplyError("staging database name is not allowed")
    if "prod" in target.database.casefold():
        raise StagingApplyError("production-like database name is not allowed")
    if target.socket is not None:
        socket_path = Path(target.socket)
        if not socket_path.is_absolute() or "mysqld" not in socket_path.name.casefold():
            raise StagingApplyError("staging socket path is not an approved local mysqld socket")
    if target.timeout_seconds < 1 or target.timeout_seconds > 3600:
        raise StagingApplyError("staging timeout is invalid")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _candidate_attribute_scope(
    records: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> frozenset[str]:
    """Return the selected SKU scope, including explicit excluded records."""
    record_scope: set[str] = set()
    for record in records:
        sku = record.get("target_sku")
        if not isinstance(sku, str) or not sku.strip() or sku in record_scope:
            raise StagingApplyError("candidate record SKU scope is invalid")
        record_scope.add(sku)
    exception_scope: set[str] = set()
    for exception in exceptions:
        if not isinstance(exception, dict):
            raise StagingApplyError("candidate exception is not an object")
        sku = exception.get("source_sku")
        reason = exception.get("reason")
        if not isinstance(sku, str) or not sku.strip() or sku in exception_scope:
            raise StagingApplyError("candidate exception SKU scope is invalid")
        if not isinstance(reason, str) or not reason.strip():
            raise StagingApplyError("candidate exception reason is invalid")
        if sku in record_scope:
            raise StagingApplyError("candidate exception overlaps record SKU scope")
        exception_scope.add(sku)
    return frozenset(record_scope | exception_scope)


def _validate_attribute_mapping_binding(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    candidate_root: Path,
    *,
    expected_database: str | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    attribute_rows_present = any(
        isinstance(record.get("attribute_rows"), list) and bool(record.get("attribute_rows"))
        for record in records
    )
    metadata = manifest.get("attribute_mapping")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise StagingApplyError("candidate inputs are missing")
    has_mapping_input = "attribute_mapping" in inputs
    if attribute_rows_present and metadata is None:
        raise StagingApplyError("attribute-bearing candidate is missing mapping metadata")
    if (metadata is None) != (not has_mapping_input):
        raise StagingApplyError("attribute mapping metadata and input must be present together")
    if metadata is None:
        return
    if not isinstance(metadata, dict):
        raise StagingApplyError("candidate attribute mapping metadata is invalid")
    mapping_entry = inputs.get("attribute_mapping")
    if not isinstance(mapping_entry, dict):
        raise StagingApplyError("candidate attribute mapping input is invalid")
    mapping_path = candidate_root / "ATTRIBUTE_MAPPING.json"
    expected_file = _manifest_file_entry(manifest, "ATTRIBUTE_MAPPING.json", deadline_check=deadline_check)
    if expected_file["sha256"] != metadata.get("file_sha256") or mapping_entry.get("sha256") != metadata.get("file_sha256"):
        raise StagingApplyError("candidate attribute mapping file identity is not bound")
    try:
        payload = _read_bounded_json(mapping_path, "ATTRIBUTE_MAPPING.json", deadline_check=deadline_check)
        _, derived = validate_attribute_mapping_payload(
            payload,
            expected_language_id=metadata.get("language_id"),
        )
    except (StagingApplyError, TransferError, ValueError, TypeError) as exc:
        raise StagingApplyError("candidate attribute mapping artifact is invalid") from exc
    derived_scope = sorted(derived["scope_skus"])
    declared_scope = metadata.get("scope_skus")
    if (
        derived["artifact_sha256"] != metadata.get("artifact_sha256")
        or derived["database"] != metadata.get("database")
        or derived["language_id"] != metadata.get("language_id")
        or derived_scope != declared_scope
    ):
        raise StagingApplyError("candidate attribute mapping metadata disagrees with sealed artifact")
    observed_file = _file_identity(mapping_path, deadline_check=deadline_check)
    if observed_file != {"size": expected_file["size"], "sha256": expected_file["sha256"]}:
        raise StagingApplyError("candidate attribute mapping file changed during validation")
    exceptions_path = candidate_root / "EXCEPTIONS.json"
    exceptions = _read_bounded_json(exceptions_path, "candidate exceptions", deadline_check=deadline_check)
    if not isinstance(exceptions, list):
        raise StagingApplyError("candidate exceptions must be a list")
    candidate_scope = _candidate_attribute_scope(records, exceptions)
    if candidate_scope != derived["scope_skus"]:
        raise StagingApplyError("attribute mapping scope does not match candidate record SKUs")
    if expected_database is not None and derived["database"] != expected_database:
        raise StagingApplyError("attribute mapping database does not match staging target")
    language_id = derived["language_id"]
    for record in records:
        target_payload = record.get("target_payload")
        if not isinstance(target_payload, dict) or target_payload.get("language_id") != language_id:
            raise StagingApplyError("candidate target language does not match attribute mapping")
        rows = record.get("attribute_rows", [])
        if not isinstance(rows, list):
            raise StagingApplyError("candidate attribute rows are invalid")
        seen_ids: set[int] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise StagingApplyError("candidate attribute row is not an object")
            attribute_id = row.get("attribute_id")
            if isinstance(attribute_id, bool) or not isinstance(attribute_id, int) or not (1 <= attribute_id <= 2147483647):
                raise StagingApplyError("candidate attribute row ID is invalid")
            if attribute_id in seen_ids:
                raise StagingApplyError("candidate record contains duplicate attribute IDs")
            seen_ids.add(attribute_id)


def _validate_candidate_source_freshness(
    manifest: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    trusted_fetched_at: str | None,
    trusted_manifest_bound: bool,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    provenance = manifest.get("run_manifest_provenance")
    if not isinstance(provenance, dict):
        raise StagingApplyError("candidate run-manifest provenance is incomplete")
    candidate_fetched_at = provenance.get("fetched_at")
    if not isinstance(candidate_fetched_at, str) or not candidate_fetched_at.strip():
        raise StagingApplyError("candidate source freshness timestamp is missing")
    if trusted_manifest_bound and (
        not isinstance(trusted_fetched_at, str) or not trusted_fetched_at.strip()
    ):
        raise StagingApplyError("trusted run manifest freshness timestamp is missing")
    reference = _utc_now()
    try:
        validate_source_freshness(
            candidate_fetched_at,
            label="candidate run manifest fetched_at",
            now=reference,
        )
        if trusted_manifest_bound:
            assert trusted_fetched_at is not None
            validate_source_freshness(
                trusted_fetched_at,
                label="trusted run manifest fetched_at",
                now=reference,
            )
    except TransferError as exc:
        raise StagingApplyError(str(exc)) from exc
    if trusted_manifest_bound and candidate_fetched_at != trusted_fetched_at:
        raise StagingApplyError("candidate and trusted run manifest freshness timestamps differ")
    for index, record in enumerate(records):
        if deadline_check is not None:
            deadline_check()
        payload = record.get("target_payload")
        if not isinstance(payload, dict):
            raise StagingApplyError(f"candidate record {index} target payload is invalid")
        fetched_at = payload.get("fetched_at")
        record_fetched_at = record.get("source_fetched_at")
        if (
            not isinstance(fetched_at, str)
            or not fetched_at.strip()
            or not isinstance(record_fetched_at, str)
            or not record_fetched_at.strip()
            or fetched_at != record_fetched_at
        ):
            raise StagingApplyError(f"candidate record {index} source freshness timestamps are invalid")
        try:
            validate_source_freshness(
                fetched_at,
                label=f"candidate record {index} fetched_at",
                now=reference,
            )
        except TransferError as exc:
            raise StagingApplyError(str(exc)) from exc


_MARKER_RE = re.compile(
    r"SELECT\s+'(?P<marker>NETLAB_TRANSFER_[A-Z_]+)'\s+AS\s+marker"
    r"(?:\s*,\s*(?P<value>[0-9]+)\s+AS\s+value)?",
    re.IGNORECASE,
)
_SCOPE_SCAN_RE = re.compile(
    r"(?P<literal>'(?:\\.|''|[^'])*'|\"(?:\\.|\"\"|[^\"])*\")"
    r"|(?P<comment>/\*.*?\*/|--[^\r\n]*|#[^\r\n]*)"
    r"|(?P<token>drop\s+database|drop\s+table|truncate\s+|delete\s+from|"
    r"alter\s+table|create\s+database|grant\s+|use\s+|"
    r"oc_product_to_category|oc_product_image|oc_product_attribute|compatibility|cms_)",
    re.IGNORECASE | re.DOTALL,
)


def _strip_sql_literals(
    sql: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> str:
    """Return SQL structure with quoted literals/comments replaced by spaces."""
    output: list[str] = []
    index = 0
    state = "normal"
    while index < len(sql):
        if deadline_check is not None and (index & 4095) == 0:
            deadline_check()
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if state == "normal":
            if char == "'":
                state = "single"
                output.append(" ")
            elif char == '"':
                state = "double"
                output.append(" ")
            elif char == "`":
                state = "backtick"
                output.append(char)
            elif char == "#" or (char == "-" and next_char == "-"):
                state = "line_comment"
                output.extend(" " * (2 if char == "-" else 1))
                if char == "-":
                    index += 1
            elif char == "/" and next_char == "*":
                state = "block_comment"
                output.extend("  ")
                index += 1
            else:
                output.append(char)
        elif state == "single":
            if char == "\\":
                output.append(" ")
                if index + 1 < len(sql):
                    output.append(" ")
                    index += 1
            elif char == "'":
                if next_char == "'":
                    output.extend("  ")
                    index += 1
                else:
                    output.append(" ")
                    state = "normal"
            else:
                output.append("\n" if char == "\n" else " ")
        elif state == "double":
            if char == "\\":
                output.append(" ")
                if index + 1 < len(sql):
                    output.append(" ")
                    index += 1
            elif char == '"':
                if next_char == '"':
                    output.extend("  ")
                    index += 1
                else:
                    output.append(" ")
                    state = "normal"
            else:
                output.append("\n" if char == "\n" else " ")
        elif state == "backtick":
            output.append(char)
            if char == "`":
                if next_char == "`":
                    output.append(next_char)
                    index += 1
                else:
                    state = "normal"
        elif state == "line_comment":
            output.append(char if char == "\n" else " ")
            if char == "\n":
                state = "normal"
        else:
            if char == "*" and next_char == "/":
                output.extend("  ")
                index += 1
                state = "normal"
            else:
                output.append("\n" if char == "\n" else " ")
        index += 1
    return "".join(output)


_INSERT_COLUMNS: dict[str, tuple[str, ...]] = {
    "oc_product": (
        "model",
        "sku",
        "upc",
        "ean",
        "jan",
        "isbn",
        "mpn",
        "location",
        "quantity",
        "stock_status_id",
        "image",
        "manufacturer_id",
        "shipping",
        "price",
        "cost",
        "points",
        "tax_class_id",
        "date_available",
        "weight",
        "weight_class_id",
        "length",
        "width",
        "height",
        "length_class_id",
        "subtract",
        "minimum",
        "sort_order",
        "status",
        "viewed",
        "date_added",
        "date_modified",
        "noindex",
        "oct_stickers",
        "dn_id",
        "suppler_code",
        "suppler_type",
    ),
    "oc_product_description": (
        "product_id",
        "language_id",
        "name",
        "description",
        "tag",
        "meta_title",
        "meta_description",
        "meta_keyword",
        "meta_h1",
    ),
    "oc_product_to_category": ("product_id", "category_id"),
    "oc_product_attribute": ("product_id", "attribute_id", "language_id", "text"),
    "oc_netlab_transfer_audit": (
        "run_id",
        "supplier_item_id",
        "source_sku",
        "target_product_id",
        "action",
        "source_kind",
        "verification_status",
        "manufacturer_verified",
        "source_url",
        "source_raw_hash",
        "source_fetched_at",
        "source_artifact_path",
        "source_artifact_sha256",
        "matches_artifact_sha256",
        "source_snapshot_json",
        "properties_json",
        "image_urls_json",
        "category_json",
        "after_json",
        "transferred_at",
    ),
}


def _split_sql_list(
    text: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if deadline_check is not None and (index & 4095) == 0:
            deadline_check()
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise StagingApplyError("candidate SQL expression has unbalanced parentheses")
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if depth != 0:
        raise StagingApplyError("candidate SQL expression has unbalanced parentheses")
    parts.append(text[start:].strip())
    return parts


def _validate_insert_shape(
    code: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    match = re.fullmatch(
        r"insert into `(?P<table>[a-z0-9_]+)` \((?P<columns>[^)]*)\) (?P<source>values|select) (?P<body>.*)",
        code,
    )
    if match is None or match.group("table") not in _INSERT_COLUMNS:
        raise StagingApplyError("candidate contains an unsupported INSERT shape")
    table = match.group("table")
    source = match.group("source")
    if source == "select" and table not in {
        "oc_product_description",
        "oc_product_to_category",
        "oc_product_attribute",
        "oc_netlab_transfer_audit",
    }:
        raise StagingApplyError("candidate SELECT INSERT is outside the allowlist")
    columns = tuple(re.findall(r"`([a-z0-9_]+)`", match.group("columns")))
    expected_columns = _INSERT_COLUMNS[table]
    if columns != expected_columns:
        raise StagingApplyError("candidate INSERT columns are outside the allowlist")
    if table == "oc_product_to_category":
        if source != "select":
            raise StagingApplyError("category relation INSERT must use the guarded SELECT shape")
        values_match = re.fullmatch(
            r"(?P<values>@netlab_transfer_product_id|\d+), (?P<category_id>\d+) "
            r"where @netlab_transfer_product_rows=1 and @netlab_transfer_description_rows=1 "
            r"on duplicate key update `category_id`=values\(`category_id`\)",
            match.group("body"),
        )
    elif table == "oc_product_description" and source == "select":
        values_match = re.fullmatch(
            r"(?P<values>.*?) where @netlab_transfer_product_rows=1",
            match.group("body"),
        )
    elif table == "oc_product_attribute" and source == "select":
        values_match = re.fullmatch(
            r"(?P<values>.*?) where @netlab_transfer_product_rows=1 "
            r"and @netlab_transfer_description_rows=1 "
            r"on duplicate key update `text`=values\(`text`\)",
            match.group("body"),
        )
    elif table == "oc_netlab_transfer_audit" and source == "select":
        values_match = re.fullmatch(
            r"(?P<values>.*?) where @netlab_transfer_product_rows=1 "
            r"and @netlab_transfer_description_rows=1",
            match.group("body"),
        )
    else:
        if source != "values":
            raise StagingApplyError("candidate SELECT INSERT table is invalid")
        values_match = re.fullmatch(r"\((?P<values>.*)\)", match.group("body"))
    if values_match is None:
        raise StagingApplyError("candidate INSERT has an unsupported duplicate-key shape")
    if source == "select" and table == "oc_product_to_category":
        values_text = f"{values_match.group('values')}, {values_match.group('category_id')}"
    else:
        values_text = values_match.group("values")
    values = _split_sql_list(
        _strip_sql_literals(values_text, deadline_check=deadline_check),
        deadline_check=deadline_check,
    )
    if len(values) != len(expected_columns):
        raise StagingApplyError("candidate INSERT value multiplicity does not match columns")
    value_pattern = re.compile(
        r"(?:convert\(0x[0-9a-f]+ using utf8mb4\)|null|"
        r"@netlab_transfer_product_id|-?(?:\d+(?:\.\d*)?|\.\d+)|"
        r"if\(@netlab_transfer_product_rows=1 and @netlab_transfer_description_rows=1, "
        r"(?:@netlab_transfer_product_id|\d+), null\))"
    )
    if any(
        value.strip() and value_pattern.fullmatch(value.strip()) is None
        for value in values
    ):
        raise StagingApplyError("candidate INSERT contains an unsupported value expression")


_AUDIT_DDL_PARTS = (
    "`transfer_id` BIGINT NOT NULL AUTO_INCREMENT",
    "`run_id` VARCHAR(128) NOT NULL",
    "`supplier_item_id` VARCHAR(64) NOT NULL",
    "`source_sku` VARCHAR(64) NOT NULL",
    "`target_product_id` INT NOT NULL",
    "`action` VARCHAR(16) NOT NULL",
    "`source_kind` VARCHAR(32) NOT NULL",
    "`verification_status` VARCHAR(64) NOT NULL",
    "`manufacturer_verified` TINYINT(1) NOT NULL",
    "`source_url` TEXT NOT NULL",
    "`source_raw_hash` CHAR(64) NOT NULL",
    "`source_fetched_at` VARCHAR(64) NOT NULL",
    "`source_artifact_path` TEXT NOT NULL",
    "`source_artifact_sha256` CHAR(64) NOT NULL",
    "`matches_artifact_sha256` CHAR(64) NOT NULL",
    "`source_snapshot_json` LONGTEXT NOT NULL",
    "`properties_json` LONGTEXT NOT NULL",
    "`image_urls_json` LONGTEXT NOT NULL",
    "`category_json` LONGTEXT NOT NULL",
    "`after_json` LONGTEXT NOT NULL",
    "`transferred_at` DATETIME NOT NULL",
    "PRIMARY KEY (`transfer_id`)",
    "UNIQUE KEY `uq_netlab_transfer_run_sku` (`run_id`, `source_sku`)",
    "KEY `idx_netlab_transfer_target` (`target_product_id`)",
)


def _validate_create_shape(
    code: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    match = re.fullmatch(
        r"create table `oc_netlab_transfer_audit` \((?P<body>.*)\) engine=innodb "
        r"default charset=utf8mb4 collate=utf8mb4_general_ci",
        code,
    )
    if match is None:
        raise StagingApplyError("candidate contains an unsupported audit DDL shape")
    if deadline_check is not None:
        deadline_check()
    actual = tuple(
        re.sub(r"\s+", " ", part).strip().casefold()
        for part in _split_sql_list(match.group("body"), deadline_check=deadline_check)
    )
    expected = tuple(re.sub(r"\s+", " ", part).strip().casefold() for part in _AUDIT_DDL_PARTS)
    if actual != expected:
        raise StagingApplyError("candidate audit DDL does not match the allowlist")


def _validate_marker_statement(
    original: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str, int | None]:
    if deadline_check is not None:
        deadline_check()
    normalized = re.sub(r"\s+", " ", original.strip())
    patterns = {
        "NETLAB_TRANSFER_APPLY_DONE": (
            r"SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT\(\*\) AS audit_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT\(0x[0-9a-f]+ USING utf8mb4\)",
            None,
        ),
        "NETLAB_TRANSFER_RELATIONS_CREATED": (
            r"SELECT 'NETLAB_TRANSFER_RELATIONS_CREATED' AS marker, (?P<value>\d+) AS value",
            "value",
        ),
        "NETLAB_TRANSFER_MEDIA_ASSIGNMENTS": (
            r"SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value",
            0,
        ),
        "NETLAB_TRANSFER_PUBLICATION_ENABLED": (
            r"SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value",
            0,
        ),
    }
    for marker, (pattern, value_spec) in patterns.items():
        if deadline_check is not None:
            deadline_check()
        match = re.fullmatch(pattern, normalized, re.IGNORECASE)
        if match is None:
            continue
        if value_spec == "value":
            return marker, int(match.group("value"))
        return marker, value_spec
    raise StagingApplyError("candidate marker SELECT has an unsupported shape")


def _validate_dml_shape(
    code: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    forbidden = re.compile(r"\b(?:select|union|from|outfile|load_file|sleep|benchmark|call)\b")
    description_guard = re.compile(
        r"where `product_id`=(?P<product_id>\d+) and `language_id`=\d+ "
        r"and @netlab_transfer_product_rows=1 "
        r"and exists \(select 1 from `oc_product` as p where p.`product_id`=(?P=product_id) "
        r"and p.`sku`=convert\(0x[0-9a-f]+ using utf8mb4\)\)",
        re.IGNORECASE,
    )
    if forbidden.search(code) and not (
        code.startswith("update `oc_product_description` set ") and description_guard.search(code)
    ):
        raise StagingApplyError("candidate contains an unsupported SQL expression")
    if code.startswith("update `oc_product` set "):
        match = re.fullmatch(
            r"update `oc_product` set (?P<assignments>.*?) where `product_id`=\d+ "
            r"and `sku`=convert\(0x[0-9a-f]+ using utf8mb4\)",
            code,
        )
        allowed = {"model", "quantity", "price", "weight", "length", "width", "height", "date_modified", "mpn", "ean"}
    elif code.startswith("update `oc_product_description` set "):
        match = re.fullmatch(
            r"update `oc_product_description` set (?P<assignments>.*?) "
            r"where `product_id`=(?P<product_id>\d+) and `language_id`=\d+ "
            r"and @netlab_transfer_product_rows=1 "
            r"and exists \(select 1 from `oc_product` as p where p.`product_id`=(?P=product_id) "
            r"and p.`sku`=convert\(0x[0-9a-f]+ using utf8mb4\)\)",
            code,
        )
        allowed = {"name", "description"}
    else:
        return
    if match is None:
        raise StagingApplyError("candidate contains an unsupported UPDATE shape")
    columns = re.findall(r"`([a-z0-9_]+)`\s*=", match.group("assignments"))
    if not columns or len(columns) != len(set(columns)) or not set(columns).issubset(allowed):
        raise StagingApplyError("candidate UPDATE columns are outside the allowlist")
    rhs_pattern = r"(?:convert\(0x[0-9a-f]+ using utf8mb4\)|-?(?:\d+(?:\.\d*)?|\.\d+))"
    empty_rhs_allowed = {"model", "mpn", "ean", "name", "description"}
    for assignment in _split_sql_list(match.group("assignments"), deadline_check=deadline_check):
        assignment_match = re.fullmatch(r"`([a-z0-9_]+)`\s*=\s*(.*)", assignment)
        if assignment_match is None or assignment_match.group(1) not in allowed:
            raise StagingApplyError("candidate UPDATE contains an unsupported value expression")
        field = assignment_match.group(1)
        rhs = assignment_match.group(2)
        if not rhs and field not in empty_rhs_allowed:
            raise StagingApplyError("candidate UPDATE contains an unsupported empty value")
        if rhs and re.fullmatch(rhs_pattern, rhs) is None:
            raise StagingApplyError("candidate UPDATE contains an unsupported value expression")


def _decode_sql_hex_text(expression: str) -> str:
    match = re.fullmatch(r"convert\(0x([0-9a-f]+) using utf8mb4\)", expression.strip().casefold())
    if match is None or len(match.group(1)) % 2:
        raise StagingApplyError("candidate operation contains an invalid text literal")
    try:
        return bytes.fromhex(match.group(1)).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise StagingApplyError("candidate operation contains an invalid UTF-8 literal") from exc


def _parse_sql_int(token: str, label: str) -> int:
    if len(token) > 18:
        raise StagingApplyError(f"candidate {label} identity exceeds numeric bound")
    try:
        return int(token)
    except ValueError as exc:
        raise StagingApplyError(f"candidate {label} identity is invalid") from exc


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_number(value: Any) -> str:
    try:
        parsed = Decimal(str(value))
    except (DecimalException, ValueError, TypeError) as exc:
        raise StagingApplyError("candidate numeric value is invalid") from exc
    if not parsed.is_finite():
        raise StagingApplyError("candidate numeric value is not finite")
    _, digits, exponent = parsed.as_tuple()
    if (
        len(digits) > _MAX_CANONICAL_NUMBER_DIGITS
        or abs(exponent) > _MAX_CANONICAL_NUMBER_EXPONENT
        or (
            exponent >= 0
            and len(digits) + exponent > _MAX_CANONICAL_NUMBER_DIGITS
        )
        or (
            exponent < 0
            and max(len(digits), -exponent) > _MAX_CANONICAL_NUMBER_DIGITS
        )
    ):
        raise StagingApplyError("candidate numeric value exceeds canonicalization bounds")
    text = format(parsed, "f")
    if "." in text:
        integer, fraction = text.split(".", 1)
        fraction = fraction.rstrip("0")
        text = integer if not fraction else f"{integer}.{fraction}"
    return text if text and text != "-0" else "0"


def _text_value(value: Any) -> tuple[str, str]:
    if value is None:
        raise StagingApplyError("candidate text value is missing")
    return ("text", str(value))


def _number_value(value: Any) -> tuple[str, str]:
    return ("number", _canonical_number(value))


def _parse_sql_value(
    expression: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str, str | None]:
    if deadline_check is not None:
        deadline_check()
    token = expression.strip().casefold()
    if token.startswith("if("):
        match = re.fullmatch(
            r"if\(@netlab_transfer_product_rows=1 and @netlab_transfer_description_rows=1, "
            r"(?P<value>@netlab_transfer_product_id|\d+), null\)",
            token,
        )
        if match is None:
            raise StagingApplyError("candidate contains an unsupported guard expression")
        return ("guarded", _parse_sql_value(match.group("value"), deadline_check=deadline_check))
    if token == "null":
        return ("null", None)
    if token.startswith("convert("):
        return ("text", _decode_sql_hex_text(token))
    if token.startswith("@netlab_"):
        if token != "@netlab_transfer_product_id":
            raise StagingApplyError("candidate contains an unsupported SQL variable")
        return ("variable", token)
    if token in {"", "''"}:
        return ("text", "")
    if re.fullmatch(r"-?(?:\d+(?:\.\d*)?|\.\d+)", token):
        return ("number", _canonical_number(token))
    raise StagingApplyError("candidate contains an unsupported SQL value")


def _assignment_signature(
    assignments: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[tuple[str, tuple[str, str | None]], ...]:
    parsed: list[tuple[str, tuple[str, str | None]]] = []
    for assignment in _split_sql_list(assignments, deadline_check=deadline_check):
        if deadline_check is not None:
            deadline_check()
        match = re.fullmatch(r"`([a-z0-9_]+)`\s*=\s*(.*)", assignment.strip(), re.IGNORECASE)
        if match is None:
            raise StagingApplyError("candidate UPDATE assignment is invalid")
        parsed.append((match.group(1).casefold(), _parse_sql_value(match.group(2))))
    if not parsed or len({field for field, _ in parsed}) != len(parsed):
        raise StagingApplyError("candidate UPDATE assignments are duplicated")
    return tuple(sorted(parsed))


def _operation_signature(
    code: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[Any, ...] | None:
    if deadline_check is not None:
        deadline_check()
    if code.startswith("update `oc_product` set "):
        match = re.fullmatch(
            r"update `oc_product` set (?P<assignments>.*?) where `product_id`=(?P<product_id>\d+) "
            r"and `sku`=(?P<sku>convert\(0x[0-9a-f]+ using utf8mb4\))",
            code,
        )
        if match is None:
            raise StagingApplyError("candidate product UPDATE identity is invalid")
        return (
            "update_product",
            _parse_sql_int(match.group("product_id"), "product"),
            _parse_sql_value(match.group("sku"), deadline_check=deadline_check),
            _assignment_signature(match.group("assignments"), deadline_check=deadline_check),
        )
    if code.startswith("update `oc_product_description` set "):
        match = re.fullmatch(
            r"update `oc_product_description` set (?P<assignments>.*?) "
            r"where `product_id`=(?P<product_id>\d+) and `language_id`=(?P<language_id>\d+) "
            r"and @netlab_transfer_product_rows=1 "
            r"and exists \(select 1 from `oc_product` as p where p.`product_id`=(?P=product_id) "
            r"and p.`sku`=(?P<sku>convert\(0x[0-9a-f]+ using utf8mb4\))\)",
            code,
        )
        if match is None:
            raise StagingApplyError("candidate description UPDATE identity is invalid")
        return (
            "update_description",
            _parse_sql_int(match.group("product_id"), "description product"),
            _parse_sql_int(match.group("language_id"), "language"),
            _parse_sql_value(match.group("sku"), deadline_check=deadline_check),
            _assignment_signature(match.group("assignments"), deadline_check=deadline_check),
        )
    if code.startswith("insert into "):
        match = re.fullmatch(
            r"insert into `(?P<table>[a-z0-9_]+)` \((?P<columns>[^)]*)\) "
            r"(?P<source>values|select) (?P<body>.*)",
            code,
        )
        if match is None:
            raise StagingApplyError("candidate INSERT identity is invalid")
        table = match.group("table")
        source = match.group("source")
        columns = tuple(re.findall(r"`([a-z0-9_]+)`", match.group("columns")))
        if columns != _INSERT_COLUMNS.get(table):
            raise StagingApplyError("candidate INSERT columns are invalid")
        if table == "oc_product_to_category":
            if source != "select":
                raise StagingApplyError("candidate category relation INSERT identity must be guarded")
            values_match = re.fullmatch(
                r"(?P<product_id>@netlab_transfer_product_id|\d+), (?P<category_id>\d+) "
                r"where @netlab_transfer_product_rows=1 and @netlab_transfer_description_rows=1 "
                r"on duplicate key update `category_id`=values\(`category_id`\)",
                match.group("body"),
            )
        elif table == "oc_product_description" and source == "select":
            values_match = re.fullmatch(
                r"(?P<values>.*?) where @netlab_transfer_product_rows=1",
                match.group("body"),
            )
        elif table == "oc_product_attribute" and source == "select":
            values_match = re.fullmatch(
                r"(?P<values>.*?) where @netlab_transfer_product_rows=1 "
                r"and @netlab_transfer_description_rows=1 "
                r"on duplicate key update `text`=values\(`text`\)",
                match.group("body"),
            )
        elif table == "oc_netlab_transfer_audit" and source == "select":
            values_match = re.fullmatch(
                r"(?P<values>.*?) where @netlab_transfer_product_rows=1 "
                r"and @netlab_transfer_description_rows=1",
                match.group("body"),
            )
        else:
            if source != "values":
                raise StagingApplyError("candidate SELECT INSERT table is invalid")
            values_match = re.fullmatch(r"\((?P<values>.*)\)", match.group("body"))
        if values_match is None:
            raise StagingApplyError("candidate INSERT duplicate-key identity is invalid")
        if source == "select" and table == "oc_product_to_category":
            values_text = f"{values_match.group('product_id')}, {values_match.group('category_id')}"
        else:
            values_text = values_match.group("values")
        values = tuple(
            _parse_sql_value(item, deadline_check=deadline_check)
            for item in _split_sql_list(values_text, deadline_check=deadline_check)
        )
        if len(values) != len(columns):
            raise StagingApplyError("candidate INSERT value multiplicity is invalid")
        if table == "oc_product":
            return ("create_product", tuple(zip(columns, values)))
        if table == "oc_product_description":
            if values[0] == ("variable", "@netlab_transfer_product_id"):
                return ("create_description", tuple(zip(columns, values)))
            return ("insert_description", tuple(zip(columns, values)))
        if table == "oc_product_to_category":
            return ("category_relation", values[0], values[1])
        if table == "oc_product_attribute":
            return ("attribute", values[0], values[1], values[2], values[3])
        if table == "oc_netlab_transfer_audit":
            return ("audit", tuple(zip(columns, values)))
    return None


def _expected_product_update(record: dict[str, Any]) -> tuple[Any, ...]:
    payload = record.get("target_payload")
    if not isinstance(payload, dict):
        raise StagingApplyError("candidate record target payload is invalid")
    transferred_at = record.get("transferred_at")
    if not isinstance(transferred_at, str):
        raise StagingApplyError("candidate record transferred_at is missing")
    assignments: dict[str, tuple[str, str | None]] = {
        "model": _text_value(payload.get("model")),
        "quantity": _number_value(payload.get("quantity")),
        "price": _number_value(payload.get("price")),
        "weight": _number_value(payload.get("weight")),
        "length": _number_value(payload.get("length")),
        "width": _number_value(payload.get("width")),
        "height": _number_value(payload.get("height")),
        "date_modified": _text_value(transferred_at),
    }
    for field in ("mpn", "ean"):
        if payload.get(field):
            assignments[field] = _text_value(payload[field])
    return tuple(sorted(assignments.items()))


def _record_language_id(record: dict[str, Any]) -> int:
    payload = record.get("target_payload")
    if not isinstance(payload, dict):
        raise StagingApplyError("candidate record target payload is invalid")
    value = payload.get("language_id", 1)
    if isinstance(value, bool) or not isinstance(value, int) or not (1 <= value <= 2147483647):
        raise StagingApplyError("candidate language ID is invalid")
    return value


def _expected_description_update(record: dict[str, Any]) -> tuple[Any, ...]:
    payload = record["target_payload"]
    preserve_fields = set(payload.get("preserve_fields", []))
    assignments = {"name": _text_value(payload.get("name"))}
    if "description" not in preserve_fields:
        assignments["description"] = _text_value(payload.get("description"))
    return tuple(sorted(assignments.items()))


def _expected_product_create(record: dict[str, Any]) -> tuple[Any, ...]:
    payload = record.get("target_payload")
    if not isinstance(payload, dict):
        raise StagingApplyError("candidate record target payload is invalid")
    transferred_at = record.get("transferred_at")
    if not isinstance(transferred_at, str):
        raise StagingApplyError("candidate record transferred_at is missing")
    values: dict[str, tuple[str, str | None]] = {
        "model": _text_value(payload.get("model")),
        "sku": _text_value(record.get("target_sku")),
        "upc": _text_value(""),
        "ean": _text_value(payload.get("ean")),
        "jan": _text_value(""),
        "isbn": _text_value(""),
        "mpn": _text_value(payload.get("mpn")),
        "location": _text_value(""),
        "quantity": _number_value(payload.get("quantity")),
        "stock_status_id": _number_value(5),
        "image": ("null", None),
        "manufacturer_id": _number_value(0),
        "shipping": _number_value(1),
        "price": _number_value(payload.get("price")),
        "cost": _number_value(0),
        "points": _number_value(0),
        "tax_class_id": _number_value(0),
        "date_available": _text_value(transferred_at[:10]),
        "weight": _number_value(payload.get("weight")),
        "weight_class_id": _number_value(1),
        "length": _number_value(payload.get("length")),
        "width": _number_value(payload.get("width")),
        "height": _number_value(payload.get("height")),
        "length_class_id": _number_value(1),
        "subtract": _number_value(0),
        "minimum": _number_value(1),
        "sort_order": _number_value(0),
        "status": _number_value(0),
        "viewed": _number_value(0),
        "date_added": _text_value(transferred_at),
        "date_modified": _text_value(transferred_at),
        "noindex": _number_value(1),
        "oct_stickers": _text_value(""),
        "dn_id": _number_value(0),
        "suppler_code": _number_value(0),
        "suppler_type": _number_value(0),
    }
    return tuple((field, values[field]) for field in _INSERT_COLUMNS["oc_product"])


def _expected_description_create(record: dict[str, Any]) -> tuple[Any, ...]:
    payload = record["target_payload"]
    return (
        ("product_id", ("variable", "@netlab_transfer_product_id")),
        ("language_id", _number_value(_record_language_id(record))),
        ("name", _text_value(payload.get("name"))),
        ("description", _text_value(payload.get("description"))),
        ("tag", _text_value("")),
        ("meta_title", _text_value("")),
        ("meta_description", _text_value("")),
        ("meta_keyword", _text_value("")),
        ("meta_h1", ("null", None)),
    )


def _expected_category_relation(record: dict[str, Any]) -> tuple[Any, ...]:
    payload = record.get("target_payload")
    if not isinstance(payload, dict):
        raise StagingApplyError("candidate record target payload is invalid")
    category_id = payload.get("target_category_id")
    if isinstance(category_id, bool) or not isinstance(category_id, int) or not (1 <= category_id <= 2147483647):
        raise StagingApplyError("candidate target category ID is invalid")
    if record.get("action") == "create":
        product_id: tuple[str, str | None] = ("variable", "@netlab_transfer_product_id")
    else:
        raw_product_id = record.get("target_product_id")
        if isinstance(raw_product_id, bool) or not isinstance(raw_product_id, int) or not (1 <= raw_product_id <= 2147483647):
            raise StagingApplyError("candidate category relation product ID is invalid")
        product_id = _number_value(raw_product_id)
    return ("category_relation", product_id, _number_value(category_id))


def _expected_attribute_operations(record: dict[str, Any]) -> list[tuple[Any, ...]]:
    rows = record.get("attribute_rows", [])
    if not isinstance(rows, list):
        raise StagingApplyError("candidate attribute_rows must be a list")
    language_id = _record_language_id(record)
    operations: list[tuple[Any, ...]] = []
    action = record.get("action")
    product_id: tuple[str, str | None]
    if action == "create":
        product_id = ("guarded", ("variable", "@netlab_transfer_product_id"))
    else:
        raw_product_id = record.get("target_product_id")
        if isinstance(raw_product_id, bool) or not isinstance(raw_product_id, int) or not (1 <= raw_product_id <= 2147483647):
            raise StagingApplyError("candidate attribute product ID is invalid")
        product_id = ("guarded", _number_value(raw_product_id))
    seen_attribute_ids: set[int] = set()
    for row in rows:
        attribute_id = row.get("attribute_id") if isinstance(row, dict) else None
        if isinstance(attribute_id, bool) or not isinstance(attribute_id, int) or not (1 <= attribute_id <= 2147483647):
            raise StagingApplyError("candidate attribute row ID is invalid")
        if attribute_id in seen_attribute_ids:
            raise StagingApplyError("candidate record contains duplicate attribute IDs")
        seen_attribute_ids.add(attribute_id)
        operations.append(("attribute", product_id, _number_value(attribute_id), _number_value(language_id), _text_value(row.get("text"))))
    return operations


def _audit_after_json(record: dict[str, Any], source_snapshot: Any) -> str:
    return _canonical_json(
        {
            "target": record["target_payload"],
            "source_kind": "netlab",
            "verification_status": record["verification_status"],
            "manufacturer_verified": False,
            "source_snapshot": source_snapshot,
            "attributes": {
                "mapped": record.get("attribute_rows", []),
                "unmapped_property_names": record.get("unmapped_attribute_names", []),
            },
        }
    )


def _expected_audit(record: dict[str, Any]) -> tuple[Any, ...]:
    action = record.get("action")
    if action not in {"update", "create"}:
        raise StagingApplyError("candidate record action is not allowlisted")
    target_id: tuple[str, str | None]
    if action == "create":
        target_id = ("guarded", ("variable", "@netlab_transfer_product_id"))
    else:
        product_id = record.get("target_product_id")
        if isinstance(product_id, bool) or not isinstance(product_id, int) or not (1 <= product_id <= 2147483647):
            raise StagingApplyError("candidate audit target product ID is invalid")
        target_id = ("guarded", _number_value(product_id))
    try:
        source_snapshot = json.loads(record["source_snapshot_json"], object_pairs_hook=_reject_duplicate_json_keys)
    except (KeyError, TypeError, ValueError) as exc:
        raise StagingApplyError("candidate source snapshot JSON is invalid") from exc
    after_json = _audit_after_json(record, source_snapshot)
    values = {
        "run_id": _text_value(record["run_id"]),
        "supplier_item_id": _text_value(record["supplier_item_id"]),
        "source_sku": _text_value(record["source_sku"]),
        "target_product_id": target_id,
        "action": _text_value(action),
        "source_kind": _text_value("netlab"),
        "verification_status": _text_value(record["verification_status"]),
        "manufacturer_verified": _number_value(0),
        "source_url": _text_value(record["source_url"]),
        "source_raw_hash": _text_value(record["source_raw_hash"]),
        "source_fetched_at": _text_value(record["source_fetched_at"]),
        "source_artifact_path": _text_value(record["source_artifact_path"]),
        "source_artifact_sha256": _text_value(record["source_artifact_sha256"]),
        "matches_artifact_sha256": _text_value(record["matches_artifact_sha256"]),
        "source_snapshot_json": _text_value(record["source_snapshot_json"]),
        "properties_json": _text_value(record["properties_json"]),
        "image_urls_json": _text_value(record["image_urls_json"]),
        "category_json": _text_value(record["category_json"]),
        "after_json": _text_value(after_json),
        "transferred_at": _text_value(record["transferred_at"]),
    }
    return tuple((field, values[field]) for field in _INSERT_COLUMNS["oc_netlab_transfer_audit"])


def _expected_operation_signatures(
    records: list[dict[str, Any]],
    *,
    deadline_check: Callable[[], None] | None = None,
) -> list[tuple[Any, ...]]:
    expected: list[tuple[Any, ...]] = []
    for record in records:
        if deadline_check is not None:
            deadline_check()
        action = record.get("action")
        sku = record.get("target_sku")
        source_sku = record.get("source_sku", sku)
        if not isinstance(sku, str) or not isinstance(source_sku, str):
            raise StagingApplyError("candidate record operation identity is invalid")
        if action == "update":
            product_id = record.get("target_product_id")
            if isinstance(product_id, bool) or not isinstance(product_id, int) or not (1 <= product_id <= 2147483647):
                raise StagingApplyError("candidate update record has no target product ID")
            expected.append(
                ("update_product", product_id, _text_value(sku), _expected_product_update(record))
            )
            expected.append(("set_product_rows", product_id, _text_value(sku)))
            expected.append(
                (
                    "update_description",
                    product_id,
                    _record_language_id(record),
                    _text_value(sku),
                    _expected_description_update(record),
                )
            )
            expected.append(("set_description_rows", product_id, _record_language_id(record)))
        elif action == "create":
            expected.append(("create_product", _expected_product_create(record)))
            expected.append(("set_product_rows",))
            expected.append(("set_product_id",))
            expected.append(("create_description", _expected_description_create(record)))
            expected.append(("set_description_rows",))
        else:
            raise StagingApplyError("candidate record action is not allowlisted")
        expected.extend(_expected_attribute_operations(record))
        payload = record.get("target_payload")
        if isinstance(payload, dict) and "target_category_id" in payload:
            expected.append(_expected_category_relation(record))
        expected.append(("audit", _expected_audit(record)))
    return expected


_REQUIRED_MARKERS = {
    "NETLAB_TRANSFER_APPLY_DONE",
    "NETLAB_TRANSFER_RELATIONS_CREATED",
    "NETLAB_TRANSFER_MEDIA_ASSIGNMENTS",
    "NETLAB_TRANSFER_PUBLICATION_ENABLED",
}


class _SqlCandidateScanner:
    """Stream SQL lexical structure and enforce the candidate statement allowlist."""

    _CAPTURE_LIMIT = 16 * 1024 * 1024

    def __init__(self, *, deadline_check: Callable[[], None] | None = None) -> None:
        self._deadline_check = deadline_check
        self._pending = ""
        self._state = "normal"
        self._capture: list[str] | None = []
        self._capture_length = 0
        self._head: list[str] = []
        self._has_code = False
        self._marker_values: dict[str, list[int | None]] = {}
        self.operations: list[tuple[Any, ...]] = []
        self.set_names = False
        self.audit_table = False

    @property
    def marker_values(self) -> dict[str, list[int | None]]:
        return self._marker_values

    def feed(self, text: str, *, final: bool = False) -> None:
        if self._deadline_check is not None:
            self._deadline_check()
        data = self._pending + text
        self._pending = ""
        if not final and data:
            self._pending = data[-1]
            data = data[:-1]
        self._process(data)

    def finish(self) -> None:
        if self._deadline_check is not None:
            self._deadline_check()
        self.feed("", final=True)
        if self._state in {"single", "double", "backtick", "block_comment"}:
            raise StagingApplyError("candidate contains an unterminated SQL literal/comment")
        if self._state == "line_comment":
            self._state = "normal"
        self._finish_statement()

    def _append(self, char: str) -> None:
        if len(self._head) < 1024:
            self._head.append(char)
        if self._capture is not None:
            self._capture_length += len(char)
            if self._capture_length > self._CAPTURE_LIMIT:
                raise StagingApplyError("candidate SQL statement exceeds validation limit")
            self._capture.append(char)

    def _process(self, data: str) -> None:
        index = 0
        while index < len(data):
            if self._deadline_check is not None and (index & 4095) == 0:
                self._deadline_check()
            char = data[index]
            next_char = data[index + 1] if index + 1 < len(data) else ""
            if self._state == "normal":
                if char == "#":
                    self._state = "line_comment"
                    index += 1
                    continue
                if char == "-" and next_char == "-":
                    self._state = "line_comment"
                    index += 2
                    continue
                if char == "/" and next_char == "*":
                    if index + 2 < len(data) and data[index + 2] == "!":
                        raise StagingApplyError("candidate contains executable SQL comment")
                    self._state = "block_comment"
                    index += 2
                    continue
                if char in {"'", '"', "`"}:
                    self._state = {"'": "single", '"': "double", "`": "backtick"}[char]
                    self._has_code = True
                    self._append(char)
                    index += 1
                    continue
                if char == ";":
                    self._finish_statement()
                    index += 1
                    continue
                if not char.isspace():
                    self._has_code = True
                self._append(char)
                index += 1
                continue
            if self._state == "line_comment":
                if char == "\n":
                    self._state = "normal"
                index += 1
                continue
            if self._state == "block_comment":
                if char == "*" and next_char == "/":
                    self._state = "normal"
                    index += 2
                else:
                    index += 1
                continue
            quote = {"single": "'", "double": '"', "backtick": "`"}[self._state]
            self._append(char)
            if char == "\\" and self._state != "backtick" and index + 1 < len(data):
                self._append(data[index + 1])
                index += 2
                continue
            if char == quote and next_char == quote:
                self._append(next_char)
                index += 2
                continue
            if char == quote:
                self._state = "normal"
            index += 1

    def _finish_statement(self) -> None:
        if not self._has_code:
            self._capture = []
            self._capture_length = 0
            self._head = []
            return
        raw = "".join(self._capture) if self._capture is not None else "".join(self._head)
        if self._deadline_check is not None:
            self._deadline_check()
        code = re.sub(
            r"\s+",
            " ",
            _strip_sql_literals(raw, deadline_check=self._deadline_check).strip().casefold(),
        )
        if self._deadline_check is not None:
            self._deadline_check()
        original = raw.strip()
        if code.startswith("update "):
            if self._deadline_check is not None:
                self._deadline_check()
            _validate_dml_shape(code, deadline_check=self._deadline_check)
            if self._deadline_check is not None:
                self._deadline_check()
            operation = _operation_signature(
                re.sub(r"\s+", " ", original.casefold()),
                deadline_check=self._deadline_check,
            )
            if self._deadline_check is not None:
                self._deadline_check()
            if operation is None:
                raise StagingApplyError("candidate UPDATE operation identity is missing")
            self.operations.append(operation)
        elif code.startswith("insert "):
            if not code.startswith((
                "insert into `oc_product` ",
                "insert into `oc_product_description` ",
                "insert into `oc_product_to_category` ",
                "insert into `oc_product_attribute` ",
                "insert into `oc_netlab_transfer_audit` ",
            )):
                raise StagingApplyError("candidate contains out-of-scope SQL statement")
            guarded_select = (
                code.startswith(
                    (
                        "insert into `oc_product_description` ",
                        "insert into `oc_product_to_category` ",
                        "insert into `oc_product_attribute` ",
                        "insert into `oc_netlab_transfer_audit` ",
                    )
                )
                and re.search(r"\) select ", code) is not None
            )
            if re.search(
                r"\b(?:union|from|outfile|load_file|sleep|benchmark|call)\b", code
            ) or ("select" in code and not guarded_select) or (
                "on duplicate" in code
                and not code.startswith((
                    "insert into `oc_product_to_category` ",
                    "insert into `oc_product_attribute` ",
                ))
            ):
                raise StagingApplyError("candidate contains an unsupported INSERT expression")
            _validate_insert_shape(code, deadline_check=self._deadline_check)
            if self._deadline_check is not None:
                self._deadline_check()
            operation = _operation_signature(
                re.sub(r"\s+", " ", original.casefold()),
                deadline_check=self._deadline_check,
            )
            if self._deadline_check is not None:
                self._deadline_check()
            if operation is None:
                raise StagingApplyError("candidate INSERT operation identity is missing")
            self.operations.append(operation)
        elif code.startswith("create ") and re.search(
            r"\b(?:select|union|from|outfile|load_file|sleep|benchmark|call)\b", code
        ):
            raise StagingApplyError("candidate contains an unsupported CREATE expression")
        if re.fullmatch(
            r"set session sql_mode\s*=\s*'strict_all_tables,no_zero_date,no_zero_in_date'",
            original,
            re.IGNORECASE,
        ):
            pass
        elif code == "set names utf8mb4":
            self.set_names = True
        elif product_match := re.fullmatch(
            r"set @netlab_transfer_product_rows = \(select count\(\*\) from `oc_product` "
            r"where `product_id`=(?P<product_id>\d+) and `sku`=(?P<sku>convert\(0x[0-9a-f]+ using utf8mb4\))\)",
            code,
        ):
            self.operations.append(
                (
                    "set_product_rows",
                    _parse_sql_int(product_match.group("product_id"), "product"),
                    _parse_sql_value(product_match.group("sku")),
                )
            )
        elif description_match := re.fullmatch(
            r"set @netlab_transfer_description_rows = \(select count\(\*\) from `oc_product_description` "
            r"where `product_id`=(?P<product_id>\d+) and `language_id`=(?P<language_id>\d+) "
            r"and @netlab_transfer_product_rows=1\)",
            code,
        ):
            self.operations.append(
                (
                    "set_description_rows",
                    _parse_sql_int(description_match.group("product_id"), "description product"),
                    _parse_sql_int(description_match.group("language_id"), "language"),
                )
            )
        elif code == "set @netlab_transfer_product_rows = row_count()":
            self.operations.append(("set_product_rows",))
        elif code == "set @netlab_transfer_description_rows = row_count()":
            self.operations.append(("set_description_rows",))
        elif re.fullmatch(
            r"set @netlab_transfer_run_id\s*=\s*convert\(0x[0-9a-f]+ using utf8mb4\)",
            code,
        ):
            pass
        elif code == "set @netlab_transfer_product_id = last_insert_id()":
            self.operations.append(("set_product_id",))
        elif code.startswith("create table `oc_netlab_transfer_audit` ("):
            _validate_create_shape(code, deadline_check=self._deadline_check)
            self.audit_table = True
        elif (
            (code.startswith("update `oc_product` set ") and " where `product_id`=" in code)
            or (code.startswith("update `oc_product_description` set ") and " where `product_id`=" in code)
            or code.startswith((
                "insert into `oc_product` (",
                "insert into `oc_product_description` (",
                "insert into `oc_product_to_category` (",
                "insert into `oc_product_attribute` (",
                "insert into `oc_netlab_transfer_audit` (",
            ))
        ):
            pass
        elif code.startswith("select "):
            marker, value = _validate_marker_statement(original, deadline_check=self._deadline_check)
            self._marker_values.setdefault(marker, []).append(value)
        else:
            raise StagingApplyError("candidate contains out-of-scope SQL statement")
        self._capture = []
        self._capture_length = 0
        self._head = []
        self._has_code = False


def _validate_scanned_candidate(scanner: _SqlCandidateScanner) -> None:
    if not scanner.set_names:
        raise StagingApplyError("candidate is missing required marker: set names utf8mb4")
    missing = _REQUIRED_MARKERS - scanner.marker_values.keys()
    if missing:
        raise StagingApplyError(f"candidate is missing required marker: {min(missing)}")
    for marker in _REQUIRED_MARKERS - {"NETLAB_TRANSFER_APPLY_DONE", "NETLAB_TRANSFER_RELATIONS_CREATED"}:
        values = scanner.marker_values[marker]
        if len(values) != 1 or values[0] != 0:
            raise StagingApplyError(f"candidate {marker.casefold()} marker is not exactly zero")
    relation_values = scanner.marker_values["NETLAB_TRANSFER_RELATIONS_CREATED"]
    if len(relation_values) != 1 or not isinstance(relation_values[0], int) or relation_values[0] < 0:
        raise StagingApplyError("candidate relations-created marker is invalid")
    if len(scanner.marker_values["NETLAB_TRANSFER_APPLY_DONE"]) != 1:
        raise StagingApplyError("candidate apply_done marker is not unique")
    if not scanner.audit_table:
        raise StagingApplyError("candidate has no provenance audit table")


def validate_candidate_sql(
    sql: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> _SqlCandidateScanner:
    if not sql.strip():
        raise StagingApplyError("candidate SQL is empty")
    scanner = _SqlCandidateScanner(deadline_check=deadline_check)
    scanner.feed(sql, final=True)
    scanner.finish()
    _validate_scanned_candidate(scanner)
    return scanner


def _validate_candidate_operations(
    scanner: _SqlCandidateScanner,
    records: list[dict[str, Any]],
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    expected = _expected_operation_signatures(records, deadline_check=deadline_check)
    actual = scanner.operations
    if actual != expected:
        raise StagingApplyError("candidate SQL operation sequence does not match RECORDS.jsonl")
    expected_relations = 0
    for record in records:
        if deadline_check is not None:
            deadline_check()
        if (
            isinstance(record.get("target_payload"), dict)
            and isinstance(record["target_payload"].get("target_category_id"), int)
        ):
            expected_relations += 1
    if scanner.marker_values["NETLAB_TRANSFER_RELATIONS_CREATED"] != [expected_relations]:
        raise StagingApplyError("candidate relations-created marker does not match RECORDS.jsonl")


def validate_candidate_operation_set(sql: str, records: list[dict[str, Any]]) -> None:
    scanner = validate_candidate_sql(sql)
    _validate_candidate_operations(scanner, records)


def validate_candidate_file(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> _SqlCandidateScanner:
    """Validate a large candidate without materializing it in memory."""
    try:
        before_path_stat = os.lstat(path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError("candidate SQL is not a regular file")
        if before_path_stat.st_size == 0:
            raise StagingApplyError("candidate SQL is empty")
        scanner = _SqlCandidateScanner(deadline_check=deadline_check)
        decoder = codecs.getincrementaldecoder("utf-8")()
        total_bytes = 0
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(before_handle_stat):
                raise StagingApplyError("candidate SQL changed before validation")
            while chunk := handle.read(1024 * 1024):
                if deadline_check is not None:
                    deadline_check()
                total_bytes += len(chunk)
                if total_bytes > _MAX_CANDIDATE_SQL_BYTES:
                    raise StagingApplyError("candidate SQL exceeds configured size bound")
                try:
                    scanner.feed(decoder.decode(chunk, final=False))
                except UnicodeDecodeError as exc:
                    raise StagingApplyError("candidate SQL is not valid UTF-8") from exc
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
        try:
            scanner.feed(decoder.decode(b"", final=True))
        except UnicodeDecodeError as exc:
            raise StagingApplyError("candidate SQL is not valid UTF-8") from exc
        scanner.finish()
    except StagingApplyError:
        raise
    except (OSError, ValueError) as exc:
        raise StagingApplyError("candidate SQL cannot be read") from exc
    if (
        _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(after_path_stat)
        or _stable_file_stat_key(before_handle_stat) != _stable_file_stat_key(after_handle_stat)
        or total_bytes != before_path_stat.st_size
    ):
        raise StagingApplyError("candidate SQL changed during validation")
    _validate_scanned_candidate(scanner)
    return scanner


def _file_identity(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    try:
        before_path_stat = os.lstat(path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError(f"candidate file is not regular: {path.name}")
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise StagingApplyError(f"candidate file changed before read: {path.name}")
            digest = hashlib.sha256()
            size = 0
            while chunk := handle.read(1024 * 1024):
                if deadline_check is not None:
                    deadline_check()
                size += len(chunk)
                digest.update(chunk)
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
    except OSError as exc:
        raise StagingApplyError(f"candidate file cannot be read: {path.name}") from exc
    if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
        after_path_stat.st_dev,
        after_path_stat.st_ino,
        after_path_stat.st_size,
    ) or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size) != (
        after_handle_stat.st_dev,
        after_handle_stat.st_ino,
        after_handle_stat.st_size,
    ) or size != before_path_stat.st_size:
        raise StagingApplyError(f"candidate file changed during read: {path.name}")
    return {"size": size, "sha256": digest.hexdigest()}


def _read_stable_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    try:
        before_path_stat = os.lstat(path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError(f"{label} is not a regular file")
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise StagingApplyError(f"{label} changed before read")
            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:
                if deadline_check is not None:
                    deadline_check()
                chunk = handle.read(min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            payload = b"".join(chunks)
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
    except OSError as exc:
        raise StagingApplyError(f"{label} cannot be read") from exc
    if len(payload) > max_bytes:
        raise StagingApplyError(f"{label} exceeds size limit")
    if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
        after_path_stat.st_dev,
        after_path_stat.st_ino,
        after_path_stat.st_size,
    ) or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size) != (
        after_handle_stat.st_dev,
        after_handle_stat.st_ino,
        after_handle_stat.st_size,
    ) or len(payload) != before_path_stat.st_size:
        raise StagingApplyError(f"{label} changed during read")
    digest = hashlib.sha256()
    for offset in range(0, len(payload), 1024 * 1024):
        if deadline_check is not None:
            deadline_check()
        digest.update(payload[offset : offset + 1024 * 1024])
    identity = {"size": len(payload), "sha256": digest.hexdigest()}
    return payload, identity


def _candidate_identity(
    manifest: dict[str, Any],
    *,
    deadline_check: Callable[[], None] | None = None,
) -> str:
    material = {
        "schema_version": manifest["schema_version"],
        "candidate_mode": manifest["candidate_mode"],
        "run_id": manifest["run_id"],
        "source_artifact_sha256": manifest["source_artifact_sha256"],
        "matches_artifact_sha256": manifest["matches_artifact_sha256"],
        "run_manifest_sha256": manifest.get("run_manifest_sha256"),
        "run_manifest_provenance": manifest.get("run_manifest_provenance"),
        "inputs": manifest["inputs"],
        "attribute_mapping": manifest.get("attribute_mapping"),
        "files": sorted(manifest["files"], key=lambda entry: entry["path"]),
    }
    if manifest.get("schema_version") == 2:
        material["selector"] = manifest["selector"]
    if deadline_check is not None:
        deadline_check()
    canonical = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256()
    for offset in range(0, len(canonical), 1024 * 1024):
        if deadline_check is not None:
            deadline_check()
        digest.update(canonical[offset : offset + 1024 * 1024].encode("utf-8"))
    return digest.hexdigest()


def _manifest_file_entry(
    manifest: dict[str, Any],
    filename: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    for entry in manifest.get("files", []):
        if deadline_check is not None:
            deadline_check()
        if isinstance(entry, dict) and entry.get("path") == filename:
            return entry
    raise StagingApplyError(f"candidate manifest is missing file: {filename}")


def _read_bounded_json_with_identity(
    path: Path,
    label: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[Any, dict[str, Any]]:
    payload, identity = _read_stable_bytes(
        path,
        label=f"candidate {label}",
        max_bytes=_MAX_JSON_BYTES,
        deadline_check=deadline_check,
    )
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, ValueError) as exc:
        raise StagingApplyError(f"candidate {label} is invalid JSON") from exc
    return value, identity


def _read_bounded_json(
    path: Path,
    label: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> Any:
    return _read_bounded_json_with_identity(path, label, deadline_check=deadline_check)[0]


def _read_candidate_jsonl(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    total = 0
    try:
        before_path_stat = os.lstat(path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError(f"candidate {label} is not a regular file")
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise StagingApplyError(f"candidate {label} changed before read")
            for line_number, line in enumerate(handle, start=1):
                if deadline_check is not None:
                    deadline_check()
                total += len(line)
                if total > max_bytes:
                    raise StagingApplyError(f"candidate {label} exceeds size limit")
                digest.update(line)
                try:
                    value = json.loads(line.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
                except (UnicodeError, ValueError) as exc:
                    raise StagingApplyError(f"candidate {label} line {line_number} is invalid JSON") from exc
                if not isinstance(value, dict):
                    raise StagingApplyError(f"candidate {label} line {line_number} is not an object")
                records.append(value)
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
    except OSError as exc:
        raise StagingApplyError(f"candidate {label} cannot be read") from exc
    if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
        after_path_stat.st_dev,
        after_path_stat.st_ino,
        after_path_stat.st_size,
    ) or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size) != (
        after_handle_stat.st_dev,
        after_handle_stat.st_ino,
        after_handle_stat.st_size,
    ) or total != before_path_stat.st_size:
        raise StagingApplyError(f"candidate {label} changed during read")
    return records, {"size": total, "sha256": digest.hexdigest()}


def _stable_file_stat_key(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        stat.S_IFMT(value.st_mode),
        value.st_nlink,
    )


def _select_manifest_input_path(
    input_entry: dict[str, Any],
    *,
    role: str,
    deadline_check: Callable[[], None] | None = None,
) -> Path:
    for raw_path in input_entry["paths"]:
        if deadline_check is not None:
            deadline_check()
        path = Path(raw_path)
        try:
            path_stat = os.lstat(path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            raise StagingApplyError(f"candidate input path cannot be inspected: {role}") from exc
        if stat.S_ISLNK(path_stat.st_mode):
            raise StagingApplyError(f"candidate input is a symlink: {role}")
        if not stat.S_ISREG(path_stat.st_mode):
            raise StagingApplyError(f"candidate input is not a regular file: {role}")
        return path
    raise StagingApplyError(f"candidate manifest input is not available: {role}")


def _capture_stable_file(
    source: Path,
    destination: Path,
    *,
    label: str,
    max_bytes: int,
    deadline_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    created = False
    try:
        before_path_stat = os.lstat(source)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError(f"{label} is not a regular file")
        if before_path_stat.st_size > max_bytes:
            raise StagingApplyError(f"{label} exceeds size limit")
        with source.open("rb") as source_handle:
            before_handle_stat = os.fstat(source_handle.fileno())
            if _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(before_handle_stat):
                raise StagingApplyError(f"{label} changed before capture")
            digest = hashlib.sha256()
            size = 0
            with destination.open("xb") as destination_handle:
                created = True
                while chunk := source_handle.read(1024 * 1024):
                    if deadline_check is not None:
                        deadline_check()
                    size += len(chunk)
                    if size > max_bytes:
                        raise StagingApplyError(f"{label} exceeds size limit")
                    digest.update(chunk)
                    destination_handle.write(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
            after_handle_stat = os.fstat(source_handle.fileno())
        after_path_stat = os.lstat(source)
    except StagingApplyError:
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    except (OSError, ValueError) as exc:
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise StagingApplyError(f"{label} could not be captured") from exc
    if (
        _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(after_path_stat)
        or _stable_file_stat_key(before_handle_stat) != _stable_file_stat_key(after_handle_stat)
        or size != before_path_stat.st_size
    ):
        try:
            destination.unlink()
        except OSError:
            pass
        raise StagingApplyError(f"{label} changed during capture")
    return {"size": size, "sha256": digest.hexdigest()}


def _validate_reconstructed_selector(
    root: Path,
    manifest: dict[str, Any],
    selector: dict[str, Any],
    *,
    implementation_sha256: str,
    selection_rows: list[dict[str, Any]],
    selection_identity: dict[str, Any],
    records: list[dict[str, Any]],
    exceptions: list[Any],
    trusted_run_manifest: Path | None = None,
    expected_seal_sha256: str | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    inputs = manifest["inputs"]
    replay_roles = {
        "normalized_source": ("normalized-source.csv", 1024 * 1024 * 1024),
        "matches": ("matches.csv", 1024 * 1024 * 1024),
        "category_mapping_proposals": ("category-mapping-proposals.csv", 1024 * 1024 * 1024),
        "product_category_proposals": ("product-category-proposals.csv", 1024 * 1024 * 1024),
        "category_snapshot": ("category-snapshot.sql", 256 * 1024 * 1024),
    }
    with tempfile.TemporaryDirectory(prefix=".candidate-selector-verify-") as temporary_directory:
        capture_root = Path(temporary_directory)
        captured: dict[str, Path] = {}
        for role, (filename, maximum) in replay_roles.items():
            if deadline_check is not None:
                deadline_check()
            source = _select_manifest_input_path(
                inputs[role],
                role=role,
                deadline_check=deadline_check,
            )
            destination = capture_root / filename
            observed = _capture_stable_file(
                source,
                destination,
                label=f"candidate input {role}",
                max_bytes=maximum,
                deadline_check=deadline_check,
            )
            expected = {"size": inputs[role]["size"], "sha256": inputs[role]["sha256"]}
            if observed != expected:
                raise StagingApplyError(f"candidate input identity changed: {role}")
            captured[role] = destination

        run_manifest_path = _select_manifest_input_path(
            inputs["run_manifest"],
            role="run_manifest",
            deadline_check=deadline_check,
        )
        run_manifest, run_manifest_identity = _read_bounded_json_with_identity(
            run_manifest_path,
            "run manifest",
            deadline_check=deadline_check,
        )
        if run_manifest_identity != {
            "size": inputs["run_manifest"]["size"],
            "sha256": inputs["run_manifest"]["sha256"],
        }:
            raise StagingApplyError("candidate run manifest identity changed")
        trusted_manifest = None
        if trusted_run_manifest is not None:
            trusted_manifest, trusted_identity, _ = _load_candidate_trusted_manifest(
                Path(trusted_run_manifest),
                candidate_root=root,
                expected_seal_sha256=expected_seal_sha256,
                deadline_check=deadline_check,
            )
            if trusted_identity != run_manifest_identity or trusted_manifest != run_manifest:
                raise StagingApplyError("candidate run manifest does not match trusted sealed bytes")
        if not isinstance(run_manifest, dict) or run_manifest.get("supplier") != "netlab":
            raise StagingApplyError("candidate run manifest provenance is invalid")
        expected_provenance = {
            "run_id": run_manifest.get("run_id"),
            "fetched_at": run_manifest.get("fetched_at"),
            "source_catalog_date": run_manifest.get("source_catalog_date"),
            "code_identity": run_manifest.get("code_identity"),
            "policy": run_manifest.get("policy"),
            "selection_inputs": run_manifest.get("selection_inputs"),
        }
        if manifest.get("run_manifest_provenance") != expected_provenance:
            raise StagingApplyError("candidate run manifest provenance does not match source bytes")
        source_info = run_manifest.get("inputs", {}).get("source")
        if not isinstance(source_info, dict) or source_info.get("sha256") != manifest.get("source_artifact_sha256"):
            raise StagingApplyError("candidate source artifact is not bound to run manifest")
        bundle_name = source_info.get("bundle_path")
        if not isinstance(bundle_name, str):
            raise StagingApplyError("candidate run manifest source bundle path is invalid")
        bundle = Path(bundle_name)
        if bundle.is_absolute() or ".." in bundle.parts:
            raise StagingApplyError("candidate run manifest source bundle path is unsafe")
        bundle_identity = _file_identity(run_manifest_path.parent / bundle, deadline_check=deadline_check)
        if bundle_identity["sha256"] != manifest.get("source_artifact_sha256"):
            raise StagingApplyError("candidate run manifest source bundle hash does not match candidate")
        source_path = _select_manifest_input_path(
            inputs["source_artifact"],
            role="source_artifact",
            deadline_check=deadline_check,
        )
        if _file_identity(source_path, deadline_check=deadline_check) != {
            "size": inputs["source_artifact"]["size"],
            "sha256": inputs["source_artifact"]["sha256"],
        }:
            raise StagingApplyError("candidate source artifact identity changed")

        scope = selector.get("category_scope")
        if not isinstance(scope, dict):
            raise StagingApplyError("scoped candidate category scope is missing")
        root_descendants: dict[int, set[int]] = {}
        for root_entry in scope.get("roots", []):
            if deadline_check is not None:
                deadline_check()
            if (
                isinstance(root_entry, dict)
                and isinstance(root_entry.get("category_id"), int)
                and isinstance(root_entry.get("descendant_ids"), list)
            ):
                root_descendants[root_entry["category_id"]] = {
                    category_id for category_id in root_entry["descendant_ids"] if isinstance(category_id, int)
                }
        all_descendants = scope.get("descendant_category_ids")
        if not isinstance(all_descendants, list):
            raise StagingApplyError("scoped candidate descendant allowlist is missing")
        for row in selection_rows:
            if deadline_check is not None:
                deadline_check()
            target_category_id = row.get("target_category_id")
            root_category_id = row.get("root_category_id")
            if (
                not isinstance(target_category_id, int)
                or target_category_id not in all_descendants
                or not isinstance(root_category_id, int)
                or target_category_id not in root_descendants.get(root_category_id, set())
            ):
                raise StagingApplyError("selection target category is outside claimed root descendants")

        try:
            reconstructed = select_two_category_items(
                captured["normalized_source"],
                captured["matches"],
                captured["category_mapping_proposals"],
                captured["product_category_proposals"],
                captured["category_snapshot"],
                deadline_check=deadline_check,
            )
        except CategorySelectorError as exc:
            raise StagingApplyError("independent selector reconstruction failed") from exc
        bounded_canary = selector.get("bounded_canary")
        if bounded_canary is not None:
            if not isinstance(bounded_canary, dict):
                raise StagingApplyError("bounded canary metadata is invalid")
            raw_ids = bounded_canary.get("supplier_item_ids")
            if (
                not isinstance(raw_ids, list)
                or not raw_ids
                or any(not isinstance(value, str) or not value for value in raw_ids)
                or len(set(raw_ids)) != len(raw_ids)
            ):
                raise StagingApplyError("bounded canary IDs are invalid")
            full_by_id = {row["supplier_item_id"]: row for row in reconstructed.selection_manifest}
            if not set(raw_ids).issubset(full_by_id):
                raise StagingApplyError("bounded canary contains an item outside trusted selector")
            filtered_rows = tuple(full_by_id[item_id] for item_id in sorted(raw_ids))
            filtered_root_counts = Counter(str(row["root_category_id"]) for row in filtered_rows)
            filtered_mapping_counts = Counter(str(row["mapping_status"]) for row in filtered_rows)
            dropped = reconstructed.selected_count - len(filtered_rows)
            if bounded_canary.get("excluded_from_trusted_selection") != dropped:
                raise StagingApplyError("bounded canary exclusion count is inconsistent")
            exclusions = dict(reconstructed.exclusion_counts)
            exclusions["bounded_canary_excluded"] = dropped
            selection_digest = hashlib.sha256()
            for row in filtered_rows:
                selection_digest.update((json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
            reconstructed = replace(
                reconstructed,
                selected_supplier_item_ids=frozenset(raw_ids),
                selection_manifest=filtered_rows,
                selected_root_counts=dict(sorted(filtered_root_counts.items())),
                exclusion_counts=dict(sorted(exclusions.items())),
                mapping_status_counts=dict(sorted(filtered_mapping_counts.items())),
                selection_manifest_sha256=selection_digest.hexdigest(),
            )
        if list(reconstructed.selection_manifest) != selection_rows:
            raise StagingApplyError("candidate selection manifest differs from independent selector reconstruction")
        if reconstructed.selection_manifest_sha256 != selection_identity["sha256"]:
            raise StagingApplyError("candidate selection hash differs from independent selector reconstruction")

        record_ids: list[str] = []
        selected_by_id = {row["supplier_item_id"]: row for row in reconstructed.selection_manifest}
        binding_fields = (
            "catalog_sku",
            "source_category_path",
            "source_row_sha256",
            "matches_row_sha256",
            "category_mapping_row_sha256",
            "product_proposal_row_sha256",
            "target_category_id",
            "root_category_id",
        )
        for record in records:
            if deadline_check is not None:
                deadline_check()
            supplier_item_id = record.get("supplier_item_id")
            if not isinstance(supplier_item_id, str) or supplier_item_id in record_ids:
                raise StagingApplyError("candidate RECORDS supplier item multiplicity is invalid")
            selected = selected_by_id.get(supplier_item_id)
            if selected is None:
                raise StagingApplyError("candidate RECORDS row is absent from reconstructed selection")
            expected_binding = {field: selected[field] for field in binding_fields}
            if record.get("selection_binding") != expected_binding:
                raise StagingApplyError("candidate RECORDS binding differs from reconstructed selection")
            if record.get("selection_manifest_sha256") != reconstructed.selection_manifest_sha256:
                raise StagingApplyError("candidate RECORDS selection hash differs from reconstruction")
            if record.get("run_manifest_sha256") != manifest.get("run_manifest_sha256"):
                raise StagingApplyError("candidate RECORDS run manifest hash differs from candidate")
            if record.get("target_sku") != selected["catalog_sku"]:
                raise StagingApplyError("candidate RECORDS target SKU differs from reconstructed selection")
            record_ids.append(supplier_item_id)

        exception_ids: list[str] = []
        for exception in exceptions:
            if deadline_check is not None:
                deadline_check()
            if not isinstance(exception, dict):
                raise StagingApplyError("candidate exception is not an object")
            supplier_item_id = exception.get("supplier_item_id")
            if not isinstance(supplier_item_id, str) or supplier_item_id in exception_ids:
                raise StagingApplyError("candidate exception supplier item multiplicity is invalid")
            if supplier_item_id not in selected_by_id:
                raise StagingApplyError("candidate exception is absent from reconstructed selection")
            exception_ids.append(supplier_item_id)
        if set(record_ids) & set(exception_ids) or set(record_ids) | set(exception_ids) != set(selected_by_id):
            raise StagingApplyError("candidate transfer rows do not conserve reconstructed selection")

        expected_selector = reconstructed.as_manifest()
        expected_selector["selector_implementation_sha256"] = implementation_sha256
        expected_selector["selection_manifest_file"] = "SELECTION_MANIFEST.jsonl"
        expected_selector["transfer_counts"] = {
            "selected_rows": reconstructed.selected_count,
            "written_records": len(records),
            "transfer_exceptions": len(exceptions),
        }
        if bounded_canary is not None:
            expected_selector["bounded_canary"] = bounded_canary
        if selector != expected_selector:
            raise StagingApplyError("candidate selector manifest differs from independent reconstruction")


def _validate_scoped_candidate_bundle(
    root: Path,
    manifest: dict[str, Any],
    entries: dict[str, dict[str, Any]],
    *,
    trusted_run_manifest: Path | None = None,
    expected_seal_sha256: str | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    selector = manifest.get("selector")
    if not isinstance(selector, dict):
        raise StagingApplyError("scoped candidate is missing selector manifest")
    if selector.get("selector_schema_version") != 1 or selector.get("selector_policy_version") != "two-category-strong-v1":
        raise StagingApplyError("scoped candidate selector schema or policy is unsupported")
    implementation_sha256 = selector.get("selector_implementation_sha256")
    if not isinstance(implementation_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", implementation_sha256) is None:
        raise StagingApplyError("scoped candidate selector implementation identity is invalid")
    current_selector = Path(__file__).with_name("two_category_selector.py")
    if _file_identity(current_selector, deadline_check=deadline_check)["sha256"] != implementation_sha256:
        raise StagingApplyError("scoped candidate selector implementation changed")
    scope = selector.get("category_scope")
    if not isinstance(scope, dict):
        raise StagingApplyError("scoped candidate category scope is missing")
    roots = scope.get("roots")
    expected_roots = [
        {"category_id": 456, "name": "Ноутбуки и компьютеры"},
        {"category_id": 537, "name": "Смартфоны,ТВ и электроника"},
    ]
    if not isinstance(roots, list) or [
        {"category_id": item.get("category_id"), "name": item.get("name")} for item in roots
    ] != expected_roots:
        raise StagingApplyError("scoped candidate roots do not match approved scope")
    descendant_ids = scope.get("descendant_category_ids")
    if not isinstance(descendant_ids, list) or descendant_ids != sorted(set(descendant_ids)) or not all(
        isinstance(item, int) and item > 0 for item in descendant_ids
    ):
        raise StagingApplyError("scoped candidate descendant allowlist is invalid")
    allowlist_sha256 = hashlib.sha256(
        json.dumps(descendant_ids, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if scope.get("allowlist_sha256") != allowlist_sha256:
        raise StagingApplyError("scoped candidate allowlist hash does not match IDs")
    selection_name = selector.get("selection_manifest_file")
    if selection_name != "SELECTION_MANIFEST.jsonl" or selection_name not in entries:
        raise StagingApplyError("scoped candidate is missing selection manifest file")
    selection_path = root / selection_name
    selection_rows, observed_selection = _read_candidate_jsonl(
        path=selection_path,
        label="selection manifest",
        max_bytes=_MAX_RECORDS_BYTES,
        deadline_check=deadline_check,
    )
    selection_identity = entries[selection_name]
    if observed_selection != selection_identity:
        raise StagingApplyError("selection manifest file identity changed")
    selection_sha256 = selector.get("selection_manifest_sha256")
    if not isinstance(selection_sha256, str) or observed_selection["sha256"] != selection_sha256:
        raise StagingApplyError("selection manifest hash does not match selector")
    selector_inputs = selector.get("inputs")
    if not isinstance(selector_inputs, dict):
        raise StagingApplyError("scoped selector input hashes are missing")
    input_hash_pairs = {
        "normalized_source_sha256": manifest["inputs"].get("normalized_source", {}).get("sha256"),
        "matches_sha256": manifest["inputs"].get("matches", {}).get("sha256"),
        "category_mapping_proposals_sha256": manifest["inputs"].get("category_mapping_proposals", {}).get("sha256"),
        "product_category_proposals_sha256": manifest["inputs"].get("product_category_proposals", {}).get("sha256"),
    }
    if any(selector_inputs.get(key) != value for key, value in input_hash_pairs.items()):
        raise StagingApplyError("selector input hashes do not match candidate inputs")
    if scope.get("snapshot_sha256") != manifest["inputs"].get("category_snapshot", {}).get("sha256"):
        raise StagingApplyError("selector snapshot hash does not match candidate input")
    trusted_fetched_at: str | None = None
    if trusted_run_manifest is not None:
        trusted_path = Path(trusted_run_manifest)
        trusted_manifest, trusted_identity, seal_metadata = _load_candidate_trusted_manifest(
            trusted_path,
            candidate_root=root,
            expected_seal_sha256=expected_seal_sha256,
            deadline_check=deadline_check,
        )
        trusted_fetched_at = trusted_manifest.get("fetched_at")
        candidate_run_manifest_input = manifest["inputs"].get("run_manifest")
        if not isinstance(candidate_run_manifest_input, dict):
            raise StagingApplyError("candidate run manifest input is missing")
        candidate_run_manifest_identity = {
            "size": candidate_run_manifest_input.get("size"),
            "sha256": candidate_run_manifest_input.get("sha256"),
        }
        if trusted_identity != candidate_run_manifest_identity:
            raise StagingApplyError("candidate run manifest is not the trusted run manifest")
        trusted_run_path = _trusted_sealed_input_path(
            candidate_run_manifest_input,
            role="run_manifest",
            seal_metadata=seal_metadata,
            deadline_check=deadline_check,
        )
        if trusted_run_path.resolve(strict=True) != trusted_path.resolve(strict=True):
            raise StagingApplyError("candidate run manifest path is not the sealed run manifest")
        source_artifact_input = manifest["inputs"].get("source_artifact")
        if not isinstance(source_artifact_input, dict):
            raise StagingApplyError("candidate source artifact input is missing")
        _trusted_sealed_input_path(
            source_artifact_input,
            role="source_artifact",
            seal_metadata=seal_metadata,
            deadline_check=deadline_check,
        )
        trusted_selection_inputs = trusted_manifest.get("selection_inputs")
        if not isinstance(trusted_selection_inputs, dict):
            raise StagingApplyError("trusted run manifest lacks sealed selection inputs")
        for role in (
            "normalized_source",
            "matches",
            "category_mapping_proposals",
            "product_category_proposals",
            "category_snapshot",
        ):
            if deadline_check is not None:
                deadline_check()
            trusted_input = trusted_selection_inputs.get(role)
            candidate_input = manifest["inputs"].get(role)
            if (
                not isinstance(trusted_input, dict)
                or not isinstance(candidate_input, dict)
                or not isinstance(trusted_input.get("size"), int)
                or trusted_input["size"] < 0
                or re.fullmatch(r"[0-9a-f]{64}", str(trusted_input.get("sha256"))) is None
                or candidate_input.get("size") != trusted_input.get("size")
                or candidate_input.get("sha256") != trusted_input.get("sha256")
            ):
                raise StagingApplyError(f"candidate selector input is not sealed by trusted run: {role}")
            trusted_input_path = _trusted_sealed_input_path(
                candidate_input,
                role=role,
                seal_metadata=seal_metadata,
                deadline_check=deadline_check,
            )
            selected_input_path = _select_manifest_input_path(
                candidate_input,
                role=role,
                deadline_check=deadline_check,
            )
            if trusted_input_path.resolve(strict=True) != selected_input_path.resolve(strict=True):
                raise StagingApplyError(f"candidate selector path is not the sealed input: {role}")
    selected_ids: set[str] = set()
    selected_root_counts: Counter[str] = Counter()
    for row in selection_rows:
        if deadline_check is not None:
            deadline_check()
        supplier_item_id = row.get("supplier_item_id")
        if not isinstance(supplier_item_id, str) or not supplier_item_id or supplier_item_id in selected_ids:
            raise StagingApplyError("selection manifest supplier item multiplicity is invalid")
        selected_ids.add(supplier_item_id)
        target_category_id = row.get("target_category_id")
        root_category_id = row.get("root_category_id")
        if not isinstance(target_category_id, int) or target_category_id < 1:
            raise StagingApplyError("selection manifest target category is invalid")
        if not isinstance(root_category_id, int) or root_category_id not in {456, 537}:
            raise StagingApplyError("selection manifest root category is invalid")
        selected_root_counts[str(root_category_id)] += 1
    counts = selector.get("counts")
    transfer_counts = selector.get("transfer_counts")
    if not isinstance(counts, dict) or not isinstance(transfer_counts, dict):
        raise StagingApplyError("scoped candidate selector counts are missing")
    if counts.get("selected_total") != len(selection_rows):
        raise StagingApplyError("selector selected_total does not match selection manifest")
    if counts.get("selected_root_counts") != dict(sorted(selected_root_counts.items())):
        raise StagingApplyError("selector root counts do not match selection manifest")

    records_path = root / "RECORDS.jsonl"
    if "RECORDS.jsonl" not in entries:
        raise StagingApplyError("scoped candidate is missing RECORDS.jsonl")
    records, observed_records = _read_candidate_jsonl(
        path=records_path,
        label="RECORDS.jsonl",
        max_bytes=_MAX_RECORDS_BYTES,
        deadline_check=deadline_check,
    )
    if observed_records != entries["RECORDS.jsonl"]:
        raise StagingApplyError("RECORDS.jsonl identity changed")
    if transfer_counts.get("selected_rows") != len(selection_rows):
        raise StagingApplyError("selector selected_rows does not match selection manifest")
    if transfer_counts.get("written_records") != len(records):
        raise StagingApplyError("selector written_records does not match RECORDS.jsonl")

    selection_by_id = {row["supplier_item_id"]: row for row in selection_rows}
    for record in records:
        if deadline_check is not None:
            deadline_check()
        supplier_item_id = record.get("supplier_item_id")
        binding = record.get("selection_binding")
        if not isinstance(supplier_item_id, str) or not isinstance(binding, dict):
            raise StagingApplyError("scoped RECORDS row is missing selection binding")
        selected = selection_by_id.get(supplier_item_id)
        if selected is None:
            raise StagingApplyError("RECORDS row is absent from selection manifest")
        if record.get("selection_manifest_sha256") != selection_sha256:
            raise StagingApplyError("RECORDS selection hash does not match selection manifest")
        if record.get("source_row_sha256") != selected.get("source_row_sha256"):
            raise StagingApplyError("RECORDS source row hash does not match selection manifest")
        if record.get("run_manifest_sha256") != manifest.get("run_manifest_sha256"):
            raise StagingApplyError("RECORDS run manifest hash does not match candidate")
        for field in (
            "catalog_sku",
            "source_category_path",
            "source_row_sha256",
            "matches_row_sha256",
            "category_mapping_row_sha256",
            "product_proposal_row_sha256",
            "target_category_id",
            "root_category_id",
        ):
            if binding.get(field) != selected.get(field):
                raise StagingApplyError(f"RECORDS selection binding mismatch: {field}")
        if record.get("target_sku") != selected.get("catalog_sku"):
            raise StagingApplyError("RECORDS target SKU does not match selection manifest")
    exceptions_path = root / "EXCEPTIONS.json"
    exceptions = _read_bounded_json(exceptions_path, "exceptions", deadline_check=deadline_check)
    if not isinstance(exceptions, list):
        raise StagingApplyError("candidate exceptions are not a JSON list")
    if transfer_counts.get("transfer_exceptions") != len(exceptions):
        raise StagingApplyError("selector transfer_exceptions does not match EXCEPTIONS.json")
    if len(selection_rows) != len(records) + len(exceptions):
        raise StagingApplyError("selector transfer counts do not conserve selected rows")
    summary = _read_bounded_json(root / "SUMMARY.json", "summary", deadline_check=deadline_check)
    if not isinstance(summary, dict):
        raise StagingApplyError("candidate summary is invalid")
    summary_selection = summary.get("category_selection")
    if (
        not isinstance(summary_selection, dict)
        or summary_selection.get("selection_manifest_sha256") != selection_sha256
        or summary_selection.get("selector_implementation_sha256") != implementation_sha256
    ):
        raise StagingApplyError("SUMMARY.json does not bind category selection")
    run_provenance = manifest.get("run_manifest_provenance")
    if (
        not isinstance(run_provenance, dict)
        or not isinstance(run_provenance.get("run_id"), str)
        or not isinstance(run_provenance.get("fetched_at"), str)
        or not run_provenance.get("fetched_at")
        or not isinstance(run_provenance.get("code_identity"), dict)
        or not isinstance(run_provenance.get("policy"), dict)
    ):
        raise StagingApplyError("candidate run-manifest provenance is incomplete")
    _validate_candidate_source_freshness(
        manifest,
        records,
        trusted_fetched_at=trusted_fetched_at,
        trusted_manifest_bound=trusted_run_manifest is not None,
        deadline_check=deadline_check,
    )
    if manifest.get("run_manifest_sha256") != manifest["inputs"].get("run_manifest", {}).get("sha256"):
        raise StagingApplyError("candidate run manifest hash is not bound to input identity")
    if records and manifest.get("run_manifest_sha256") != records[0].get("run_manifest_sha256"):
        raise StagingApplyError("RECORDS run manifest hash is not bound")
    if manifest.get("candidate_mode") == "apply_staging":
        sql_path = root / "APPLY_STAGING.sql"
        scanner = validate_candidate_file(sql_path, deadline_check=deadline_check)
        _validate_candidate_operations(scanner, records, deadline_check=deadline_check)
    _validate_reconstructed_selector(
        root,
        manifest,
        selector,
        implementation_sha256=implementation_sha256,
        selection_rows=selection_rows,
        selection_identity=observed_selection,
        records=records,
        exceptions=exceptions,
        trusted_run_manifest=trusted_run_manifest,
        expected_seal_sha256=expected_seal_sha256,
        deadline_check=deadline_check,
    )


def validate_candidate_bundle(
    candidate_sql: Path,
    *,
    trusted_run_manifest: Path | None = None,
    expected_trusted_run_seal_sha256: str | None = None,
    require_trusted_run_manifest: bool = True,
    deadline_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Validate the no-clobber file set bound by CANDIDATE_MANIFEST.json."""
    root = candidate_sql.resolve(strict=True).parent
    manifest_path = root / "CANDIDATE_MANIFEST.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise StagingApplyError("candidate has no CANDIDATE_MANIFEST.json")
    try:
        sealed_candidate = load_sealed_run(
            root,
            read_content=False,
            deadline_check=deadline_check,
        )
    except IntegrityDeadlineExceeded:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise StagingApplyError("candidate is not backed by a verified immutable seal") from exc
    manifest = _read_bounded_json(manifest_path, "manifest", deadline_check=deadline_check)
    if not isinstance(manifest, dict):
        raise StagingApplyError("candidate manifest schema is unsupported")
    schema_version = manifest.get("schema_version")
    if (
        schema_version not in {1, 2}
        or manifest.get("candidate_mode") != "apply_staging"
        or not isinstance(manifest.get("candidate_id"), str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest["candidate_id"]) is None
    ):
        raise StagingApplyError("candidate manifest schema is unsupported")
    if (
        schema_version == 2
        and require_trusted_run_manifest
        and (trusted_run_manifest is None or expected_trusted_run_seal_sha256 is None)
    ):
        raise StagingApplyError("schema-v2 apply requires an externally anchored trusted run seal")
    run_id = manifest.get("run_id")
    entries = manifest.get("files")
    source_hash = manifest.get("source_artifact_sha256")
    matches_hash = manifest.get("matches_artifact_sha256")
    inputs = manifest.get("inputs")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(entries, list)
        or not entries
        or re.fullmatch(r"[0-9a-f]{64}", source_hash or "") is None
        or re.fullmatch(r"[0-9a-f]{64}", matches_hash or "") is None
        or not isinstance(inputs, dict)
    ):
        raise StagingApplyError("candidate manifest is missing run_id or files")

    input_roles = ["source_artifact", "normalized_source", "matches"]
    attribute_mapping_meta = manifest.get("attribute_mapping")
    if attribute_mapping_meta is not None:
        if not isinstance(attribute_mapping_meta, dict):
            raise StagingApplyError("candidate attribute mapping metadata is invalid")
        for key in ("file_sha256", "artifact_sha256"):
            if not isinstance(attribute_mapping_meta.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", attribute_mapping_meta[key]) is None:
                raise StagingApplyError(f"candidate attribute mapping {key} is invalid")
        if not isinstance(attribute_mapping_meta.get("database"), str) or not re.fullmatch(
            r"mks123_stage(?:_[A-Za-z0-9]+)*", attribute_mapping_meta["database"]
        ):
            raise StagingApplyError("candidate attribute mapping database is invalid")
        if isinstance(attribute_mapping_meta.get("language_id"), bool) or not isinstance(attribute_mapping_meta.get("language_id"), int) or not (1 <= attribute_mapping_meta["language_id"] <= 2147483647):
            raise StagingApplyError("candidate attribute mapping language is invalid")
        scope_skus = attribute_mapping_meta.get("scope_skus")
        if not isinstance(scope_skus, list) or any(not isinstance(sku, str) or not sku for sku in scope_skus) or len(set(scope_skus)) != len(scope_skus):
            raise StagingApplyError("candidate attribute mapping scope is invalid")
        input_roles.append("attribute_mapping")
    if schema_version == 2:
        input_roles.extend(["run_manifest", "category_mapping_proposals", "product_category_proposals", "category_snapshot"])
    else:
        input_roles.append("run_manifest")
    if set(inputs) != set(input_roles):
        unexpected = sorted(set(inputs) - set(input_roles))
        missing = sorted(set(input_roles) - set(inputs))
        raise StagingApplyError(f"candidate input roles are not exact: missing={missing}, unexpected={unexpected}")
    for role in input_roles:
        if deadline_check is not None:
            deadline_check()
        input_entry = inputs.get(role)
        if not isinstance(input_entry, dict):
            raise StagingApplyError(f"candidate manifest is missing input: {role}")
        input_paths = input_entry.get("paths")
        input_hash = input_entry.get("sha256")
        input_size = input_entry.get("size")
        if (
            not isinstance(input_paths, list)
            or not input_paths
            or any(
                not isinstance(path_value, str)
                or not (
                    Path(path_value).is_absolute()
                    or path_value.startswith("/")
                    or re.fullmatch(r"[A-Za-z]:[\\\\/].*", path_value)
                )
                for path_value in input_paths
            )
            or not isinstance(input_size, int)
            or input_size < 0
            or not isinstance(input_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", input_hash) is None
        ):
            raise StagingApplyError(f"candidate manifest input is invalid: {role}")
        if schema_version != 2:
            input_file: Path | None = None
            for path_value in input_paths:
                if deadline_check is not None:
                    deadline_check()
                candidate_path = Path(path_value)
                if not candidate_path.is_symlink() and candidate_path.is_file():
                    input_file = candidate_path
                    break
            if input_file is None:
                raise StagingApplyError(f"candidate manifest input is not a regular file: {role}")
            observed_input = _file_identity(input_file, deadline_check=deadline_check)
            if observed_input["size"] != input_size or observed_input["sha256"] != input_hash:
                raise StagingApplyError(f"candidate input identity changed: {role}")
    if inputs["source_artifact"]["sha256"] != source_hash or inputs["matches"]["sha256"] != matches_hash:
        raise StagingApplyError("candidate manifest input hashes do not match source/matches fields")
    if attribute_mapping_meta is not None and inputs["attribute_mapping"]["sha256"] != attribute_mapping_meta["file_sha256"]:
        raise StagingApplyError("candidate attribute mapping input hash does not match metadata")

    expected: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if deadline_check is not None:
            deadline_check()
        if not isinstance(entry, dict):
            raise StagingApplyError("candidate manifest has a non-object file entry")
        relative = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size")
        if (
            not isinstance(relative, str)
            or relative.replace("\\", "/") != relative
            or not relative
            or relative == "CANDIDATE_MANIFEST.json"
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise StagingApplyError("candidate manifest has an invalid file entry")
        if relative == "APPLY_STAGING.sql" and size > _MAX_CANDIDATE_SQL_BYTES:
            raise StagingApplyError("candidate SQL exceeds configured size bound")
        if relative == "RECORDS.jsonl" and size > _MAX_RECORDS_BYTES:
            raise StagingApplyError("candidate RECORDS.jsonl exceeds configured bounds")
        if relative in expected:
            raise StagingApplyError(f"candidate manifest has duplicate path: {relative}")
        expected[relative] = {"size": size, "sha256": digest}

    actual: dict[str, Path] = {}
    for path in _enumerate_candidate_entries(root, deadline_check=deadline_check):
        if deadline_check is not None:
            deadline_check()
        relative = path.relative_to(root).as_posix()
        if relative in {"CANDIDATE_MANIFEST.json", "seal.json"}:
            continue
        if path.is_symlink() or not path.is_file():
            raise StagingApplyError(f"candidate bundle contains non-regular entry: {relative}")
        actual[relative] = path
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        detail = f"missing {missing[0]}" if missing else f"unexpected {extra[0]}"
        raise StagingApplyError(f"candidate file set changed: {detail}")

    for relative, identity in expected.items():
        if deadline_check is not None:
            deadline_check()
        observed = _file_identity(actual[relative], deadline_check=deadline_check)
        if observed != identity:
            raise StagingApplyError(f"candidate file identity changed: {relative}")
    records_for_metadata, _ = _read_candidate_jsonl(
        actual["RECORDS.jsonl"],
        label="RECORDS.jsonl",
        max_bytes=_MAX_RECORDS_BYTES,
        deadline_check=deadline_check,
    )
    has_attribute_rows = any(
        isinstance(record.get("attribute_rows"), list) and bool(record.get("attribute_rows"))
        for record in records_for_metadata
    )
    if has_attribute_rows and attribute_mapping_meta is None:
        raise StagingApplyError("attribute-bearing candidate is missing mapping metadata")
    _validate_attribute_mapping_binding(
        manifest,
        records_for_metadata,
        root,
        deadline_check=deadline_check,
    )
    sealed_files = sealed_candidate.files
    if set(sealed_files) != set(expected) | {"CANDIDATE_MANIFEST.json"}:
        raise StagingApplyError("candidate seal does not bind the complete candidate file set")
    for relative, identity in expected.items():
        if deadline_check is not None:
            deadline_check()
        sealed_identity = sealed_files[relative]
        sealed_size = sealed_identity.size if sealed_identity.size is not None else 0
        if sealed_size != identity["size"] or sealed_identity.sha256 != identity["sha256"]:
            raise StagingApplyError(f"candidate seal identity mismatch: {relative}")
    if schema_version == 2:
        _validate_scoped_candidate_bundle(
            root,
            manifest,
            expected,
            trusted_run_manifest=trusted_run_manifest,
            expected_seal_sha256=expected_trusted_run_seal_sha256,
            deadline_check=deadline_check,
        )
    summary_path = root / "SUMMARY.json"
    summary = _read_bounded_json(summary_path, "summary", deadline_check=deadline_check)
    if not isinstance(summary, dict) or summary.get("run_id") != run_id:
        raise StagingApplyError("candidate manifest does not bind SUMMARY.json run_id")
    if _candidate_identity(manifest, deadline_check=deadline_check) != manifest["candidate_id"]:
        raise StagingApplyError("candidate_id does not match the committed file map")
    return manifest


def _verify_locked_candidate_bundle(
    manifest: dict[str, Any],
    source_handles: dict[str, BinaryIO],
    *,
    candidate_root: Path,
    control_identities: dict[str, dict[str, Any]],
    deadline_check: Callable[[], None] | None = None,
) -> None:
    expected = {entry["path"] for entry in manifest["files"]}
    expected.update({"CANDIDATE_MANIFEST.json", "seal.json"})
    if set(source_handles) != expected:
        missing = sorted(expected - set(source_handles))
        extra = sorted(set(source_handles) - expected)
        detail = f"missing {missing[0]}" if missing else f"unexpected {extra[0]}"
        raise StagingApplyError(f"candidate lock file set mismatch: {detail}")
    if set(control_identities) != {"CANDIDATE_MANIFEST.json", "seal.json"}:
        raise StagingApplyError("candidate control identities are incomplete")
    for relative, expected_identity in control_identities.items():
        if deadline_check is not None:
            deadline_check()
        if _handle_identity(source_handles[relative], deadline_check=deadline_check) != expected_identity:
            raise StagingApplyError(f"candidate control identity changed: {relative}")

    try:
        actual_paths: dict[str, Path] = {}
        for path in _enumerate_candidate_entries(candidate_root, deadline_check=deadline_check):
            if deadline_check is not None:
                deadline_check()
            relative = path.relative_to(candidate_root).as_posix()
            if path.is_symlink() or not path.is_file():
                raise StagingApplyError(f"candidate lock contains non-regular entry: {relative}")
            actual_paths[relative] = path
    except OSError as exc:
        raise StagingApplyError("candidate lock file set cannot be re-enumerated") from exc
    if set(actual_paths) != expected:
        missing = sorted(expected - set(actual_paths))
        extra = sorted(set(actual_paths) - expected)
        detail = f"missing {missing[0]}" if missing else f"unexpected {extra[0]}"
        raise StagingApplyError(f"candidate lock file set changed: {detail}")

    for relative in sorted(expected):
        if deadline_check is not None:
            deadline_check()
        handle = source_handles[relative]
        if not _path_matches_locked_handle(actual_paths[relative], handle):
            raise StagingApplyError(f"candidate locked identity changed: {relative}")

    locked_manifest = _read_locked_bounded_json(
        source_handles["CANDIDATE_MANIFEST.json"],
        "manifest",
        deadline_check=deadline_check,
    )
    if locked_manifest != manifest:
        raise StagingApplyError("candidate manifest was not validated from the locked handle")

    entries = {entry["path"]: entry for entry in manifest["files"]}
    for relative, entry in entries.items():
        if deadline_check is not None:
            deadline_check()
        handle = source_handles[relative]
        if _handle_identity(handle, deadline_check=deadline_check) != {"size": entry["size"], "sha256": entry["sha256"]}:
            raise StagingApplyError(f"candidate bytes changed during locked validation: {relative}")


def _snapshot_candidate_bundle(
    candidate_sql: Path,
    backup_root: Path,
    manifest: dict[str, Any],
    *,
    source_handles: dict[str, BinaryIO],
    deadline_check: Callable[[], None] | None = None,
) -> Path:
    snapshot_root = backup_root / "candidate-snapshot"
    snapshot_root.mkdir(exist_ok=False)
    entries = {entry["path"]: entry for entry in manifest["files"]}
    for relative in ("APPLY_STAGING.sql", "RECORDS.jsonl"):
        entry = entries.get(relative)
        if entry is None:
            raise StagingApplyError(f"candidate manifest is missing file: {relative}")
        source_handle = source_handles.get(relative)
        if source_handle is None:
            raise StagingApplyError(f"candidate lock is missing file: {relative}")
        destination = snapshot_root / relative
        digest = hashlib.sha256()
        size = 0
        copy_limit = min(
            entry["size"],
            _MAX_CANDIDATE_SQL_BYTES if relative == "APPLY_STAGING.sql" else _MAX_RECORDS_BYTES,
        )
        try:
            with destination.open("xb") as destination_handle:
                source_handle.seek(0)
                while chunk := source_handle.read(1024 * 1024):
                    if deadline_check is not None:
                        deadline_check()
                    if size + len(chunk) > copy_limit:
                        raise StagingApplyError(f"candidate snapshot exceeds configured bound: {relative}")
                    size += len(chunk)
                    digest.update(chunk)
                    destination_handle.write(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())
        except StagingApplyError:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
        except OSError as exc:
            try:
                destination.unlink()
            except OSError:
                pass
            raise StagingApplyError(f"candidate snapshot could not be created: {relative}") from exc
        if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
            try:
                destination.unlink()
            except OSError:
                pass
            raise StagingApplyError(f"candidate changed during validated snapshot: {relative}")
    return snapshot_root / "APPLY_STAGING.sql"


def _safe_backup_root(
    path: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> Path:
    if deadline_check is not None:
        deadline_check()
    resolved = path.resolve()
    if deadline_check is not None:
        deadline_check()
    if "serverbackups" not in {part.casefold() for part in resolved.parts}:
        raise StagingApplyError("backup root must be under durable ServerBackups")
    if resolved.exists():
        raise StagingApplyError(f"backup root already exists: {resolved}")
    return resolved


def _safe_candidate_root(
    candidate_sql: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> Path:
    if deadline_check is not None:
        deadline_check()
    resolved = candidate_sql.resolve(strict=True)
    if deadline_check is not None:
        deadline_check()
    if "serverbackups" not in {part.casefold() for part in resolved.parts}:
        raise StagingApplyError("candidate must be under durable ServerBackups")
    if resolved.name != "APPLY_STAGING.sql":
        raise StagingApplyError("candidate filename must be APPLY_STAGING.sql")
    return resolved


def _write_receipt_file(
    backup_root: Path,
    result: dict[str, Any],
    filename: str,
) -> Path:
    if not backup_root.is_dir() or backup_root.is_symlink():
        raise StagingApplyError("apply receipt root is not a regular directory")
    result_path = backup_root / filename
    payload = dict(result)
    payload["result_path"] = str(result_path)
    try:
        with result_path.open("xb") as handle:
            handle.write((json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError) as exc:
        raise StagingApplyError("apply result receipt could not be written") from exc
    return result_path


def write_apply_result(backup_root: Path, result: dict[str, Any]) -> Path:
    return _write_receipt_file(backup_root, result, "APPLY_RESULT.json")


def _write_pending_apply_result(backup_root: Path, result: dict[str, Any]) -> Path:
    return _write_receipt_file(backup_root, result, "APPLY_PENDING.json")


def _write_failure_receipt(backup_root: Path, result: dict[str, Any]) -> Path:
    if not backup_root.is_dir() or backup_root.is_symlink():
        raise StagingApplyError("failure receipt root is not a regular directory")
    result_path = backup_root / "APPLY_FAILURE.json"
    payload = dict(result)
    payload["result_path"] = str(result_path)
    try:
        with result_path.open("xb") as handle:
            handle.write((json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError) as exc:
        raise StagingApplyError("failure receipt could not be written") from exc
    return result_path


def _finalize_success(
    target: StagingTarget,
    backup_root: Path,
    result: dict[str, Any],
    before: dict[str, Any],
    records: list[dict[str, Any]],
    coordination_session: _LockedMysqlSession,
) -> dict[str, Any]:
    coordination_session.assert_alive()
    pending_result = dict(result)
    pending_result["status"] = "COMMIT_PENDING"
    pending_result["receipt_stage"] = "before_commit"
    try:
        pending_receipt = _write_pending_apply_result(backup_root, pending_result)
    except StagingApplyError as receipt_exc:
        result["stage"] = "receipt"
        result["receipt_error"] = str(receipt_exc)
        try:
            result["rollback_readback"] = _restore_with_coordination(
                target,
                before,
                records,
                coordination_session=coordination_session,
            )
            result["rollback"] = "PASS"
            result["status"] = "ROLLED_BACK_RECEIPT_FAILURE"
        except StagingApplyError as rollback_exc:
            result["rollback"] = f"FAILED: {rollback_exc}"
            result["status"] = "ROLLBACK_BLOCKED"
        try:
            failure_receipt = _write_failure_receipt(backup_root, result)
            result["failure_result_path"] = str(failure_receipt)
        except StagingApplyError as failure_receipt_exc:
            result["failure_receipt_error"] = str(failure_receipt_exc)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from receipt_exc
    coordination_session.assert_alive()
    result["pending_result_path"] = str(pending_receipt)
    return result


def _finalize_committed_result(
    backup_root: Path,
    result: dict[str, Any],
) -> dict[str, Any]:
    committed = dict(result)
    committed["status"] = "PASS"
    committed["receipt_stage"] = "after_commit"
    committed.pop("pending_result_path", None)
    try:
        receipt = write_apply_result(backup_root, committed)
    except StagingApplyError as exc:
        blocked = dict(result)
        blocked["status"] = "COMMITTED_RECEIPT_BLOCKED"
        blocked["stage"] = "receipt_after_commit"
        blocked["receipt_error"] = str(exc)
        try:
            failure_receipt = _write_failure_receipt(backup_root, blocked)
            blocked["failure_result_path"] = str(failure_receipt)
        except StagingApplyError as failure_exc:
            blocked["failure_receipt_error"] = str(failure_exc)
        raise StagingApplyError(json.dumps(blocked, ensure_ascii=False, sort_keys=True)) from exc
    committed["result_path"] = str(receipt)
    return committed


def _restore_with_coordination(
    target: StagingTarget,
    before: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    coordination_session: _LockedMysqlSession | None = None,
) -> dict[str, Any]:
    if coordination_session is None:
        raise StagingApplyError("rollback requires the active InnoDB coordination session")
    coordination_session.assert_alive()
    rollback = coordination_session.rollback_transaction(before)
    coordination_session.assert_alive()
    verified = verify_restored_state(
        target,
        before,
        records,
        query_runner=coordination_session.query,
    )
    coordination_session.assert_alive()
    return {"status": "PASS", "transaction": rollback, "verification": verified}


def _before_state_identity(before: dict[str, Any]) -> str:
    stable = {key: value for key, value in before.items() if key != "competing_writer_sessions"}
    return json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _client_command(target: StagingTarget, *, include_database: bool = True) -> list[str]:
    command = [target.mariadb_bin, "--batch", "--raw", "--skip-column-names"]
    if target.socket:
        command.extend(["--protocol=socket", "--socket", target.socket])
    else:
        command.extend(["--protocol=tcp", "--host", target.host, "--port", str(target.port)])
    if include_database:
        command.extend(["--database", target.database])
    return command


def _run_sql(target: StagingTarget, sql: str, *, include_database: bool = True) -> str:
    try:
        result = subprocess.run(
            _client_command(target, include_database=include_database),
            input=sql,
            text=True,
            capture_output=True,
            timeout=target.timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StagingApplyError("mariadb query could not complete") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit={result.returncode}"
        raise StagingApplyError(f"mariadb query failed: {detail[:500]}")
    return result.stdout


def _enumerate_candidate_entries(
    root: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> list[Path]:
    pending = [root]
    entries: list[Path] = []
    try:
        while pending:
            if deadline_check is not None:
                deadline_check()
            current = pending.pop()
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if deadline_check is not None:
                        deadline_check()
                    path = Path(entry.path)
                    if len(entries) >= _MAX_CANDIDATE_ENTRIES:
                        raise StagingApplyError("candidate bundle exceeds entry-count limit")
                    entries.append(path)
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
    except OSError as exc:
        raise StagingApplyError("candidate bundle cannot be enumerated") from exc
    return entries


@contextmanager
def _locked_candidate_bundle(
    root: Path,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> Iterator[dict[str, BinaryIO]]:
    files: list[Path] = []
    for path in _enumerate_candidate_entries(root, deadline_check=deadline_check):
        if deadline_check is not None:
            deadline_check()
        if not path.is_symlink() and path.is_file():
            files.append(path)
    files.sort(key=lambda path: path.relative_to(root).as_posix())
    if not files:
        raise StagingApplyError("candidate bundle has no regular files")
    with ExitStack() as stack:
        handles: dict[str, BinaryIO] = {}
        for path in files:
            if deadline_check is not None:
                deadline_check()
            handles[path.relative_to(root).as_posix()] = stack.enter_context(
                _locked_candidate_handle(path, deadline_check=deadline_check)
            )
        yield handles


def _close_locked_candidate_handle(
    handle: BinaryIO,
    *,
    locked: bool,
    windows_lock: tuple[Any, int, Any] | None,
) -> list[BaseException]:
    errors: list[BaseException] = []
    if locked and os.name == "posix":
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(exc)
    elif locked and windows_lock is not None:
        try:
            _release_windows_candidate_lock(windows_lock)
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(exc)
    try:
        handle.close()
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(exc)
    return errors


@contextmanager
def _locked_candidate_handle(
    path: Path,
    *,
    expected_identity: dict[str, Any] | None = None,
    on_boundary_error: Callable[[StagingApplyError], StagingApplyError] | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> Iterator[BinaryIO]:
    handle: BinaryIO | None = None
    locked = False
    windows_lock: tuple[Any, int, Any] | None = None
    try:
        if deadline_check is not None:
            deadline_check()
        handle = path.open("rb")
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise StagingApplyError("candidate snapshot is already in use") from exc
            locked = True
        elif os.name == "nt":
            windows_lock = _acquire_windows_candidate_lock(handle)
            locked = True
        if expected_identity is not None and _handle_identity(handle, deadline_check=deadline_check) != expected_identity:
            raise StagingApplyError("candidate snapshot identity changed")
    except (OSError, StagingApplyError) as exc:
        cleanup_errors: list[BaseException] = []
        if handle is not None:
            cleanup_errors = _close_locked_candidate_handle(
                handle,
                locked=locked,
                windows_lock=windows_lock,
            )
        failure = exc if isinstance(exc, StagingApplyError) else StagingApplyError("candidate snapshot cannot be opened")
        if cleanup_errors:
            details = "; ".join(str(error) for error in cleanup_errors)
            if isinstance(exc, IntegrityDeadlineExceeded):
                failure = _CandidatePreparationTimeout(f"{failure}; candidate handle cleanup failed: {details}")
            else:
                failure = StagingApplyError(f"{failure}; candidate handle cleanup failed: {details}")
        if on_boundary_error is not None:
            raise on_boundary_error(failure) from failure
        raise failure from exc
    assert handle is not None
    try:
        yield handle
    finally:
        active_exception = sys.exc_info()[1]
        cleanup_errors = _close_locked_candidate_handle(
            handle,
            locked=locked,
            windows_lock=windows_lock,
        )
        if cleanup_errors:
            details = "; ".join(str(error) for error in cleanup_errors)
            if isinstance(active_exception, IntegrityDeadlineExceeded):
                active_exception.add_note(f"candidate handle cleanup failed: {details}")
                if isinstance(active_exception, _CandidatePreparationTimeout):
                    raise active_exception
                raise _CandidatePreparationTimeout(
                    f"{active_exception}; candidate handle cleanup failed: {details}"
                ) from active_exception
            if len(cleanup_errors) == 1:
                raise cleanup_errors[0]
            raise StagingApplyError(f"candidate handle cleanup failed: {details}") from cleanup_errors[0]


def _acquire_windows_candidate_lock(handle: BinaryIO) -> tuple[Any, int, Any]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", ctypes.c_void_p),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    lock_file_ex = kernel32.LockFileEx
    lock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_OVERLAPPED),
    ]
    lock_file_ex.restype = wintypes.BOOL
    os_handle = int(msvcrt.get_osfhandle(handle.fileno()))
    lock_size = max(int(os.fstat(handle.fileno()).st_size), 1)
    overlapped = _OVERLAPPED()
    if not lock_file_ex(
        wintypes.HANDLE(os_handle),
        0x00000002 | 0x00000001,
        0,
        0xFFFFFFFF,
        0xFFFFFFFF,
        ctypes.byref(overlapped),
    ):
        error = ctypes.get_last_error()
        raise OSError(error, "candidate snapshot cannot acquire an exclusive Windows lock")
    return kernel32, lock_size, (os_handle, overlapped, _OVERLAPPED, ctypes)


def _release_windows_candidate_lock(lock: tuple[Any, int, Any]) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32, _lock_size, details = lock
    os_handle, overlapped, _overlapped_type, _ctypes = details
    unlock_file_ex = kernel32.UnlockFileEx
    unlock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    unlock_file_ex.restype = wintypes.BOOL
    if not unlock_file_ex(
        wintypes.HANDLE(os_handle),
        0,
        0xFFFFFFFF,
        0xFFFFFFFF,
        ctypes.byref(overlapped),
    ):
        raise OSError(ctypes.get_last_error(), "candidate snapshot Windows lock release failed")


def _handle_identity(
    handle: BinaryIO,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    try:
        handle.seek(0)
        while chunk := handle.read(1024 * 1024):
            if deadline_check is not None:
                deadline_check()
            size += len(chunk)
            digest.update(chunk)
        handle.seek(0)
    except (OSError, ValueError) as exc:
        raise StagingApplyError("candidate snapshot handle could not be read") from exc
    return {"size": size, "sha256": digest.hexdigest()}


def _read_locked_bounded_json(
    handle: BinaryIO,
    label: str,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> Any:
    try:
        handle.seek(0)
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_JSON_BYTES:
            if deadline_check is not None:
                deadline_check()
            chunk = handle.read(min(1024 * 1024, _MAX_JSON_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        handle.seek(0)
    except (OSError, ValueError) as exc:
        raise StagingApplyError(f"locked candidate {label} cannot be read") from exc
    if len(payload) > _MAX_JSON_BYTES:
        raise StagingApplyError(f"locked candidate {label} exceeds size limit")
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeError, ValueError) as exc:
        raise StagingApplyError(f"locked candidate {label} is invalid JSON") from exc


def _path_matches_locked_handle(path: Path, handle: BinaryIO) -> bool:
    try:
        before_path_stat = os.lstat(path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            return False
        with path.open("rb") as current_handle:
            before_handle_stat = os.fstat(current_handle.fileno())
        after_path_stat = os.lstat(path)
        locked_stat = os.fstat(handle.fileno())
    except (OSError, ValueError):
        return False
    return (
        _stable_file_stat_key(before_path_stat) == _stable_file_stat_key(before_handle_stat)
        and _stable_file_stat_key(before_path_stat) == _stable_file_stat_key(after_path_stat)
        and _stable_file_stat_key(before_path_stat) == _stable_file_stat_key(locked_stat)
    )


def _run_file(
    target: StagingTarget,
    path: Path,
    *,
    include_database: bool = True,
    audit_table_exists: bool = False,
    source_handle: BinaryIO | None = None,
    expected_identity: dict[str, Any] | None = None,
    transactional: bool = False,
) -> str:
    if source_handle is None:
        try:
            with path.open("rb") as owned_handle:
                return _run_file(
                    target,
                    path,
                    include_database=include_database,
                    audit_table_exists=audit_table_exists,
                    source_handle=owned_handle,
                    expected_identity=expected_identity,
                    transactional=transactional,
                )
        except OSError as exc:
            raise StagingApplyError("mariadb file operation could not complete") from exc
    handle = source_handle
    if transactional or audit_table_exists:
        raise StagingApplyError(
            "direct file execution cannot provide the staging transaction contract; "
            "use the locked InnoDB session"
        )

    try:
        handle.seek(0)
        result = subprocess.run(
            _client_command(target, include_database=include_database),
            stdin=handle,
            capture_output=True,
            timeout=target.timeout_seconds,
            check=False,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise StagingApplyError("mariadb file operation could not complete") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip() or f"exit={result.returncode}"
        raise StagingApplyError(f"mariadb file operation failed: {detail[-500:]}")
    if expected_identity is not None and _handle_identity(handle) != expected_identity:
        raise StagingApplyError("candidate bytes changed during execution")
    return result.stdout.decode("utf-8", "replace")


class _LockedMysqlSession:
    _MARKER_PREFIX = "__NETLAB_SESSION_"

    def __init__(
        self,
        target: StagingTarget,
        table_names: list[str] | tuple[str, ...],
        *,
        audit_table_exists: bool,
    ) -> None:
        tables = list(table_names)
        if audit_table_exists and "oc_netlab_transfer_audit" not in tables:
            tables.append("oc_netlab_transfer_audit")
        if not tables or any(re.fullmatch(r"[A-Za-z0-9_]+", table) is None for table in tables):
            raise StagingApplyError("database table inventory contains an unsafe lock identifier")
        self.target = target
        self.tables = list(dict.fromkeys(tables))
        self.lock_mode: str | None = None
        self.lock_name = f"netlab-staging:{target.database}:apply"
        self._lock_acquired = False
        self._transaction_started = False
        self._commit_state = "NOT_ATTEMPTED"
        self._lock_state = "NOT_ATTEMPTED"
        self.process: subprocess.Popen[bytes] | None = None
        self.stdout: BinaryIO | None = None
        self.stderr: BinaryIO | None = None
        self._stream_lock = threading.Lock()
        self._stream_buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self._stream_errors: dict[str, BaseException] = {}
        self._stream_readers: dict[str, threading.Thread] = {}
        self._stdin_write_lock = threading.Lock()
        self._stdin_write_lock_owner: int | None = None
        self._active_stdin_writer: threading.Thread | None = None
        self._transport_abort_reason: str | None = None
        self._transport_kill_error: OSError | None = None
        self._output_offset = 0
        self._query_number = 0

    def __enter__(self) -> Self:
        try:
            self.process = subprocess.Popen(
                [*_client_command(self.target), "--unbuffered"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert self.process.stdout is not None and self.process.stderr is not None
            self.stdout = self.process.stdout
            self.stderr = self.process.stderr
            self._start_stream_reader("stdout", self.stdout)
            self._start_stream_reader("stderr", self.stderr)
            # MariaDB releases LOCK TABLES locks when START TRANSACTION begins.
            # Keep the named lock and the SERIALIZABLE transaction on this same
            # client; the transaction's reads acquire the InnoDB row/gap and
            # metadata locks needed by the fixed pilot-table preflight.
            self._execute_with_marker("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            self._execute_with_marker("START TRANSACTION")
            self._transaction_started = True
            lock_output = self._execute_with_marker(
                f"SELECT GET_LOCK({_sql_literal(self.lock_name)}, 0)"
            )
            if lock_output.strip() != "1":
                raise StagingApplyError("staging coordination lock could not be acquired")
            self._lock_acquired = True
            self._lock_state = "ACQUIRED"
            self.lock_mode = "named_get_lock_serializable_transaction"
            return self
        except (OSError, StagingApplyError):
            self._close(success=False)
            raise

    def _start_stream_reader(self, name: str, stream: BinaryIO) -> None:
        reader = threading.Thread(
            target=self._drain_stream,
            args=(name, stream),
            name=f"netlab-staging-{name}-reader",
            daemon=True,
        )
        self._stream_readers[name] = reader
        reader.start()

    def _drain_stream(self, name: str, stream: BinaryIO) -> None:
        read_chunk = getattr(stream, "read1", None) or stream.read
        try:
            while chunk := read_chunk(64 * 1024):
                with self._stream_lock:
                    self._stream_buffers[name].extend(chunk)
        except (EOFError, OSError, RuntimeError, ValueError) as exc:
            with self._stream_lock:
                self._stream_errors[name] = exc

    def _abort_stdin_transport(self, reason: str) -> None:
        self._transport_abort_reason = reason
        if self._transaction_started:
            self._commit_state = "UNKNOWN"
        if self._lock_acquired:
            self._lock_state = "UNKNOWN"
        process = self.process
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError as exc:
                self._transport_kill_error = exc

    def _release_stdin_write_lock(self) -> None:
        lock = getattr(self, "_stdin_write_lock", None)
        owner = getattr(self, "_stdin_write_lock_owner", None)
        if lock is not None and owner == threading.get_ident():
            self._stdin_write_lock_owner = None
            lock.release()

    def _write_stdin_bounded(self, data: bytes, *, deadline: float, flush: bool = False) -> None:
        self._assert_alive()
        process = self.process
        assert process is not None and process.stdin is not None
        lock = getattr(self, "_stdin_write_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._stdin_write_lock = lock
            self._stdin_write_lock_owner = None
        if not lock.acquire(blocking=False):
            raise StagingApplyError("locked staging session rejected concurrent stdin write")
        self._stdin_write_lock_owner = threading.get_ident()
        done = threading.Event()
        errors: list[BaseException] = []

        def write() -> None:
            try:
                written = process.stdin.write(data)
                if written != len(data):
                    raise OSError("locked staging session stdin short write")
                if flush:
                    process.stdin.flush()
            except (EOFError, OSError, RuntimeError, ValueError) as exc:
                errors.append(exc)
            finally:
                done.set()

        writer = threading.Thread(
            target=write,
            name="netlab-staging-stdin-writer",
            daemon=True,
        )
        self._active_stdin_writer = writer
        try:
            writer.start()
        except RuntimeError as exc:
            self._active_stdin_writer = None
            self._release_stdin_write_lock()
            raise StagingApplyError("locked staging session stdin writer could not start") from exc
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not done.wait(timeout=remaining):
            self._abort_stdin_transport("stdin write deadline exceeded")
            writer.join(timeout=1.0)
            if not writer.is_alive():
                self._active_stdin_writer = None
                self._release_stdin_write_lock()
            raise StagingApplyError("locked staging session stdin write timed out")
        self._active_stdin_writer = None
        self._release_stdin_write_lock()
        if errors:
            raise StagingApplyError("locked staging session stdin write failed") from errors[0]

    def _assert_alive(self) -> None:
        transport_abort_reason = getattr(self, "_transport_abort_reason", None)
        if transport_abort_reason is not None:
            raise StagingApplyError(
                f"locked staging session transport aborted: {transport_abort_reason}"
            )
        if self.process is None or self.process.poll() is not None:
            raise StagingApplyError("locked staging session exited")
        if self.process.stdin is None:
            raise StagingApplyError("locked staging session is not writable")

    def assert_alive(self) -> None:
        self._assert_alive()

    def _read_new_output(self) -> bytes:
        with self._stream_lock:
            error = self._stream_errors.get("stdout")
            if error is not None:
                raise StagingApplyError("locked staging session stdout reader failed") from error
            return bytes(self._stream_buffers["stdout"][self._output_offset :])

    def _stderr_text(self) -> str:
        with self._stream_lock:
            error = self._stream_errors.get("stderr")
            if error is not None:
                raise StagingApplyError("locked staging session stderr reader failed") from error
            return bytes(self._stream_buffers["stderr"]).decode("utf-8", "replace").strip()

    def _join_stream_readers(self, timeout: float) -> None:
        deadline = time.monotonic() + max(timeout, 0.0)
        for reader in self._stream_readers.values():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            reader.join(timeout=remaining)

    def _wait_for_marker(self, marker: str, *, deadline: float | None = None) -> str:
        marker_bytes = marker.encode("ascii")
        if deadline is None:
            deadline = time.monotonic() + self.target.timeout_seconds

        def marker_bounds(data: bytes) -> tuple[int, int] | None:
            consumed = 0
            for line in data.splitlines(keepends=True):
                if not line.endswith(b"\n"):
                    continue
                if line.strip() == marker_bytes:
                    return consumed, consumed + len(line)
                consumed += len(line)
            return None

        while time.monotonic() < deadline:
            data = self._read_new_output()
            with self._stream_lock:
                stderr_error = self._stream_errors.get("stderr")
            if stderr_error is not None:
                raise StagingApplyError("locked staging session stderr reader failed") from stderr_error
            bounds = marker_bounds(data)
            if bounds is not None:
                start, consumed = bounds
                self._output_offset += consumed
                return data[:start].decode("utf-8", "replace")
            if self.process is None:
                raise StagingApplyError("locked staging session exited")
            if self.process.poll() is not None:
                self._join_stream_readers(min(1.0, max(0.0, deadline - time.monotonic())))
                data = self._read_new_output()
                bounds = marker_bounds(data)
                if bounds is not None:
                    start, consumed = bounds
                    self._output_offset += consumed
                    return data[:start].decode("utf-8", "replace")
                error = self._stderr_text()
                if error:
                    raise StagingApplyError(f"locked staging session query failed: {error[-500:]}")
                raise StagingApplyError("locked staging session exited")
            time.sleep(0.02)
        raise StagingApplyError("locked staging session query timed out")

    def _execute_with_marker(self, sql: str, *, deadline: float | None = None) -> str:
        self._assert_alive()
        assert self.process is not None and self.process.stdin is not None
        if deadline is None:
            deadline = time.monotonic() + self.target.timeout_seconds
        self._query_number += 1
        marker = f"{self._MARKER_PREFIX}{self._query_number}__"
        payload = (sql.rstrip(";") + ";\n" + f"SELECT '{marker}';\n").encode("utf-8")
        self._write_stdin_bounded(payload, deadline=deadline, flush=True)
        output = self._wait_for_marker(marker, deadline=deadline)
        error = self._stderr_text()
        if error:
            raise StagingApplyError(f"locked staging session query failed: {error[-500:]}")
        return output

    def run_candidate(
        self,
        handle: BinaryIO,
        *,
        audit_table_exists: bool,
        expected_identity: dict[str, Any] | None = None,
    ) -> str:
        self._assert_alive()
        assert self.process is not None and self.process.stdin is not None
        deadline = time.monotonic() + self.target.timeout_seconds
        try:
            digest = hashlib.sha256()
            raw_size = 0
            handle.seek(0)
            prefix = handle.read(4 * 1024 * 1024)
            digest.update(prefix)
            raw_size += len(prefix)
            create_start = prefix.find(b"CREATE TABLE `oc_netlab_transfer_audit`")
            if create_start < 0 and audit_table_exists:
                raise StagingApplyError("candidate audit-table DDL is missing")
            if create_start < 0:
                ddl_end = 0
            else:
                ddl_end = prefix.find(b";", create_start)
                if ddl_end < 0:
                    raise StagingApplyError("candidate audit-table DDL is incomplete")
                ddl_end += 1
            initial = prefix[:ddl_end] if not audit_table_exists else prefix[:create_start]
            if initial:
                self._write_stdin_bounded(initial, deadline=deadline)
            pending = b""

            def write_filtered(data: bytes, *, final: bool = False) -> None:
                nonlocal pending
                pending += data
                lines = pending.splitlines(keepends=True)
                if not final and lines and not lines[-1].endswith((b"\n", b"\r")):
                    pending = lines.pop()
                else:
                    pending = b""
                ready = []
                for line in lines:
                    normalized = line.strip().upper()
                    if normalized.startswith(b"LOCK TABLES ") or normalized == b"UNLOCK TABLES;":
                        raise StagingApplyError("candidate contains unsupported table-lock statement")
                    ready.append(line)
                if ready:
                    self._write_stdin_bounded(b"".join(ready), deadline=deadline)

            write_filtered(prefix[ddl_end:])
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                raw_size += len(chunk)
                write_filtered(chunk)
            write_filtered(b"", final=True)
            observed_identity = {"size": raw_size, "sha256": digest.hexdigest()}
            if expected_identity is not None and observed_identity != expected_identity:
                raise StagingApplyError("candidate bytes changed during locked execution")
            self._write_stdin_bounded(b"", deadline=deadline, flush=True)
            output = self._execute_with_marker("SELECT 1", deadline=deadline)
            if expected_identity is not None and _handle_identity(handle) != expected_identity:
                raise StagingApplyError("candidate snapshot changed after execution")
            return output
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise StagingApplyError("locked candidate execution could not complete") from exc

    def rollback_transaction(self, before: dict[str, Any]) -> dict[str, Any]:
        self._assert_alive()
        auto_increment = before.get("auto_increment")
        if not isinstance(auto_increment, dict):
            raise StagingApplyError("rollback metadata has no AUTO_INCREMENT state")
        expected_tables = tuple(self.tables)
        if (
            not expected_tables
            or len(set(expected_tables)) != len(expected_tables)
            or set(auto_increment) != set(expected_tables)
        ):
            raise StagingApplyError("rollback AUTO_INCREMENT state does not cover the locked pilot tables")
        for table in expected_tables:
            value = auto_increment[table]
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
                raise StagingApplyError(f"rollback AUTO_INCREMENT state is invalid for {table}")
        self._execute_with_marker("ROLLBACK")
        self._transaction_started = False
        # ALTER TABLE implicitly commits in MariaDB. Re-issue the same
        # transaction contract before semantic rollback read-back.
        for table in expected_tables:
            value = auto_increment[table]
            if value is not None:
                self._execute_with_marker(f"ALTER TABLE `{table}` AUTO_INCREMENT = {value}")
        self._execute_with_marker("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        self._execute_with_marker("START TRANSACTION")
        self._transaction_started = True
        self._assert_alive()
        return {"status": "PASS", "checks": {"transaction_rolled_back": True, "auto_increment_restored": True}}

    def query(self, sql: str) -> str:
        return self._execute_with_marker(sql)

    def _close(self, *, success: bool) -> None:
        process = self.process
        transaction_started_at_close = self._transaction_started
        transport_abort_reason = getattr(self, "_transport_abort_reason", None)
        cleanup_status: tuple[str, str] | None = None
        cleanup_failures: list[str] = []
        returncode: int | None = None

        cleanup_priority = {
            "COMMIT_AMBIGUOUS_BLOCKED": 5,
            "ROLLBACK_AMBIGUOUS_BLOCKED": 5,
            "COMMITTED_LOCK_RELEASE_BLOCKED": 4,
            "COMMITTED_SESSION_CLEANUP_BLOCKED": 3,
            "COORDINATION_LOCK_RELEASE_BLOCKED": 2,
            "SESSION_CLEANUP_BLOCKED": 1,
        }

        def record_cleanup(status: str, message: str) -> None:
            nonlocal cleanup_status
            if cleanup_status is None:
                cleanup_status = (status, message)
                return
            if cleanup_priority.get(status, 0) > cleanup_priority.get(cleanup_status[0], 0):
                cleanup_failures.append(f"{cleanup_status[0]}: {cleanup_status[1]}")
                cleanup_status = (status, message)
            else:
                cleanup_failures.append(f"{status}: {message}")

        transport_kill_error = getattr(self, "_transport_kill_error", None)
        if transport_kill_error is not None:
            record_cleanup(
                "COMMITTED_SESSION_CLEANUP_BLOCKED"
                if self._commit_state == "COMMITTED"
                else "SESSION_CLEANUP_BLOCKED",
                f"locked staging session abort kill failed: {transport_kill_error}",
            )

        def state_error(status: str, message: str) -> StagingSessionStateError:
            if cleanup_failures:
                message = f"{message}; additional cleanup failures: {' | '.join(cleanup_failures)}"
            return StagingSessionStateError(
                status,
                message,
                commit_state=self._commit_state,
                lock_state=self._lock_state,
            )

        try:
            if process is not None and process.poll() is None and process.stdin is not None:
                if self._transaction_started:
                    if success:
                        self._commit_state = "UNKNOWN"
                        try:
                            self._execute_with_marker("COMMIT")
                            self._transaction_started = False
                            self._commit_state = "COMMITTED"
                        except StagingApplyError as exc:
                            record_cleanup(
                                "COMMIT_AMBIGUOUS_BLOCKED",
                                f"commit outcome is unknown: {exc}",
                            )
                    else:
                        try:
                            self._execute_with_marker("ROLLBACK")
                            self._transaction_started = False
                            self._commit_state = "ROLLED_BACK"
                        except StagingApplyError as exc:
                            record_cleanup(
                                "ROLLBACK_AMBIGUOUS_BLOCKED",
                                f"rollback outcome is unknown: {exc}",
                            )
                if self._lock_acquired and process.poll() is None:
                    self._lock_state = "UNKNOWN"
                    try:
                        release_output = self._execute_with_marker(
                            f"SELECT RELEASE_LOCK({_sql_literal(self.lock_name)})"
                        )
                        if release_output.strip() != "1":
                            raise StagingApplyError("staging coordination lock could not be released")
                        self._lock_acquired = False
                        self._lock_state = "RELEASED"
                    except StagingApplyError as exc:
                        if self._commit_state == "COMMITTED":
                            record_cleanup(
                                "COMMITTED_LOCK_RELEASE_BLOCKED",
                                f"database commit completed but coordination lock release is unverified: {exc}",
                            )
                        else:
                            record_cleanup(
                                "COORDINATION_LOCK_RELEASE_BLOCKED",
                                f"coordination lock release is unverified: {exc}",
                            )
                if cleanup_status is not None and process.poll() is None:
                    try:
                        process.kill()
                    except OSError as exc:
                        record_cleanup(
                            "COMMITTED_SESSION_CLEANUP_BLOCKED"
                            if self._commit_state == "COMMITTED"
                            else "SESSION_CLEANUP_BLOCKED",
                            f"locked staging session could not be killed after cleanup failure: {exc}",
                        )
                try:
                    process.stdin.close()
                except (OSError, ValueError) as exc:
                    record_cleanup(
                        "COMMITTED_SESSION_CLEANUP_BLOCKED"
                        if self._commit_state == "COMMITTED"
                        else "SESSION_CLEANUP_BLOCKED",
                        f"locked staging session stdin could not be closed: {exc}",
                    )
                try:
                    returncode = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except OSError as exc:
                        record_cleanup(
                            "COMMITTED_SESSION_CLEANUP_BLOCKED"
                            if self._commit_state == "COMMITTED"
                            else "SESSION_CLEANUP_BLOCKED",
                            f"locked staging session could not be killed after cleanup timeout: {exc}",
                        )
                    try:
                        returncode = process.wait(timeout=10)
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        record_cleanup(
                            "COMMITTED_SESSION_CLEANUP_BLOCKED"
                            if self._commit_state == "COMMITTED"
                            else "SESSION_CLEANUP_BLOCKED",
                            f"locked staging session did not exit after cleanup: {exc}",
                        )
            elif process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except (OSError, ValueError) as exc:
                    record_cleanup(
                        "COMMITTED_SESSION_CLEANUP_BLOCKED"
                        if self._commit_state == "COMMITTED"
                        else "SESSION_CLEANUP_BLOCKED",
                        f"locked staging session stdin could not be closed: {exc}",
                    )
                try:
                    returncode = process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired) as exc:
                    record_cleanup(
                        "COMMITTED_SESSION_CLEANUP_BLOCKED"
                        if self._commit_state == "COMMITTED"
                        else "SESSION_CLEANUP_BLOCKED",
                        f"locked staging session could not be reaped: {exc}",
                    )
        finally:
            closed_streams: set[str] = set()

            def cleanup_failure(message: str) -> tuple[str, str]:
                return (
                    "COMMITTED_SESSION_CLEANUP_BLOCKED"
                    if self._commit_state == "COMMITTED"
                    else "SESSION_CLEANUP_BLOCKED",
                    message,
                )

            def close_stream(name: str, stream: BinaryIO | None) -> None:
                nonlocal cleanup_status
                if stream is None or name in closed_streams:
                    return
                closed_streams.add(name)
                try:
                    stream.close()
                except (OSError, ValueError) as exc:
                    record_cleanup(*cleanup_failure(
                        f"locked staging session {name} stream close failed: {exc}"
                    ))

            writer = getattr(self, "_active_stdin_writer", None)
            if writer is not None and writer.is_alive() and process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except (OSError, ValueError) as exc:
                    record_cleanup(*cleanup_failure(
                        f"locked staging session stdin could not be closed: {exc}"
                    ))
                writer.join(timeout=10)
                if writer.is_alive():
                    writer.join(timeout=1)
                    if writer.is_alive():
                        record_cleanup(*cleanup_failure(
                            "locked staging session stdin writer did not exit"
                        ))
            self._release_stdin_write_lock()

            for name, reader in getattr(self, "_stream_readers", {}).items():
                reader.join(timeout=10)
                if reader.is_alive():
                    close_stream(name, self.stdout if name == "stdout" else self.stderr)
                    reader.join(timeout=1)
                    if reader.is_alive():
                        record_cleanup(*cleanup_failure(
                            f"locked staging session {name} reader did not exit"
                        ))

            for name, error in getattr(self, "_stream_errors", {}).items():
                if error is not None:
                    record_cleanup(*cleanup_failure(
                        f"locked staging session {name} reader failed during cleanup: {error}"
                    ))

            close_stream("stdout", self.stdout)
            close_stream("stderr", self.stderr)
            self.process = None
            self._transaction_started = False
        if not success and transaction_started_at_close and self._commit_state not in {"COMMITTED", "ROLLED_BACK"}:
            record_cleanup(
                "ROLLBACK_AMBIGUOUS_BLOCKED",
                "transaction outcome is unknown because the session exited before rollback",
            )
        if self._lock_acquired and self._lock_state != "RELEASED":
            record_cleanup(
                "COMMITTED_LOCK_RELEASE_BLOCKED"
                if self._commit_state == "COMMITTED"
                else "COORDINATION_LOCK_RELEASE_BLOCKED",
                "coordination lock release is unverified because the session exited before release",
            )
        if transport_abort_reason is not None:
            if transaction_started_at_close or self._commit_state == "UNKNOWN":
                record_cleanup(
                    "ROLLBACK_AMBIGUOUS_BLOCKED",
                    (
                        "transaction outcome is unknown after locked session transport abort: "
                        f"{transport_abort_reason}"
                    ),
                )
            else:
                record_cleanup(
                    "SESSION_CLEANUP_BLOCKED",
                    f"locked staging session transport aborted: {transport_abort_reason}",
                )
        if success and self._commit_state != "COMMITTED":
            record_cleanup(
                "COMMIT_AMBIGUOUS_BLOCKED",
                "successful apply exited without a proven COMMIT",
            )
        elif success and self._commit_state == "COMMITTED" and self._lock_state != "RELEASED":
            record_cleanup(
                "COMMITTED_LOCK_RELEASE_BLOCKED",
                "database commit completed but coordination lock release is unverified",
            )
        elif success and self._commit_state == "COMMITTED" and returncode not in {None, 0}:
            record_cleanup(
                "COMMITTED_SESSION_CLEANUP_BLOCKED",
                "database commit completed but the session exited abnormally",
            )
        if cleanup_status is not None:
            raise state_error(*cleanup_status)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._close(success=exc_type is None)



def _scalar(
    target: StagingTarget,
    sql: str,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> str:
    output = query_runner(sql) if query_runner is not None else _run_sql(target, sql)
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise StagingApplyError("staging scalar query returned an unexpected row count")
    return lines[0]


def _query_lines(
    target: StagingTarget,
    sql: str,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> list[list[str]]:
    output = query_runner(sql) if query_runner is not None else _run_sql(target, sql)
    return [line.split("\t") for line in output.splitlines() if line.strip()]


def _decode_hex_field(value: str) -> str:
    if not value or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        return value
    try:
        return bytes.fromhex(value).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return value


def _decode_hex_fields(row: list[str], indexes: set[int]) -> list[str]:
    return [_decode_hex_field(value) if index in indexes else value for index, value in enumerate(row)]


def _count(
    target: StagingTarget,
    sql: str,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> int:
    value = _scalar(target, sql, query_runner=query_runner)
    try:
        result = int(value)
    except ValueError as exc:
        raise StagingApplyError("staging count query returned non-integer") from exc
    if result < 0:
        raise StagingApplyError("staging count query returned a negative value")
    return result


def _sql_literal(value: str) -> str:
    if "\x00" in value:
        raise StagingApplyError("candidate identifier contains NUL")
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _call_query_lines(
    target: StagingTarget,
    sql: str,
    query_runner: Callable[[str], str] | None,
) -> list[list[str]]:
    if query_runner is None:
        return _query_lines(target, sql)
    return _query_lines(target, sql, query_runner=query_runner)


def _call_count(
    target: StagingTarget,
    sql: str,
    query_runner: Callable[[str], str] | None,
) -> int:
    if query_runner is None:
        return _count(target, sql)
    return _count(target, sql, query_runner=query_runner)


_PILOT_LOCK_TABLES = (
    "oc_product",
    "oc_product_description",
    "oc_product_to_category",
    "oc_product_image",
    "oc_netlab_transfer_audit",
)
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_CANDIDATE_SQL_BYTES = 4 * 1024 * 1024 * 1024
_MAX_RECORDS = 100_000
_MAX_RECORDS_BYTES = 768 * 1024 * 1024
_MAX_CANDIDATE_ENTRIES = 100_000
_MAX_RECORD_LINE_BYTES = 16 * 1024 * 1024
_MAX_CANONICAL_NUMBER_DIGITS = 128
_MAX_CANONICAL_NUMBER_EXPONENT = 128


def _load_records(
    candidate_sql: Path,
    *,
    expected_identity: dict[str, Any] | None = None,
    deadline_check: Callable[[], None] | None = None,
) -> list[dict[str, Any]]:
    records_path = candidate_sql.parent / "RECORDS.jsonl"
    records: list[dict[str, Any]] = []
    seen_skus: set[str] = set()
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        before_path_stat = os.lstat(records_path)
        if not stat.S_ISREG(before_path_stat.st_mode):
            raise StagingApplyError("candidate RECORDS.jsonl is not a regular file")
        with records_path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(before_handle_stat):
                raise StagingApplyError("candidate RECORDS.jsonl changed before reading")
            while True:
                if deadline_check is not None:
                    deadline_check()
                line = handle.readline(_MAX_RECORD_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > _MAX_RECORD_LINE_BYTES:
                    raise StagingApplyError("candidate RECORDS.jsonl exceeds configured bounds")
                total_bytes += len(line)
                if total_bytes > _MAX_RECORDS_BYTES:
                    raise StagingApplyError("candidate RECORDS.jsonl exceeds configured bounds")
                digest.update(line)
                if not line.strip():
                    continue
                if len(records) >= _MAX_RECORDS:
                    raise StagingApplyError("candidate RECORDS.jsonl exceeds record-count bound")
                row = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
                if not isinstance(row, dict):
                    raise StagingApplyError("candidate record is not an object")
                sku = row.get("target_sku")
                action = row.get("action")
                if not isinstance(sku, str) or not sku or sku in seen_skus:
                    raise StagingApplyError("candidate has duplicate or invalid target SKU")
                if action not in {"update", "create"}:
                    raise StagingApplyError("candidate has unsupported action")
                seen_skus.add(sku)
                records.append(row)
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(records_path)
    except StagingApplyError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise StagingApplyError("candidate RECORDS.jsonl is invalid") from exc
    if (
        _stable_file_stat_key(before_path_stat) != _stable_file_stat_key(after_path_stat)
        or _stable_file_stat_key(before_handle_stat) != _stable_file_stat_key(after_handle_stat)
        or total_bytes != before_path_stat.st_size
    ):
        raise StagingApplyError("candidate RECORDS.jsonl changed during reading")
    observed_identity = {"size": total_bytes, "sha256": digest.hexdigest()}
    if expected_identity is not None:
        expected = {"size": expected_identity.get("size"), "sha256": expected_identity.get("sha256")}
        if expected_identity.get("path", "RECORDS.jsonl") != "RECORDS.jsonl" or observed_identity != expected:
            raise StagingApplyError("candidate RECORDS.jsonl identity changed")
    if not records:
        raise StagingApplyError("candidate has no records")
    return records


def _semantic_digest(
    target: StagingTarget,
    table: str,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    if table not in {"oc_product_to_category", "oc_product_image"}:
        raise StagingApplyError(f"semantic digest table is not allowlisted: {table}")
    if table == "oc_product_to_category":
        rows = _call_query_lines(
            target,
            "SELECT `product_id`, `category_id` FROM `oc_product_to_category`",
            query_runner,
        )
    else:
        rows = [
            _decode_hex_fields(row, {2})
            for row in _call_query_lines(
                target,
                "SELECT `product_image_id`, `product_id`, HEX(`image`), `sort_order` "
                "FROM `oc_product_image`",
                query_runner=query_runner,
            )
        ]
    canonical = json.dumps(sorted(rows), ensure_ascii=False, separators=(",", ":"))
    return {"rows": len(rows), "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def _category_relation_rows(
    target: StagingTarget,
    product_ids: list[int] | None = None,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> set[tuple[int, int]]:
    ids_clause = ""
    if product_ids:
        ids_clause = f" WHERE `product_id` IN ({','.join(str(product_id) for product_id in sorted(set(product_ids)))})"
    elif product_ids == []:
        return set()
    rows: set[tuple[int, int]] = set()
    for row in _call_query_lines(
        target,
        "SELECT `product_id`, `category_id` FROM `oc_product_to_category`" + ids_clause,
        query_runner=query_runner,
    ):
        if len(row) != 2:
            raise StagingApplyError("category relation row has an unexpected field count")
        try:
            product_id, category_id = int(row[0]), int(row[1])
        except (TypeError, ValueError) as exc:
            raise StagingApplyError("category relation row contains non-numeric IDs") from exc
        if product_id <= 0 or category_id <= 0:
            raise StagingApplyError("category relation row contains non-positive IDs")
        rows.add((product_id, category_id))
    return rows


def _category_relations_for_records(
    records: list[dict[str, Any]],
    product_ids: dict[str, int],
) -> set[tuple[int, int]]:
    relations: set[tuple[int, int]] = set()
    for record in records:
        payload = record.get("target_payload")
        if not isinstance(payload, dict) or "target_category_id" not in payload:
            continue
        try:
            category_id = int(payload["target_category_id"])
        except (TypeError, ValueError) as exc:
            raise StagingApplyError("candidate target category ID is invalid") from exc
        product_id = product_ids.get(record.get("target_sku"))
        if product_id is None or category_id <= 0:
            raise StagingApplyError("candidate category relation target is invalid")
        relations.add((product_id, category_id))
    return relations


def _semantic_digest_without_category_relations(
    target: StagingTarget,
    excluded: set[tuple[int, int]],
) -> dict[str, Any]:
    rows = [
        (int(row[0]), int(row[1]))
        for row in _call_query_lines(target, "SELECT `product_id`, `category_id` FROM `oc_product_to_category`")
        if len(row) == 2 and (int(row[0]), int(row[1])) not in excluded
    ]
    canonical = json.dumps(sorted(rows), ensure_ascii=False, separators=(",", ":"))
    return {"rows": len(rows), "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def _database_table_engines(
    target: StagingTarget,
    *,
    tables: tuple[str, ...] | None = None,
    query_runner: Callable[[str], str] | None = None,
) -> list[tuple[str, str]]:
    requested = tuple(_PILOT_LOCK_TABLES if tables is None else tables)
    if (
        not requested
        or len(set(requested)) != len(requested)
        or any(re.fullmatch(r"[A-Za-z0-9_]+", table) is None for table in requested)
    ):
        raise StagingApplyError("database engine inventory table allowlist is invalid")
    table_literals = ", ".join(_sql_literal(table) for table in requested)
    rows = _call_query_lines(
        target,
        "SELECT `table_name`, `engine` FROM information_schema.tables "
        "WHERE table_schema=DATABASE() AND table_type='BASE TABLE' "
        f"AND `table_name` IN ({table_literals}) ORDER BY `table_name`",
        query_runner,
    )
    table_engines: list[tuple[str, str]] = []
    requested_set = set(requested)
    for row in rows:
        if len(row) != 2 or not row[0] or not row[1] or re.fullmatch(r"[A-Za-z0-9_]+", row[0]) is None:
            raise StagingApplyError("database engine inventory is invalid")
        if row[0] not in requested_set:
            raise StagingApplyError("database engine inventory returned an out-of-scope table")
        table_engines.append((row[0], row[1].upper()))
    if {table for table, _ in table_engines} != requested_set or len(table_engines) != len(requested):
        missing = sorted(requested_set - {table for table, _ in table_engines})
        if missing:
            raise StagingApplyError(f"database engine inventory is missing pilot table: {missing[0]}")
        raise StagingApplyError("database engine inventory contains duplicate pilot table rows")
    return table_engines


def _database_engines(target: StagingTarget) -> list[str]:
    return sorted({engine for _, engine in _database_table_engines(target)})


def _competing_writer_sessions(
    target: StagingTarget,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> int:
    return _call_count(
        target,
        "SELECT COUNT(*) FROM information_schema.processlist "
        "WHERE db=DATABASE() AND id <> CONNECTION_ID() "
        "AND command IN ('Query','Execute') "
        "AND info REGEXP '^[[:space:]]*(INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE|DROP|TRUNCATE|LOAD|RENAME)'",
        query_runner,
    )


_QUERY_BATCH_SIZE = 500


def _batches(values: list[Any], size: int = _QUERY_BATCH_SIZE) -> list[list[Any]]:
    if size <= 0:
        raise StagingApplyError("query batch size must be positive")
    return [values[offset : offset + size] for offset in range(0, len(values), size)]


def _affected_state_digest(
    target: StagingTarget,
    records: list[dict[str, Any]],
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    skus = sorted(record["target_sku"] for record in records)
    product_rows: list[list[str]] = []
    for batch in _batches(skus):
        literals = ",".join(_sql_literal(sku) for sku in batch)
        product_rows.extend(
            _decode_hex_fields(row, {1, 2, 9, 10}) for row in _call_query_lines(
                target,
                "SELECT `product_id`, HEX(`sku`), HEX(`model`), `quantity`, `price`, `weight`, `length`, "
                "`width`, `height`, HEX(`mpn`), HEX(`ean`), `status`, `noindex` "
                f"FROM `oc_product` WHERE `sku` IN ({literals})",
                query_runner=query_runner,
            )
        )
    product_ids = sorted({int(row[0]) for row in product_rows if len(row) == 13})
    description_rows: list[list[str]] = []
    for batch in _batches(product_ids):
        description_ids = ",".join(str(product_id) for product_id in batch)
        description_rows.extend(
            _decode_hex_fields(row, {2, 3}) for row in _call_query_lines(
                target,
                "SELECT `product_id`, `language_id`, HEX(`name`), HEX(`description`) "
                f"FROM `oc_product_description` WHERE `product_id` IN ({description_ids}) "
                "ORDER BY `product_id`, `language_id`, `name`, `description`",
                query_runner=query_runner,
            )
        )
    material = {"products": sorted(product_rows), "descriptions": sorted(description_rows)}
    canonical = json.dumps(material, ensure_ascii=False, separators=(",", ":"))
    return {
        "product_rows": len(product_rows),
        "description_rows": len(description_rows),
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _auto_increment_state(
    target: StagingTarget,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, int | None]:
    state: dict[str, int | None] = {}
    for table in _PILOT_LOCK_TABLES:
        if re.fullmatch(r"[A-Za-z0-9_]+", table) is None:
            raise StagingApplyError("database table inventory contains an unsafe identifier")
        rows = _call_query_lines(
            target,
            "SELECT COALESCE(CAST(`auto_increment` AS CHAR), 'NULL') "
            "FROM information_schema.tables WHERE table_schema=DATABASE() "
            f"AND table_name={_sql_literal(table)}",
            query_runner=query_runner,
        )
        if len(rows) != 1 or len(rows[0]) != 1:
            raise StagingApplyError(f"could not read AUTO_INCREMENT state for {table}")
        token = rows[0][0]
        if token == "NULL":
            state[table] = None
            continue
        if not re.fullmatch(r"[0-9]+", token):
            raise StagingApplyError(f"invalid AUTO_INCREMENT state for {table}")
        state[table] = int(token)
    return state


_AUDIT_TABLE_COLLATION = "utf8mb4_general_ci"
_AUDIT_COLUMN_CONTRACT = (
    ("transfer_id", "bigint", "NO", "auto_increment", "", ""),
    ("run_id", "varchar(128)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("supplier_item_id", "varchar(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_sku", "varchar(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("target_product_id", "int", "NO", "", "", ""),
    ("action", "varchar(16)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_kind", "varchar(32)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("verification_status", "varchar(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("manufacturer_verified", "tinyint(1)", "NO", "", "", ""),
    ("source_url", "text", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_raw_hash", "char(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_fetched_at", "varchar(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_artifact_path", "text", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_artifact_sha256", "char(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("matches_artifact_sha256", "char(64)", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("source_snapshot_json", "longtext", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("properties_json", "longtext", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("image_urls_json", "longtext", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("category_json", "longtext", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("after_json", "longtext", "NO", "", "utf8mb4", _AUDIT_TABLE_COLLATION),
    ("transferred_at", "datetime", "NO", "", "", ""),
)
_AUDIT_INDEX_CONTRACT = (
    ("PRIMARY", "0", "1", "transfer_id", "BTREE"),
    ("idx_netlab_transfer_target", "1", "1", "target_product_id", "BTREE"),
    ("uq_netlab_transfer_run_sku", "0", "1", "run_id", "BTREE"),
    ("uq_netlab_transfer_run_sku", "0", "2", "source_sku", "BTREE"),
)


def _validate_audit_table_schema(
    target: StagingTarget,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> None:
    table_rows = _call_query_lines(
        target,
        "SELECT `engine`, COALESCE(`table_collation`, '') FROM information_schema.tables "
        "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
        "AND table_type='BASE TABLE'",
        query_runner,
    )
    if len(table_rows) != 1 or len(table_rows[0]) != 2:
        raise StagingApplyError("existing audit table metadata is missing or ambiguous")
    engine, collation = table_rows[0]
    if engine.upper() != "INNODB":
        raise StagingApplyError("existing audit table engine must be InnoDB")
    if collation.casefold() != _AUDIT_TABLE_COLLATION:
        raise StagingApplyError(
            f"existing audit table collation must be {_AUDIT_TABLE_COLLATION}"
        )

    column_rows = _call_query_lines(
        target,
        "SELECT `column_name`, `column_type`, `is_nullable`, `extra`, "
        "COALESCE(`character_set_name`, ''), COALESCE(`collation_name`, '') "
        "FROM information_schema.columns WHERE table_schema=DATABASE() "
        "AND table_name='oc_netlab_transfer_audit' ORDER BY ordinal_position",
        query_runner,
    )
    actual_columns: list[tuple[str, str, str, str, str, str]] = []
    for row in column_rows:
        if len(row) != 6:
            raise StagingApplyError("existing audit table column metadata is invalid")
        name, column_type, nullable, extra, charset, column_collation = row
        normalized_type = column_type.casefold()
        normalized_type = re.sub(r"^(bigint|int)\(\d+\)$", r"\1", normalized_type)
        actual_columns.append(
            (
                name,
                normalized_type,
                nullable.upper(),
                extra.casefold(),
                charset.casefold(),
                column_collation.casefold(),
            )
        )
    if tuple(actual_columns) != _AUDIT_COLUMN_CONTRACT:
        raise StagingApplyError("existing audit table columns do not match the allowlist")

    index_rows = _call_query_lines(
        target,
        "SELECT `index_name`, CAST(`non_unique` AS CHAR), CAST(`seq_in_index` AS CHAR), "
        "`column_name`, `index_type` FROM information_schema.statistics "
        "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
        "ORDER BY CASE WHEN `index_name`='PRIMARY' THEN 0 ELSE 1 END, "
        "`index_name`, `seq_in_index`, `column_name`",
        query_runner,
    )
    if any(len(row) != 5 for row in index_rows):
        raise StagingApplyError("existing audit table index metadata is invalid")
    actual_indexes = tuple(tuple(row) for row in index_rows)
    if actual_indexes != _AUDIT_INDEX_CONTRACT:
        raise StagingApplyError("existing audit table keys do not match the allowlist")


def _require_transactional_pilot(before: dict[str, Any]) -> None:
    engines = {str(engine).upper() for engine in before.get("engines", [])}
    if engines != {"INNODB"} or before.get("consistency_strategy") != "single_transaction":
        rendered = ", ".join(sorted(engines)) or "unknown"
        raise StagingApplyError(
            "INNODB_REQUIRED: staging pilot accepts only InnoDB pilot tables; "
            f"detected engines={rendered}"
        )


def _preflight(
    target: StagingTarget,
    records: list[dict[str, Any]],
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    table_engines = _database_table_engines(
        target,
        tables=_PILOT_LOCK_TABLES,
        query_runner=query_runner,
    )
    engines = sorted({engine for _, engine in table_engines})
    consistency_strategy = "single_transaction"
    competing_writers = _competing_writer_sessions(target, query_runner=query_runner)
    if competing_writers:
        raise StagingApplyError(f"competing staging writer sessions detected: {competing_writers}")
    before = {
        "products": _call_count(target, "SELECT COUNT(*) FROM `oc_product`", query_runner),
        "descriptions": _call_count(target, "SELECT COUNT(*) FROM `oc_product_description`", query_runner),
        "categories": _call_count(target, "SELECT COUNT(*) FROM `oc_product_to_category`", query_runner),
        "images": _call_count(target, "SELECT COUNT(*) FROM `oc_product_image`", query_runner),
        "audit_table": _call_count(
            target,
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit'",
            query_runner,
        ),
        "categories_digest": _semantic_digest(target, "oc_product_to_category", query_runner=query_runner),
        "images_digest": _semantic_digest(target, "oc_product_image", query_runner=query_runner),
        "engines": engines,
        "table_engines": table_engines,
        "consistency_strategy": consistency_strategy,
        "competing_writer_sessions": competing_writers,
        "auto_increment": _auto_increment_state(target, query_runner=query_runner),
    }
    if before["audit_table"]:
        _validate_audit_table_schema(target, query_runner=query_runner)
    run_id = records[0].get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise StagingApplyError("candidate records have no run_id")
    language_ids = {_record_language_id(record) for record in records}
    if len(language_ids) != 1:
        raise StagingApplyError("candidate records use multiple language IDs")
    before["language_id"] = next(iter(language_ids))

    create_skus = [record["target_sku"] for record in records if record["action"] == "create"]
    update_pairs: list[tuple[int, str]] = []
    for record in records:
        if record["action"] != "update":
            continue
        product_id = record.get("target_product_id")
        if not isinstance(product_id, int) or product_id <= 0:
            raise StagingApplyError(f"update record has invalid target product id: {record['target_sku']}")
        update_pairs.append((product_id, record["target_sku"]))
    if len(update_pairs) != len(set(update_pairs)):
        raise StagingApplyError("candidate contains duplicate update targets")
    before["affected_category_relations"] = sorted(
        _category_relation_rows(
            target,
            [product_id for product_id, _ in update_pairs],
            query_runner=query_runner,
        )
    )
    before["category_relations_snapshot"] = sorted(
        _category_relation_rows(target, query_runner=query_runner)
    )

    if create_skus:
        existing: set[str] = set()
        for batch in _batches(create_skus):
            create_literals = ",".join(_sql_literal(sku) for sku in batch)
            existing.update(
                _decode_hex_field(row[0])
                for row in _call_query_lines(
                    target,
                    f"SELECT HEX(`sku`) FROM `oc_product` WHERE `sku` IN ({create_literals})",
                    query_runner=query_runner,
                )
                if row
            )
        if existing:
            raise StagingApplyError(f"create SKU already exists in staging: {min(existing)}")

    if update_pairs:
        actual_rows: list[list[str]] = []
        for batch in _batches(update_pairs):
            predicates = " OR ".join(
                f"(`product_id`={product_id} AND `sku`={_sql_literal(sku)})"
                for product_id, sku in batch
            )
            actual_rows.extend(
                _decode_hex_fields(row, {1})
                for row in _call_query_lines(
                    target,
                    "SELECT `product_id`, HEX(`sku`), `status`, `noindex` "
                    f"FROM `oc_product` WHERE {predicates}",
                    query_runner=query_runner,
                )
            )
        actual = {(int(row[0]), row[1]) for row in actual_rows if len(row) == 4}
        expected = set(update_pairs)
        if actual != expected:
            missing = sorted(expected - actual, key=lambda item: item[1])
            extra = sorted(actual - expected, key=lambda item: item[1])
            detail = f"missing {missing[0][1]}" if missing else f"unexpected {extra[0][1]}"
            raise StagingApplyError(f"exact target SKU/product mismatch in staging: {detail}")
        before["update_flags"] = {
            row[1]: (row[2], row[3]) for row in actual_rows if len(row) == 4
        }
        product_to_sku = {int(row[0]): row[1] for row in actual_rows if len(row) == 4}
        description_rows: list[list[str]] = []
        for batch in _batches(sorted(product_to_sku)):
            description_ids = ",".join(str(product_id) for product_id in batch)
            description_rows.extend(
                _decode_hex_fields(row, {1, 2})
                for row in _call_query_lines(
                    target,
                    "SELECT `product_id`, HEX(`name`), HEX(`description`) FROM `oc_product_description` "
                    f"WHERE `product_id` IN ({description_ids}) "
                    f"AND `language_id`={before['language_id']}",
                    query_runner=query_runner,
                )
            )
        before["update_descriptions"] = {
            product_to_sku[int(row[0])]: (row[1], row[2])
            for row in description_rows
            if len(row) == 3 and int(row[0]) in product_to_sku
        }
    before["affected_state_digest"] = _affected_state_digest(
        target,
        records,
        query_runner=query_runner,
    )
    return before


def _backup_database(
    target: StagingTarget,
    backup_root: Path,
    *,
    before: dict[str, Any],
    consistency_strategy: str = "single_transaction",
    coordination_session: _LockedMysqlSession | None = None,
) -> Path:
    del target
    if consistency_strategy != "single_transaction":
        raise StagingApplyError("INNODB_REQUIRED: only the InnoDB transaction backup is supported")
    if coordination_session is None:
        raise StagingApplyError("before-state snapshot requires the active InnoDB coordination session")
    coordination_session.assert_alive()
    snapshot_path = backup_root / "before-state.json"
    try:
        with snapshot_path.open("x", encoding="utf-8", newline="\n") as handle:
            payload = json.dumps(before, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, TypeError, ValueError) as exc:
        try:
            snapshot_path.unlink()
        except OSError:
            pass
        raise StagingApplyError("InnoDB before-state snapshot could not be written") from exc
    coordination_session.assert_alive()
    return snapshot_path


def verify_restored_state(
    target: StagingTarget,
    before: dict[str, Any],
    records: list[dict[str, Any]] | None = None,
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    checks = {
        "products": _call_count(target, "SELECT COUNT(*) FROM `oc_product`", query_runner) == before["products"],
        "descriptions": _call_count(target, "SELECT COUNT(*) FROM `oc_product_description`", query_runner) == before["descriptions"],
        "categories": _semantic_digest(target, "oc_product_to_category", query_runner=query_runner) == before.get("categories_digest"),
        "images": _semantic_digest(target, "oc_product_image", query_runner=query_runner) == before.get("images_digest"),
        "audit_table": _call_count(
            target,
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit'",
            query_runner,
        ) == before["audit_table"],
    }
    if records is not None and "affected_state_digest" in before:
        checks["affected_state"] = _affected_state_digest(target, records, query_runner=query_runner) == before["affected_state_digest"]
    if "auto_increment" in before:
        checks["auto_increment"] = _auto_increment_state(target, query_runner=query_runner) == before["auto_increment"]
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise StagingApplyError(f"rollback semantic read-back failed: {', '.join(failed)}")
    return {"status": "PASS", "checks": checks}


_AUDIT_REQUIRED_RECORD_FIELDS = {
    "run_id",
    "supplier_item_id",
    "source_sku",
    "source_kind",
    "verification_status",
    "source_url",
    "source_raw_hash",
    "source_fetched_at",
    "source_artifact_path",
    "source_artifact_sha256",
    "matches_artifact_sha256",
    "source_snapshot_json",
    "properties_json",
    "image_urls_json",
    "category_json",
}


def _verify_audit_provenance(
    target: StagingTarget,
    records: list[dict[str, Any]],
    product_ids: dict[str, int],
    *,
    query_runner: Callable[[str], str] | None = None,
) -> int:
    if not all(_AUDIT_REQUIRED_RECORD_FIELDS.issubset(record) for record in records):
        return -1
    run_ids = {record["run_id"] for record in records}
    if len(run_ids) != 1:
        raise StagingApplyError("audit provenance records contain multiple run IDs")
    run_id = next(iter(run_ids))
    rows = [
        _decode_hex_fields(row, {1, 2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19})
        for row in _call_query_lines(
            target,
            "SELECT `transfer_id`, HEX(`run_id`), HEX(`supplier_item_id`), HEX(`source_sku`), "
            "`target_product_id`, HEX(`action`), HEX(`source_kind`), HEX(`verification_status`), "
            "`manufacturer_verified`, HEX(`source_url`), HEX(`source_raw_hash`), HEX(`source_fetched_at`), "
            "HEX(`source_artifact_path`), HEX(`source_artifact_sha256`), HEX(`matches_artifact_sha256`), "
            "HEX(`source_snapshot_json`), HEX(`properties_json`), HEX(`image_urls_json`), HEX(`category_json`), "
            "HEX(`after_json`) FROM `oc_netlab_transfer_audit` "
            f"WHERE `run_id`={_sql_literal(run_id)} ORDER BY `transfer_id`",
            query_runner=query_runner,
        )
    ]
    expected_by_item = {record["supplier_item_id"]: record for record in records}
    if len(rows) != len(records):
        raise StagingApplyError(f"audit provenance row count mismatch: {len(rows)} != {len(records)}")
    seen: set[str] = set()
    for row in rows:
        if len(row) != 20:
            raise StagingApplyError("audit provenance row has an unexpected field count")
        supplier_item_id = row[2]
        record = expected_by_item.get(supplier_item_id)
        if record is None or supplier_item_id in seen:
            raise StagingApplyError("audit provenance supplier item multiplicity mismatch")
        seen.add(supplier_item_id)
        expected_product_id = product_ids[record["target_sku"]]
        expected_after = _audit_after_json(record, json.loads(record["source_snapshot_json"], object_pairs_hook=_reject_duplicate_json_keys))
        expected = [
            record["run_id"],
            record["supplier_item_id"],
            record["source_sku"],
            str(expected_product_id),
            record["action"],
            "netlab",
            record["verification_status"],
            "0",
            record["source_url"],
            record["source_raw_hash"],
            record["source_fetched_at"],
            record["source_artifact_path"],
            record["source_artifact_sha256"],
            record["matches_artifact_sha256"],
            record["source_snapshot_json"],
            record["properties_json"],
            record["image_urls_json"],
            record["category_json"],
            expected_after,
        ]
        actual = row[1:4] + [row[4]] + row[5:]
        if actual != expected:
            mismatches = [
                field
                for field, actual_value, expected_value in zip(
                    [
                        "run_id",
                        "supplier_item_id",
                        "source_sku",
                        "target_product_id",
                        "action",
                        "source_kind",
                        "verification_status",
                        "manufacturer_verified",
                        "source_url",
                        "source_raw_hash",
                        "source_fetched_at",
                        "source_artifact_path",
                        "source_artifact_sha256",
                        "matches_artifact_sha256",
                        "source_snapshot_json",
                        "properties_json",
                        "image_urls_json",
                        "category_json",
                        "after_json",
                    ],
                    actual,
                    expected,
                )
                if actual_value != expected_value
            ]
            raise StagingApplyError(
                f"audit provenance field mismatch for supplier item: {supplier_item_id}; fields={mismatches}"
            )
    if seen != set(expected_by_item):
        raise StagingApplyError("audit provenance supplier item set mismatch")
    return len(rows)


def _readback(
    target: StagingTarget,
    records: list[dict[str, Any]],
    before: dict[str, Any],
    *,
    query_runner: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    skus = [record["target_sku"] for record in records]
    product_rows: list[list[str]] = []
    for batch in _batches(skus):
        batch_literals = ",".join(_sql_literal(sku) for sku in batch)
        product_rows.extend(
            _decode_hex_fields(row, {1, 2, 9, 10})
            for row in _call_query_lines(
                target,
                "SELECT `product_id`, HEX(`sku`), HEX(`model`), `quantity`, `price`, `weight`, "
                "`length`, `width`, `height`, HEX(`mpn`), HEX(`ean`), `status`, `noindex` "
                f"FROM `oc_product` WHERE `sku` IN ({batch_literals})",
                query_runner=query_runner,
            )
        )
    actual_by_sku: dict[str, list[str]] = {}
    for row in product_rows:
        if len(row) != 13:
            raise StagingApplyError("read-back product row has an unexpected field count")
        sku = row[1]
        if sku in actual_by_sku:
            raise StagingApplyError(f"read-back has duplicate product rows for SKU: {sku}")
        actual_by_sku[sku] = row
    expected_by_sku = {record["target_sku"]: record for record in records}
    missing = sorted(set(expected_by_sku) - set(actual_by_sku))
    if missing:
        raise StagingApplyError(f"read-back SKU count is not one: {missing[0]}")
    unexpected = sorted(set(actual_by_sku) - set(expected_by_sku))
    if unexpected:
        raise StagingApplyError(f"read-back returned unexpected SKU: {unexpected[0]}")

    product_ids: dict[str, int] = {}
    field_indexes = {
        "model": 2,
        "quantity": 3,
        "price": 4,
        "weight": 5,
        "length": 6,
        "width": 7,
        "height": 8,
        "mpn": 9,
        "ean": 10,
    }
    numeric_fields = {"quantity", "price", "weight", "length", "width", "height"}
    for sku, record in expected_by_sku.items():
        row = actual_by_sku[sku]
        try:
            product_id = int(row[0])
        except (TypeError, ValueError) as exc:
            raise StagingApplyError(f"read-back has invalid product id for SKU: {sku}") from exc
        if product_id <= 0:
            raise StagingApplyError(f"read-back has non-positive product id for SKU: {sku}")
        product_ids[sku] = product_id
        if record["action"] == "update" and record.get("target_product_id") != product_id:
            raise StagingApplyError(f"read-back product id mismatch for SKU: {sku}")
        payload = record.get("target_payload")
        if not isinstance(payload, dict):
            raise StagingApplyError(f"read-back record has no target payload for SKU: {sku}")
        for field, index in field_indexes.items():
            if field not in payload:
                continue
            expected = payload[field]
            if record["action"] == "update" and field in {"mpn", "ean"} and expected in {None, ""}:
                continue
            actual = row[index]
            if field in numeric_fields:
                try:
                    matches = Decimal(str(expected)) == Decimal(actual)
                except (InvalidOperation, ValueError) as exc:
                    raise StagingApplyError(f"read-back has invalid {field} for SKU: {sku}") from exc
            else:
                matches = actual == str(expected)
            if not matches:
                raise StagingApplyError(
                    f"read-back field mismatch for SKU {sku}: {field}={actual!r}, expected {expected!r}"
                )
        if record["action"] == "create" and (row[11], row[12]) != ("0", "1"):
            raise StagingApplyError(f"new product is not disabled/noindex for SKU: {sku}")
        if (
            record["action"] == "update"
            and sku in before.get("update_flags", {})
            and (row[11], row[12]) != tuple(before["update_flags"][sku])
        ):
            raise StagingApplyError(f"status/noindex changed unexpectedly for SKU: {sku}")

    description_rows: list[list[str]] = []
    for batch in _batches(sorted(set(product_ids.values()))):
        description_ids = ",".join(str(product_id) for product_id in batch)
        description_rows.extend(
            _decode_hex_fields(row, {2, 3})
            for row in _call_query_lines(
                target,
                "SELECT `product_id`, `language_id`, HEX(`name`), HEX(`description`) "
                f"FROM `oc_product_description` WHERE `product_id` IN ({description_ids}) "
                f"AND `language_id`={before.get('language_id', 1)}",
                query_runner=query_runner,
            )
        )
    descriptions: dict[int, list[str]] = {}
    for row in description_rows:
        if len(row) != 4:
            raise StagingApplyError("read-back description row has an unexpected field count")
        product_id = int(row[0])
        if product_id in descriptions:
            raise StagingApplyError(f"read-back has duplicate description rows for product id: {product_id}")
        descriptions[product_id] = row
    for sku, record in expected_by_sku.items():
        payload = record["target_payload"]
        product_id = product_ids[sku]
        row = descriptions.get(product_id)
        if row is None:
            raise StagingApplyError(
                f"read-back has no language-{before.get('language_id', 1)} description for SKU: {sku}"
            )
        expected_values = {
            "name": payload["name"],
            "description": payload["description"],
        }
        if "description" in payload.get("preserve_fields", []):
            before_description = before.get("update_descriptions", {}).get(sku)
            if before_description is None:
                raise StagingApplyError(f"missing before description for preserved SKU: {sku}")
            expected_values["description"] = before_description[1]
        for field, index in (("name", 2), ("description", 3)):
            if row[index] != str(expected_values[field]):
                raise StagingApplyError(
                    f"read-back description field mismatch for SKU {sku}: "
                    f"{field}={row[index]!r}, expected {expected_values[field]!r}"
                )
    created = sum(record["action"] == "create" for record in records)
    checked = len(records)
    audit_rows = None
    if records and isinstance(records[0].get("run_id"), str) and records[0]["run_id"]:
        audit_rows = _verify_audit_provenance(
            target,
            records,
            product_ids,
            query_runner=query_runner,
        )
        if audit_rows < 0:
            run_id = records[0]["run_id"]
            audit_rows = _call_count(
                target,
                "SELECT COUNT(*) FROM `oc_netlab_transfer_audit` "
                f"WHERE `run_id`={_sql_literal(run_id)}",
                query_runner,
            )
        if audit_rows != len(records):
            raise StagingApplyError(f"audit read-back count mismatch: {audit_rows} != {len(records)}")
    expected_relations = _category_relations_for_records(records, product_ids)
    actual_relations = _category_relation_rows(target, query_runner=query_runner)
    missing_relations = sorted(expected_relations - actual_relations)
    if missing_relations:
        raise StagingApplyError(
            "read-back category relation missing: "
            f"product_id={missing_relations[0][0]}, category_id={missing_relations[0][1]}"
        )
    before_relations = {tuple(row) for row in before.get("category_relations_snapshot", [])}
    new_relations = expected_relations - before_relations
    if actual_relations - new_relations != before_relations:
        raise StagingApplyError("category relation content changed outside the candidate set")
    if len(actual_relations) != len(before_relations) + len(new_relations):
        raise StagingApplyError("category relation count delta does not match candidate set")
    after_categories = len(actual_relations)
    after_images = _call_count(
        target,
        "SELECT COUNT(*) FROM `oc_product_image`",
        query_runner,
    )
    after_images_digest = (
        _semantic_digest(target, "oc_product_image", query_runner=query_runner)
        if "images_digest" in before
        else None
    )
    if after_categories != before["categories"] + len(new_relations):
        raise StagingApplyError("category relation count delta does not match candidate set")
    if after_images != before["images"]:
        raise StagingApplyError("media relation count changed")
    if after_images_digest != before.get("images_digest"):
        raise StagingApplyError("media relation content changed")
    after_products = _call_count(
        target,
        "SELECT COUNT(*) FROM `oc_product`",
        query_runner,
    )
    if after_products != before["products"] + created:
        raise StagingApplyError("product count delta does not match create count")
    return {
        "records_checked": checked,
        "created": created,
        "audit_rows": audit_rows,
        "products_before": before["products"],
        "products_after": after_products,
        "categories_unchanged": not new_relations,
        "categories_content_unchanged": not new_relations,
        "category_relations_added": len(new_relations),
        "images_unchanged": True,
        "images_content_unchanged": True,
    }


def _backup_apply_readback(
    target: StagingTarget,
    backup_root: Path,
    candidate_sql: Path,
    candidate_handle: BinaryIO,
    records: list[dict[str, Any]],
    before: dict[str, Any],
    result: dict[str, Any],
    candidate_identity: dict[str, Any],
    coordination_session: _LockedMysqlSession | None = None,
    manifest: dict[str, Any] | None = None,
    trusted_run_manifest: Path | None = None,
    expected_trusted_run_seal_sha256: str | None = None,
) -> dict[str, Any]:
    if coordination_session is None:
        raise StagingApplyError("InnoDB apply requires the active coordination session")
    coordination_session.assert_alive()
    query_runner: Callable[[str], str] = coordination_session.query
    _require_transactional_pilot(before)
    try:
        before_state_path = _backup_database(
            target,
            backup_root,
            before=before,
            consistency_strategy=before["consistency_strategy"],
            coordination_session=coordination_session,
        )
        result["before_state"] = str(before_state_path)
        result["before_state_identity"] = _file_identity(before_state_path)
    except StagingApplyError as exc:
        result.update({"status": "FAILED", "stage": "backup", "error": str(exc)})
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc

    try:
        after_backup = _preflight(target, records, query_runner=query_runner)
    except StagingApplyError as exc:
        result.update({"status": "FAILED", "stage": "post_backup_preflight", "error": str(exc)})
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
    if _before_state_identity(after_backup) != _before_state_identity(before):
        result.update(
            {
                "status": "ABORTED_CONCURRENT_CHANGE",
                "stage": "post_backup_preflight",
                "error": "staging state changed after backup and before apply",
            }
        )
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True))

    try:
        coordination_session.assert_alive()
        locked_before = _preflight(target, records, query_runner=query_runner)
        if _before_state_identity(locked_before) != _before_state_identity(before):
            raise StagingApplyError("staging state changed before locked apply")
        if manifest is not None:
            _revalidate_candidate_source_freshness(
                manifest,
                records,
                trusted_run_manifest,
                expected_seal_sha256=expected_trusted_run_seal_sha256,
            )
        result["before"] = locked_before
        coordination_session.run_candidate(
            candidate_handle,
            audit_table_exists=bool(locked_before["audit_table"]),
            expected_identity=candidate_identity,
        )
        result["readback"] = _readback(
            target,
            records,
            locked_before,
            query_runner=query_runner,
        )
        coordination_session.assert_alive()
        result["lock_scope"] = "named_get_lock_serializable_transaction_through_backup_apply_readback_pending_receipt"
        result["status"] = "PASS"
    except StagingApplyError as exc:
        result["stage"] = "apply_or_readback"
        result["apply_error"] = str(exc)
        try:
            result["rollback_readback"] = _restore_with_coordination(
                target,
                before,
                records,
                coordination_session=coordination_session,
            )
            result["rollback"] = "PASS"
            result["status"] = "ROLLED_BACK"
        except StagingApplyError as rollback_exc:
            result["rollback"] = f"FAILED: {rollback_exc}"
            result["status"] = "ROLLBACK_BLOCKED"
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
    return _finalize_success(
        target,
        backup_root,
        result,
        before,
        records,
        coordination_session=coordination_session,
    )


def _prepare_candidate_snapshot(
    candidate_sql: Path,
    backup_root: Path,
    *,
    trusted_run_manifest: Path | None,
    expected_trusted_run_seal_sha256: str | None,
    result: dict[str, Any],
    deadline: _CandidatePreparationDeadline,
) -> tuple[dict[str, Any], list[dict[str, Any]], Path, dict[str, Any]]:
    with _locked_candidate_bundle(candidate_sql.parent, deadline_check=deadline.check) as source_handles:
        locked_control_identities: dict[str, dict[str, Any]] = {}
        for relative in ("CANDIDATE_MANIFEST.json", "seal.json"):
            deadline.check()
            locked_control_identities[relative] = _handle_identity(
                source_handles[relative],
                deadline_check=deadline.check,
            )
        validate_candidate_file(candidate_sql, deadline_check=deadline.check)
        manifest = validate_candidate_bundle(
            candidate_sql,
            trusted_run_manifest=trusted_run_manifest,
            expected_trusted_run_seal_sha256=expected_trusted_run_seal_sha256,
            require_trusted_run_manifest=True,
            deadline_check=deadline.check,
        )
        if manifest.get("schema_version") != 2:
            raise StagingApplyError("apply requires candidate schema version 2")
        _verify_locked_candidate_bundle(
            manifest,
            source_handles,
            candidate_root=candidate_sql.parent,
            control_identities=locked_control_identities,
            deadline_check=deadline.check,
        )
        backup_root.mkdir(parents=True, exist_ok=False)
        try:
            candidate_snapshot = _snapshot_candidate_bundle(
                candidate_sql,
                backup_root,
                manifest,
                source_handles=source_handles,
                deadline_check=deadline.check,
            )
            _verify_locked_candidate_bundle(
                manifest,
                source_handles,
                candidate_root=candidate_sql.parent,
                control_identities=locked_control_identities,
                deadline_check=deadline.check,
            )
            snapshot_scanner = validate_candidate_file(candidate_snapshot, deadline_check=deadline.check)
            records_entry = _manifest_file_entry(
                manifest,
                "RECORDS.jsonl",
                deadline_check=deadline.check,
            )
            records = _load_records(
                candidate_snapshot,
                expected_identity=records_entry,
                deadline_check=deadline.check,
            )
            _validate_attribute_mapping_binding(
                manifest,
                records,
                candidate_sql.parent,
                deadline_check=deadline.check,
            )
            _revalidate_candidate_source_freshness(
                manifest,
                records,
                trusted_run_manifest,
                expected_seal_sha256=expected_trusted_run_seal_sha256,
                deadline_check=deadline.check,
            )
            _validate_candidate_operations(snapshot_scanner, records, deadline_check=deadline.check)
            for record in records:
                deadline.check()
                if (
                    record.get("run_id") != manifest["run_id"]
                    or record.get("source_artifact_sha256") != manifest["source_artifact_sha256"]
                    or record.get("matches_artifact_sha256") != manifest["matches_artifact_sha256"]
                ):
                    raise StagingApplyError("candidate manifest identity does not match RECORDS.jsonl")
            result["candidate_snapshot"] = str(candidate_snapshot)
            result["candidate_id"] = manifest["candidate_id"]
            result["candidate_run_id"] = manifest["run_id"]
        except _CandidatePreparationTimeout:
            raise
        except StagingApplyError as exc:
            result.update({"status": "REJECTED", "stage": "candidate", "error": str(exc)})
            receipt = write_apply_result(backup_root, result)
            result["result_path"] = str(receipt)
            raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
    snapshot_entry = _manifest_file_entry(
        manifest,
        "APPLY_STAGING.sql",
        deadline_check=deadline.check,
    )
    return manifest, records, candidate_snapshot, {"size": snapshot_entry["size"], "sha256": snapshot_entry["sha256"]}


def apply_candidate(
    candidate_sql: Path,
    *,
    target: StagingTarget,
    backup_root: Path,
    confirm_staging_only: bool,
    trusted_run_manifest: Path | None = None,
    expected_trusted_run_seal_sha256: str | None = None,
) -> dict[str, Any]:
    """Apply one candidate to a loopback staging DB with rollback evidence."""
    if not confirm_staging_only:
        raise StagingApplyError("explicit staging-only confirmation is required")
    deadline = _CandidatePreparationDeadline.from_target(target)
    validate_staging_target(target)
    candidate_sql = _safe_candidate_root(candidate_sql, deadline_check=deadline.check)
    candidate_root = candidate_sql.parent
    backup_root = _safe_backup_root(backup_root, deadline_check=deadline.check)
    result: dict[str, Any] = {
        "status": "FAILED",
        "execution_attempt_id": uuid.uuid4().hex,
        "database": target.database,
        "candidate": str(candidate_sql),
        "production_writes": 0,
        "publication_enabled": False,
        "relations_created": 0,
        "media_assignments": 0,
    }
    def _candidate_preparation_timeout_error(exc: _CandidatePreparationTimeout) -> StagingApplyError:
        result.update(
            {
                "status": "REJECTED",
                "stage": "candidate_preparation_timeout",
                "error": str(exc),
            }
        )
        try:
            if not backup_root.exists():
                backup_root.mkdir(parents=True, exist_ok=False)
            receipt = write_apply_result(backup_root, result)
            result["result_path"] = str(receipt)
        except (OSError, StagingApplyError) as receipt_exc:
            result["receipt_error"] = str(receipt_exc)
        return StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True))

    try:
        manifest, records, candidate_sql, snapshot_identity = _prepare_candidate_snapshot(
            candidate_sql,
            backup_root,
            trusted_run_manifest=trusted_run_manifest,
            expected_trusted_run_seal_sha256=expected_trusted_run_seal_sha256,
            result=result,
            deadline=deadline,
        )
    except _CandidatePreparationTimeout as exc:
        raise _candidate_preparation_timeout_error(exc) from exc
    except IntegrityDeadlineExceeded as exc:
        timeout = _CandidatePreparationTimeout(str(exc))
        raise _candidate_preparation_timeout_error(timeout) from exc
    try:
        deadline.check()
        _validate_attribute_mapping_binding(
            manifest,
            records,
            candidate_root,
            expected_database=target.database,
            deadline_check=deadline.check,
        )
    except _CandidatePreparationTimeout as exc:
        raise _candidate_preparation_timeout_error(exc) from exc
    except StagingApplyError as exc:
        result.update({"status": "REJECTED", "stage": "candidate_attribute_mapping", "error": str(exc)})
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
    def _candidate_boundary_error(exc: StagingApplyError) -> StagingApplyError:
        if isinstance(exc, _CandidatePreparationTimeout):
            return _candidate_preparation_timeout_error(exc)
        result.update({"status": "REJECTED", "stage": "candidate_snapshot", "error": str(exc)})
        receipt = write_apply_result(backup_root, result)
        result["result_path"] = str(receipt)
        return StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True))

    with _locked_candidate_handle(
        candidate_sql,
        expected_identity=snapshot_identity,
        on_boundary_error=_candidate_boundary_error,
        deadline_check=deadline.check,
    ) as candidate_handle:
        try:
            deadline.check()
            with _LockedMysqlSession(
                target,
                _PILOT_LOCK_TABLES,
                audit_table_exists=True,
            ) as coordination_session:
                coordination_session.assert_alive()
                before = _preflight(
                    target,
                    records,
                    query_runner=coordination_session.query,
                )
                if not before["audit_table"]:
                    raise StagingApplyError(
                        "staging apply requires a pre-created audit table"
                    )
                _require_transactional_pilot(before)
                result["before"] = before
                _revalidate_candidate_source_freshness(
                    manifest,
                    records,
                    trusted_run_manifest,
                    expected_seal_sha256=expected_trusted_run_seal_sha256,
                )
                apply_result = _backup_apply_readback(
                    target,
                    backup_root,
                    candidate_sql,
                    candidate_handle,
                    records,
                    before,
                    result,
                    snapshot_identity,
                    coordination_session,
                    manifest=manifest,
                    trusted_run_manifest=trusted_run_manifest,
                    expected_trusted_run_seal_sha256=expected_trusted_run_seal_sha256,
                )
            return _finalize_committed_result(backup_root, apply_result)
        except _CandidatePreparationTimeout as exc:
            result.update(
                {
                    "status": "REJECTED",
                    "stage": "candidate_preparation_timeout",
                    "error": str(exc),
                }
            )
            receipt = write_apply_result(backup_root, result)
            result["result_path"] = str(receipt)
            raise _CandidatePreparationTimeout(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
        except StagingSessionStateError as exc:
            result.update(
                {
                    "status": exc.status,
                    "stage": "coordination",
                    "error": str(exc),
                    "commit_state": exc.commit_state,
                    "coordination_lock_state": exc.lock_state,
                }
            )
            try:
                failure_receipt = _write_failure_receipt(backup_root, result)
                result["failure_result_path"] = str(failure_receipt)
            except StagingApplyError as failure_exc:
                result["failure_receipt_error"] = str(failure_exc)
            raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
        except StagingApplyError as exc:
            if result.get("result_path") or result.get("failure_result_path"):
                raise
            result.update({"status": "FAILED", "stage": "coordination", "error": str(exc)})
            receipt = write_apply_result(backup_root, result)
            result["result_path"] = str(receipt)
            raise StagingApplyError(json.dumps(result, ensure_ascii=False, sort_keys=True)) from exc
