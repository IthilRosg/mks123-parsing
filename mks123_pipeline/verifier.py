from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any

from .adapters import NetlabAdapter, create_adapter
from .config import load_pilot_config, pricing_context_from_config
from .db_digest import (
    database_content_sha256,
    read_only_table_counts,
)
from .integrity import load_sealed_run, read_evidence
from .manifest import MANIFEST_NAME
from .netlab_acquisition import (
    parse_netlab_acquisition_metadata,
    validate_netlab_acquisition_metadata,
    validate_netlab_properties_acquisition_metadata,
)
from .netlab_properties import scan_netlab_properties
from .runner import run_pilot
from .state import update_missing_state

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MOSCOW = timezone(timedelta(hours=3))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _csv_rows(data: bytes) -> list[dict[str, str]]:
    with io.StringIO(data.decode("utf-8-sig"), newline="") as handle:
        return list(csv.DictReader(handle))


def _jsonl_rows(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


def _result(checks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    passed = sum(1 for item in checks.values() if item["passed"])
    return {
        "status": "PASS" if passed == len(checks) else "FAIL",
        "checks_passed": passed,
        "checks_total": len(checks),
        "checks": checks,
    }


def _check(checks: dict[str, dict[str, Any]], name: str, condition: bool, detail: Any) -> None:
    checks[name] = {"passed": bool(condition), "detail": detail}


def _safe_bundle_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or PurePosixPath(value).is_absolute():
        return False
    return ".." not in PurePosixPath(value).parts and "\\" not in value


def _rate_source_hash_matches(manifest: dict[str, Any]) -> bool:
    inputs = manifest.get("inputs")
    policy = manifest.get("policy")
    if not isinstance(inputs, dict) or not isinstance(policy, dict):
        return False
    source = inputs.get("source")
    rates = policy.get("rates")
    if not isinstance(source, dict) or not isinstance(rates, dict):
        return False
    source_hash = source.get("sha256")
    supplier = manifest.get("supplier")
    if not isinstance(source_hash, str) or not isinstance(supplier, str):
        return False
    for currency, rate in rates.items():
        if not isinstance(rate, dict) or rate.get("currency") != currency:
            return False
        if rate.get("source") == "supplier_feed" and (
            rate.get("source_sha256") != source_hash or rate.get("supplier_id") != supplier
        ):
            return False
    return True


def _code_identity_hash_matches(identity: Any) -> bool:
    if not isinstance(identity, dict) or identity.get("schema_version") != "1":
        return False
    files = identity.get("files")
    runtime = identity.get("runtime")
    digest = identity.get("sha256")
    if (
        not isinstance(files, dict)
        or not isinstance(runtime, dict)
        or not isinstance(runtime.get("dependencies"), dict)
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
    ):
        return False
    for path, record in files.items():
        if not _safe_bundle_path(path) or not isinstance(record, dict):
            return False
        if _SHA256.fullmatch(str(record.get("sha256", ""))) is None:
            return False
        size = record.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return False
    return _sha256(_canonical_bytes({"files": files, "runtime": runtime})) == digest


def _canonical_run_id_matches(manifest: dict[str, Any]) -> bool:
    inputs = manifest.get("inputs")
    policy = manifest.get("policy")
    code_identity = manifest.get("code_identity")
    if not isinstance(inputs, dict) or not isinstance(policy, dict) or not isinstance(code_identity, dict):
        return False
    source = inputs.get("source")
    catalog = inputs.get("catalog")
    config = inputs.get("config")
    if not isinstance(source, dict) or not isinstance(catalog, dict) or not isinstance(config, dict):
        return False
    config_hash = config.get("sha256")
    if not isinstance(config_hash, str):
        config_hash = _sha256(_canonical_bytes(config))
    supplier = manifest.get("supplier")
    values = (
        source.get("sha256"),
        catalog.get("sha256"),
        config_hash,
        policy.get("hash"),
        code_identity.get("sha256"),
    )
    if not isinstance(supplier, str) or any(not isinstance(value, str) for value in values):
        return False
    source_hash, catalog_hash, config_hash, policy_hash, code_hash = values
    if any(_SHA256.fullmatch(value) is None for value in values):
        return False
    expected = (
        f"{supplier}-{source_hash[:12]}-catalog-{catalog_hash[:12]}-"
        f"config-{config_hash[:12]}-policy-{policy_hash[:12]}-code-{code_hash[:12]}"
    )
    properties = inputs.get("properties")
    if isinstance(properties, dict) and isinstance(properties.get("sha256"), str):
        expected += f"-properties-{properties['sha256'][:12]}"
    return manifest.get("run_id") == expected and manifest.get("canonical_run_id") == expected


def _catalog_scope_map(data: bytes, sku_prefix: str) -> dict[str, str]:
    if not isinstance(sku_prefix, str) or not sku_prefix:
        raise ValueError("catalog SKU prefix is invalid")
    result: dict[str, str] = {}
    for row in _csv_rows(data):
        product_id = row.get("product_id")
        sku = row.get("sku")
        if not isinstance(product_id, str) or not re.fullmatch(r"[0-9]+", product_id):
            raise ValueError("catalog scope contains an invalid product_id")
        if not isinstance(sku, str) or not sku:
            raise ValueError("catalog scope contains an empty SKU")
        if not sku.startswith(sku_prefix):
            continue
        canonical_id = str(int(product_id))
        if canonical_id in result:
            raise ValueError(f"catalog scope contains duplicate product_id: {canonical_id}")
        result[canonical_id] = sku
    return result


def _missing_action_gate(
    feed_completeness: Any,
    missing_decision: Any,
    state_payload: dict[str, Any] | None,
    missing_rows: list[dict[str, str]],
    catalog_scope_items: Any,
    *,
    supplier: Any = None,
    source_items: Any = None,
    catalog_scope: dict[str, str] | None = None,
    previous_state_payload: dict[str, Any] | None = None,
    expected_run_id: str | None = None,
    missing_policy: Any = None,
) -> tuple[bool, dict[str, Any]]:
    errors: list[str] = []
    if not isinstance(feed_completeness, dict):
        errors.append("feed_completeness must be an object")
        feed_completeness = {}
    if not isinstance(missing_decision, dict):
        errors.append("missing_product_state must be an object")
        missing_decision = {}

    status = feed_completeness.get("status")
    if status not in {"complete", "blocked_incomplete"}:
        errors.append("feed_completeness.status is not an approved value")
    if feed_completeness.get("missing_actions_allowed") is not False:
        errors.append("feed_completeness.missing_actions_allowed must be false")

    decision_complete = missing_decision.get("complete")
    if not isinstance(decision_complete, bool):
        errors.append("missing_product_state.complete must be boolean")
    elif status in {"complete", "blocked_incomplete"} and decision_complete != (status == "complete"):
        errors.append("missing-product decision does not match feed completeness status")
    if state_payload is None or (
        isinstance(decision_complete, bool)
        and state_payload.get("last_feed_complete") != decision_complete
    ):
        errors.append("missing-product state completeness does not match decision")

    proposed_actions = missing_decision.get("proposed_actions")
    if not isinstance(proposed_actions, list):
        errors.append("missing-product proposed_actions must be a list")
    elif status == "blocked_incomplete" and proposed_actions:
        errors.append("incomplete feed cannot propose missing-product actions")
    actions_allowed = missing_decision.get("actions_allowed")
    if not isinstance(actions_allowed, bool):
        errors.append("missing_product_state.actions_allowed must be boolean")
    elif status == "blocked_incomplete" and actions_allowed:
        errors.append("incomplete feed cannot allow missing-product actions")

    try:
        scope_items = int(catalog_scope_items)
    except (TypeError, ValueError):
        scope_items = -1
        errors.append("catalog_scope_items must be an integer")
    if isinstance(catalog_scope_items, bool) or scope_items < 0:
        errors.append("catalog_scope_items must be nonnegative")

    missing_map: dict[str, str] = {}
    for row in missing_rows:
        product_id = row.get("product_id") if isinstance(row, dict) else None
        sku = row.get("sku") if isinstance(row, dict) else None
        if (
            not isinstance(product_id, str)
            or re.fullmatch(r"[0-9]+", product_id) is None
            or product_id != str(int(product_id))
            or int(product_id) <= 0
        ):
            errors.append("missing rows contain an invalid product_id")
            continue
        if not isinstance(sku, str) or not sku:
            errors.append(f"missing row has an empty SKU: {product_id}")
            continue
        if product_id in missing_map:
            errors.append(f"missing rows contain duplicate product_id: {product_id}")
            continue
        if sku in missing_map.values():
            errors.append(f"missing rows contain duplicate SKU: {sku}")
        missing_map[product_id] = sku
        if catalog_scope is not None:
            if product_id not in catalog_scope:
                errors.append(f"missing row is outside catalog scope: {product_id}")
            elif catalog_scope[product_id] != sku:
                errors.append(f"missing row SKU mismatch: {product_id}")

    missing_count = len(missing_rows)
    if scope_items >= 0 and missing_count > scope_items:
        errors.append("missing rows exceed catalog scope")
    if catalog_scope is not None and len(catalog_scope) != scope_items:
        errors.append("catalog scope count does not match catalog_scope_items")

    try:
        covered_ratio = Decimal(str(feed_completeness.get("catalog_covered_ratio")))
        source_ratio = Decimal(str(feed_completeness.get("source_to_catalog_ratio")))
        if not covered_ratio.is_finite() or not Decimal(0) <= covered_ratio <= Decimal(1):
            errors.append("catalog_covered_ratio is outside 0..1")
        if not source_ratio.is_finite() or source_ratio < 0:
            errors.append("source_to_catalog_ratio is invalid")
    except (InvalidOperation, TypeError, ValueError):
        covered_ratio = None
        source_ratio = None
        errors.append("feed completeness ratios are not numeric")

    if source_items is not None:
        try:
            source_count = int(source_items)
            if isinstance(source_items, bool) or source_count < 0:
                raise ValueError
            expected_source_ratio = (
                Decimal(source_count) / Decimal(scope_items) if scope_items else Decimal(1)
            )
            if source_ratio is not None and source_ratio != expected_source_ratio:
                errors.append("source_to_catalog_ratio does not reconcile with source_items")
        except (TypeError, ValueError, InvalidOperation, ZeroDivisionError):
            errors.append("source_items must be a nonnegative integer")
    if scope_items:
        expected_covered_ratio = Decimal(scope_items - missing_count) / Decimal(scope_items)
    else:
        expected_covered_ratio = Decimal(1)
    if covered_ratio is not None and covered_ratio != expected_covered_ratio:
        errors.append("catalog_covered_ratio does not reconcile with missing rows")

    if status == "complete":
        if missing_count != 0:
            errors.append("complete feed has missing catalog rows")
        if covered_ratio != Decimal(1):
            errors.append("complete feed must have catalog_covered_ratio=1")
        if decision_complete is not True:
            errors.append("complete feed must set missing_product_state.complete=true")
        if feed_completeness.get("reason") != "all_catalog_scope_items_seen":
            errors.append("complete feed reason is invalid")
        if missing_decision.get("reason") != "complete_feed":
            errors.append("complete missing-product reason is invalid")
    elif status == "blocked_incomplete":
        if missing_count == 0:
            errors.append("incomplete feed must have missing catalog rows")
        if covered_ratio is not None and not covered_ratio < Decimal(1):
            errors.append("incomplete feed must have catalog_covered_ratio<1")
        if decision_complete is not False:
            errors.append("incomplete feed must set missing_product_state.complete=false")
        if feed_completeness.get("reason") != "source_does_not_cover_catalog_scope":
            errors.append("incomplete feed reason is invalid")
        if missing_decision.get("reason") != "incomplete_feed":
            errors.append("incomplete missing-product reason is invalid")

    if state_payload is not None:
        products = state_payload.get("products")
        if not isinstance(products, dict):
            errors.append("missing-product state products must be an object")
        if not isinstance(state_payload.get("last_run_id"), str) or not state_payload.get("last_run_id"):
            errors.append("missing-product state last_run_id is invalid")
        elif expected_run_id is not None and state_payload.get("last_run_id") != expected_run_id:
            errors.append("missing-product state last_run_id does not match run inputs")

    if (
        state_payload is not None
        and isinstance(supplier, str)
        and isinstance(missing_policy, dict)
        and isinstance(decision_complete, bool)
        and expected_run_id is not None
    ):
        try:
            expected_state, expected_decision = update_missing_state(
                previous_state_payload,
                supplier=supplier,
                run_id=expected_run_id,
                complete=decision_complete,
                missing_products=missing_map,
                action=missing_policy.get("configured_action"),
                threshold=missing_policy.get("consecutive_missing_runs"),
            )
            if state_payload != expected_state:
                errors.append("missing-product state does not match previous state and current missing rows")
            if missing_decision != expected_decision:
                errors.append("missing-product decision does not match state policy")
        except (TypeError, ValueError) as exc:
            errors.append(f"cannot reconcile missing-product state: {exc}")

    return not errors, {
        "errors": errors,
        "status": status,
        "missing_rows": missing_count,
        "catalog_scope_items": scope_items,
        "expected_catalog_covered_ratio": str(expected_covered_ratio),
    }


def _external_check(
    checks: dict[str, dict[str, Any]],
    label: str,
    path: Path | None,
    record: dict[str, Any],
) -> None:
    if path is None:
        return
    try:
        data = read_evidence(path).data
        actual = {"sha256": _sha256(data), "size": len(data)}
        expected = {"sha256": record.get("sha256"), "size": record.get("size")}
        _check(checks, f"external_{label}_hash", actual == expected, {"actual": actual, "expected": expected})
    except OSError as exc:
        _check(checks, f"external_{label}_hash", False, str(exc))


def _netlab_content_semantics(
    manifest: dict[str, Any],
    files: dict[str, Any],
    rows: dict[str, list[dict[str, Any]]],
) -> tuple[bool, Any]:
    if manifest.get("supplier") != "netlab":
        return True, "not_netlab"
    try:
        manifest_summary = manifest["summary"]
        content = manifest_summary.get("content_enrichment") if isinstance(manifest_summary, dict) else None
        if not isinstance(content, dict) or content.get("enabled") is not True:
            return True, "content_disabled"
        inputs = manifest["inputs"]
        properties_record = inputs["properties"]
        properties_metadata_record = inputs["properties_metadata"]
        properties_evidence = files[properties_record["bundle_path"]]
        metadata_evidence = files[properties_metadata_record["bundle_path"]]
        with tempfile.TemporaryDirectory(prefix="verify-netlab-content-") as temporary:
            properties_path = Path(temporary) / "properties.zip"
            properties_path.write_bytes(properties_evidence.data)
            stats = scan_netlab_properties(
                properties_path,
                max_bytes=268 * 1024 * 1024,
                allow_unknown_property_ids=True,
            )
        metadata_payload = parse_netlab_acquisition_metadata(metadata_evidence.data)
        validate_netlab_properties_acquisition_metadata(
            metadata_payload,
            source_data=properties_evidence.data,
            expected_fetched_at=str(content.get("properties_fetched_at") or ""),
            expected_catalog_date=stats.catalog_date,
            expected_stats=stats,
        )
        expected_fields = {
            "properties_source_sha256": stats.source_sha256,
            "properties_catalog_date": stats.catalog_date,
            "properties_item_count": stats.item_count,
            "properties_count": stats.property_count,
            "properties_observation_count": stats.observation_count,
            "unknown_property_id_count": stats.unknown_property_id_count,
            "unknown_observation_count": stats.unknown_observation_count,
        }
        if "missing_observation_count" in metadata_payload:
            expected_fields["properties_missing_observation_count"] = stats.missing_observation_count
        for field, expected in expected_fields.items():
            if content.get(field) != expected:
                raise ValueError(f"content summary field does not match properties feed: {field}")
        if content.get("join_key") != "price_offer.uid=GoodsProperties.item.@id":
            raise ValueError("content join key is not the approved UID contract")
        description_count = 0
        matched_count = 0
        review_count = 0
        for row in rows.get("normalized_jsonl", []):
            provenance = row.get("content_provenance")
            if not isinstance(provenance, dict):
                raise TypeError("normalized row is missing content provenance")
            join = provenance.get("join")
            properties = provenance.get("properties")
            if not isinstance(join, dict) or join.get("key") != "uid" or not isinstance(properties, dict):
                raise ValueError("normalized row has invalid content join provenance")
            if properties.get("source_sha256") != stats.source_sha256:
                raise ValueError("normalized row properties provenance is not source-bound")
            if row.get("description") is not None:
                description_count += 1
                if "<script" in str(row["description"]).casefold() or re.search(
                    r"\\bon[a-z]+\\s*=|javascript:", str(row["description"]).casefold()
                ):
                    raise ValueError("normalized description is not sanitized")
            if join.get("matched") is True:
                matched_count += 1
                if not isinstance(join.get("item_id"), str) or not join["item_id"]:
                    raise ValueError("matched content row has no UID")
                if properties.get("item_id") != join["item_id"]:
                    raise ValueError("matched content provenance UID mismatch")
            if provenance.get("review_only") is True:
                review_count += 1
            images = row.get("image_urls") or []
            if not isinstance(images, list):
                raise TypeError("normalized image_urls is not a list")
            for image_url in images:
                if (
                    not isinstance(image_url, str)
                    or not image_url.startswith("https://nlimg.netlab.ru/")
                    or "#" in image_url
                ):
                    raise ValueError("normalized image URL is not allowlisted")
        if matched_count != content.get("uid_properties_overlap"):
            raise ValueError("content UID overlap does not match normalized rows")
        if description_count != content.get("description_items"):
            raise ValueError("content description count does not match normalized rows")
        if content.get("review_only_unknown_properties") is not True:
            raise ValueError("unknown properties are not marked review-only")
        return True, {
            "uid_properties_overlap": matched_count,
            "description_items": description_count,
            "review_only_rows": review_count,
        }
    except (KeyError, OSError, TypeError, ValueError, InvalidOperation) as exc:
        return False, str(exc)


def _netlab_artifact_reconciliation(
    manifest: dict[str, Any],
    files: dict[str, Any],
    summary: dict[str, Any],
) -> tuple[bool, Any]:
    if manifest.get("supplier") != "netlab":
        return True, "not_netlab"

    try:
        inputs = manifest["inputs"]
        if not isinstance(inputs, dict):
            raise TypeError("Netlab manifest inputs are invalid")

        def input_data(label: str) -> tuple[dict[str, Any], bytes]:
            record = inputs.get(label)
            if not isinstance(record, dict):
                raise TypeError(f"Netlab manifest input record is missing: {label}")
            bundle_path = record.get("bundle_path")
            if not _safe_bundle_path(bundle_path) or bundle_path not in files:
                raise ValueError(f"Netlab sealed input evidence is missing: {label}")
            return record, files[bundle_path].data

        source_record, source_data = input_data("source")
        catalog_record, catalog_data = input_data("catalog")
        config_record, config_data = input_data("config")
        source_metadata_record, source_metadata_data = input_data("source_metadata")
        content_summary = summary.get("content_enrichment")
        content_enabled = isinstance(content_summary, dict) and content_summary.get("enabled") is True
        properties_record: dict[str, Any] | None = None
        properties_data: bytes | None = None
        properties_metadata_record: dict[str, Any] | None = None
        properties_metadata_data: bytes | None = None
        if content_enabled:
            properties_record, properties_data = input_data("properties")
            properties_metadata_record, properties_metadata_data = input_data("properties_metadata")
        if config_record.get("status") == "not_provided":
            raise ValueError("Netlab verifier requires a bundled config")
        state_record = inputs.get("previous_state")
        state_data: bytes | None = None
        if isinstance(state_record, dict) and state_record.get("status") != "not_provided":
            bundle_path = state_record.get("bundle_path")
            if not _safe_bundle_path(bundle_path) or bundle_path not in files:
                raise ValueError("Netlab sealed previous-state evidence is missing")
            state_data = files[bundle_path].data

        def safe_original_name(record: dict[str, Any], fallback: str) -> str:
            value = record.get("original_name", fallback)
            if (
                not isinstance(value, str)
                or not value
                or Path(value).name != value
                or PurePosixPath(value).name != value
                or chr(92) in value
            ):
                raise ValueError("Netlab input original name is invalid")
            return value

        source_name = safe_original_name(source_record, "source.zip")
        catalog_name = safe_original_name(catalog_record, "catalog.csv")
        config_name = safe_original_name(config_record, "config.yaml")
        source_metadata_name = safe_original_name(source_metadata_record, "source-metadata.json")
        properties_name = (
            safe_original_name(properties_record, "properties.zip") if properties_record is not None else None
        )
        properties_metadata_name = (
            safe_original_name(properties_metadata_record, "properties-metadata.json")
            if properties_metadata_record is not None
            else None
        )
        state_name = safe_original_name(state_record, "previous-state.json") if state_data is not None else None
        fetched_at = manifest.get("fetched_at")
        if not isinstance(fetched_at, str) or not fetched_at:
            raise ValueError("Netlab manifest fetched_at is invalid")

        with tempfile.TemporaryDirectory(prefix="verify-netlab-recompute-") as temporary:
            temporary_root = Path(temporary)
            source_path = temporary_root / source_name
            catalog_path = temporary_root / catalog_name
            config_path = temporary_root / config_name
            source_metadata_path = temporary_root / source_metadata_name
            properties_path = temporary_root / properties_name if properties_name is not None else None
            properties_metadata_path = (
                temporary_root / properties_metadata_name if properties_metadata_name is not None else None
            )
            source_path.write_bytes(source_data)
            catalog_path.write_bytes(catalog_data)
            config_path.write_bytes(config_data)
            source_metadata_path.write_bytes(source_metadata_data)
            if properties_path is not None and properties_data is not None:
                properties_path.write_bytes(properties_data)
            if properties_metadata_path is not None and properties_metadata_data is not None:
                properties_metadata_path.write_bytes(properties_metadata_data)
            previous_state_path = None
            if state_data is not None and state_name is not None:
                previous_state_path = temporary_root / state_name
                previous_state_path.write_bytes(state_data)

            loaded_config = load_pilot_config(config_path)
            if loaded_config.supplier.id != "netlab":
                raise ValueError("captured config is not Netlab")
            adapter = create_adapter(
                loaded_config.supplier.id,
                expected_catalog_sku_prefix=loaded_config.supplier.scope.catalog_sku_prefix,
            )
            expected_dir = temporary_root / "expected"
            run_pilot(
                source_path,
                catalog_path,
                expected_dir,
                fetched_at,
                min_source_items=loaded_config.supplier.source.min_offer_count,
                max_source_items=loaded_config.supplier.source.max_offer_count,
                max_source_bytes=loaded_config.supplier.source.max_response_bytes,
                adapter=adapter,
                pricing_resolver=lambda snapshot: pricing_context_from_config(
                    loaded_config.pricing,
                    observed_at=snapshot.catalog_date or fetched_at,
                    supplier_id=loaded_config.supplier.id,
                    supplier_rates=snapshot.currencies,
                    source_sha256=snapshot.source_sha256,
                ),
                config_path=config_path,
                source_metadata_path=source_metadata_path,
                properties_path=properties_path,
                properties_metadata_path=properties_metadata_path,
                properties_fetched_at=(
                    content_summary.get("properties_fetched_at")
                    if isinstance(content_summary, dict)
                    else None
                ),
                previous_state_path=previous_state_path,
                missing_product_action=(
                    loaded_config.stock.missing_product_policy.action if loaded_config.stock else None
                ),
                consecutive_missing_runs=(
                    loaded_config.stock.missing_product_policy.consecutive_missing_runs
                    if loaded_config.stock
                    else None
                ),
            )
            expected_manifest = json.loads(
                read_evidence(expected_dir / MANIFEST_NAME).data.decode("utf-8")
            )
            expected_summary = json.loads(
                read_evidence(expected_dir / "reports/summary.json").data.decode("utf-8")
            )
            mismatches: list[str] = []
            expected_files = {
                path.relative_to(expected_dir).as_posix()
                for path in expected_dir.rglob("*")
                if path.is_file() and path.name != "seal.json"
            }
            actual_files = set(files)
            for name in sorted((actual_files | expected_files) - {MANIFEST_NAME, "pilot.duckdb"}):
                actual_evidence = files.get(name)
                expected_path = expected_dir / name
                if actual_evidence is None or not expected_path.is_file():
                    mismatches.append(f"artifact_set:{name}")
                elif actual_evidence.data != read_evidence(expected_path).data:
                    mismatches.append(f"artifact_bytes:{name}")

            actual_database = files.get("pilot.duckdb")
            expected_database = expected_dir / "pilot.duckdb"
            if actual_database is None or not expected_database.is_file():
                mismatches.append("artifact_set:pilot.duckdb")
            else:
                with tempfile.NamedTemporaryFile(prefix="verify-netlab-db-", suffix=".duckdb", delete=False) as handle:
                    handle.write(actual_database.data)
                    actual_database_path = Path(handle.name)
                try:
                    actual_digest = database_content_sha256(actual_database_path)
                finally:
                    actual_database_path.unlink(missing_ok=True)
                expected_digest = database_content_sha256(expected_database)
                if actual_digest != expected_digest:
                    mismatches.append("duckdb_content")

            expected_manifest_without_diagnostics = dict(expected_manifest)
            actual_manifest_without_diagnostics = dict(manifest)
            expected_manifest_without_diagnostics.pop("diagnostics", None)
            actual_manifest_without_diagnostics.pop("diagnostics", None)
            if expected_manifest_without_diagnostics != actual_manifest_without_diagnostics:
                mismatches.append("manifest_semantics")
            if expected_summary != summary:
                mismatches.append("summary_semantics")
            return not mismatches, {
                "mismatches": mismatches,
                "expected_artifacts": len(expected_files),
                "actual_artifacts": len(actual_files),
            }
    except (KeyError, OSError, TypeError, ValueError, InvalidOperation, json.JSONDecodeError) as exc:
        return False, str(exc)


def _netlab_pricing_semantics(
    manifest: dict[str, Any],
    files: dict[str, Any],
    rows: dict[str, list[dict[str, str]]],
) -> tuple[bool, Any]:
    if manifest.get("supplier") != "netlab":
        return True, "not_netlab"
    try:
        inputs = manifest["inputs"]
        source_record = inputs["source"]
        config_record = inputs["config"]
        source_metadata_record = inputs["source_metadata"]
        source_evidence = files[source_record["bundle_path"]]
        config_evidence = files[config_record["bundle_path"]]
        source_metadata_evidence = files[source_metadata_record["bundle_path"]]
        if not source_record["bundle_path"].casefold().endswith(".zip"):
            raise ValueError("Netlab source is not a captured ZIP")
        with tempfile.TemporaryDirectory(prefix="verify-netlab-") as temporary:
            temporary_root = Path(temporary)
            source_path = temporary_root / "source.zip"
            config_path = temporary_root / "config.yaml"
            source_path.write_bytes(source_evidence.data)
            config_path.write_bytes(config_evidence.data)
            config = load_pilot_config(config_path)
            snapshot = NetlabAdapter().parse(
                source_path,
                fetched_at=str(manifest.get("fetched_at") or ""),
                min_items=config.supplier.source.min_offer_count,
                max_items=config.supplier.source.max_offer_count,
                max_bytes=config.supplier.source.max_response_bytes,
            )
        if config.supplier.id != "netlab":
            raise ValueError("captured config is not Netlab")
        metadata_payload = parse_netlab_acquisition_metadata(source_metadata_evidence.data)
        validate_netlab_acquisition_metadata(
            metadata_payload,
            source_data=source_evidence.data,
            expected_fetched_at=str(manifest.get("fetched_at") or ""),
            expected_catalog_date=snapshot.catalog_date,
            expected_item_count=len(snapshot.items),
            expected_currency_rates=snapshot.currencies,
        )
        configured_rates = config.pricing.exchange_rates
        if set(configured_rates) != {"USD"}:
            raise ValueError("Netlab config must declare exactly one USD rate")
        configured_usd = configured_rates["USD"]
        if (
            configured_usd.source != "supplier_feed"
            or configured_usd.min_rub_per_unit != Decimal(40)
            or configured_usd.max_rub_per_unit != Decimal(200)
        ):
            raise ValueError("Netlab USD bounds/source are not the approved exact contract")
        supplier_rate = snapshot.currencies.get("USD")
        if supplier_rate is None or not Decimal(40) <= supplier_rate <= Decimal(200):
            raise ValueError("captured Netlab ZIP has no approved USD rate")
        policy = manifest["policy"]
        rates = policy.get("rates")
        if not isinstance(rates, dict) or set(rates) != {"USD"}:
            raise ValueError("manifest must declare exactly one Netlab USD rate")
        rate = rates["USD"]
        if (
            rate.get("currency") != "USD"
            or Decimal(str(rate.get("rub_per_unit"))) != supplier_rate
            or rate.get("source") != "supplier_feed"
            or rate.get("approved") is not True
            or rate.get("supplier_id") != "netlab"
            or rate.get("source_sha256") != source_evidence.sha256
            or rate.get("observed_at") != snapshot.catalog_date
        ):
            raise ValueError("manifest Netlab rate is not bound to the captured supplier ZIP")
        rule = policy.get("rule")
        if (
            policy.get("vat_basis") != "included"
            or not isinstance(rule, dict)
            or rule.get("approved") is not True
            or Decimal(str(rule.get("multiplier"))) != Decimal("1.10")
        ):
            raise ValueError("manifest Netlab pricing policy is not approved")
        source_time = datetime.strptime(str(snapshot.catalog_date), "%Y-%m-%d %H:%M").replace(tzinfo=_MOSCOW)
        fetched_time = datetime.fromisoformat(str(manifest.get("fetched_at")))
        if fetched_time.tzinfo is None:
            raise ValueError("Netlab fetch timestamp has no timezone")
        age = fetched_time.astimezone(UTC) - source_time.astimezone(UTC)
        if age < -timedelta(minutes=15) or age > timedelta(hours=24):
            raise ValueError("Netlab supplier timestamp violates freshness contract")
        normalized = {row.get("supplier_item_id"): row for row in rows.get("normalized", [])}
        for proposal in rows.get("proposals", []):
            if not proposal.get("proposed_price"):
                continue
            item = normalized.get(proposal.get("supplier_item_id"))
            if item is None or item.get("currency") != "USD":
                raise ValueError("priced Netlab proposal is not a normalized USD item")
            source_price = Decimal(str(item.get("source_price")))
            cost = source_price * supplier_rate
            calculated = cost * Decimal("1.10")
            if (
                Decimal(str(proposal.get("source_price"))) != source_price
                or proposal.get("source_currency") != "USD"
                or Decimal(str(proposal.get("exchange_rate"))) != supplier_rate
                or proposal.get("exchange_rate_source") != "supplier_feed"
                or proposal.get("markup_rule_id") != rule.get("id")
                or proposal.get("markup_rule_version") != rule.get("version")
                or Decimal(str(proposal.get("cost_rub"))) != cost
                or Decimal(str(proposal.get("calculated_price"))) != calculated
                or Decimal(str(proposal.get("proposed_price"))) != calculated
            ):
                raise ValueError("Netlab proposal does not equal priceE × supplier USD rate × 1.10")
        return True, {"usd_rate": str(supplier_rate), "proposals": len(rows.get("proposals", []))}
    except (KeyError, OSError, TypeError, ValueError, InvalidOperation) as exc:
        return False, str(exc)


def verify_run(
    run_dir: str | Path,
    *,
    source: str | Path | None = None,
    catalog: str | Path | None = None,
    config: str | Path | None = None,
) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {}
    try:
        sealed = load_sealed_run(run_dir)
    except Exception as exc:  # noqa: BLE001 - verifier must return a machine result
        _check(checks, "run_seal", False, str(exc))
        return _result(checks)
    files = sealed.files
    _check(checks, "run_seal", True, {"files": len(files), "sha256": sealed.seal_evidence.sha256})

    manifest_evidence = files.get(MANIFEST_NAME)
    manifest: dict[str, Any] | None = None
    if manifest_evidence is None:
        _check(checks, "manifest_present", False, MANIFEST_NAME)
    else:
        try:
            candidate = json.loads(manifest_evidence.data.decode("utf-8"))
            manifest = candidate if isinstance(candidate, dict) else None
            _check(checks, "manifest_present", manifest is not None, "parsed")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _check(checks, "manifest_present", False, str(exc))

    if manifest is None:
        return _result(checks)

    required_manifest = {
        "manifest_version",
        "run_id",
        "canonical_run_id",
        "supplier",
        "inputs",
        "policy",
        "code_identity",
        "summary",
    }
    _check(
        checks,
        "manifest_structure",
        manifest.get("manifest_version") == 1
        and required_manifest <= set(manifest)
        and manifest.get("run_id") == manifest.get("canonical_run_id")
        and isinstance(manifest.get("run_id"), str)
        and isinstance(manifest.get("supplier"), str)
        and _RUN_ID.fullmatch(manifest["run_id"]) is not None,
        {"run_id": manifest.get("run_id"), "supplier": manifest.get("supplier")},
    )
    _check(
        checks,
        "canonical_run_id",
        _canonical_run_id_matches(manifest),
        manifest.get("canonical_run_id"),
    )

    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        _check(checks, "manifest_inputs", False, "inputs must be an object")
        inputs = {}
    else:
        _check(checks, "manifest_inputs", True, sorted(inputs))

    manifest_content = manifest.get("summary", {}).get("content_enrichment") if isinstance(manifest.get("summary"), dict) else None
    content_required = manifest.get("supplier") == "netlab" and isinstance(manifest_content, dict) and manifest_content.get("enabled") is True
    for label in ("source", "catalog", "source_metadata", "properties", "properties_metadata"):
        record = inputs.get(label)
        if label in {"source_metadata", "properties", "properties_metadata"} and isinstance(record, dict) and record.get("status") == "not_provided":
            required = label == "source_metadata" and manifest.get("supplier") == "netlab" or label != "source_metadata" and content_required
            _check(
                checks,
                f"bundle_{label}",
                not required,
                "not_provided",
            )
            continue
        if not isinstance(record, dict) or not _safe_bundle_path(record.get("bundle_path")):
            _check(checks, f"bundle_{label}", False, "invalid input record")
            continue
        bundle_path = record["bundle_path"]
        evidence = files.get(bundle_path)
        actual = {"sha256": evidence.sha256, "size": len(evidence.data)} if evidence else None
        expected = {"sha256": record.get("sha256"), "size": record.get("size")}
        _check(checks, f"bundle_{label}", actual == expected, {"actual": actual, "expected": expected})
    config_record = inputs.get("config")
    if isinstance(config_record, dict) and config_record.get("status") == "not_provided":
        _check(checks, "bundle_config", True, "not_provided")
    elif isinstance(config_record, dict) and _safe_bundle_path(config_record.get("bundle_path")):
        evidence = files.get(config_record["bundle_path"])
        actual = {"sha256": evidence.sha256, "size": len(evidence.data)} if evidence else None
        expected = {"sha256": config_record.get("sha256"), "size": config_record.get("size")}
        _check(checks, "bundle_config", actual == expected, {"actual": actual, "expected": expected})
    else:
        _check(checks, "bundle_config", False, "invalid config record")
    previous_state_record = inputs.get("previous_state")
    if isinstance(previous_state_record, dict) and previous_state_record.get("status") == "not_provided":
        _check(checks, "bundle_previous_state", True, "not_provided")
    elif isinstance(previous_state_record, dict) and _safe_bundle_path(previous_state_record.get("bundle_path")):
        evidence = files.get(previous_state_record["bundle_path"])
        actual = {"sha256": evidence.sha256, "size": len(evidence.data)} if evidence else None
        expected = {"sha256": previous_state_record.get("sha256"), "size": previous_state_record.get("size")}
        _check(checks, "bundle_previous_state", actual == expected, {"actual": actual, "expected": expected})
    else:
        _check(checks, "bundle_previous_state", False, "invalid previous state record")

    policy = manifest.get("policy")
    if isinstance(policy, dict) and isinstance(policy.get("hash"), str):
        policy_without_hash = {key: value for key, value in policy.items() if key != "hash"}
        _check(
            checks,
            "policy_hash",
            _sha256(_canonical_bytes(policy_without_hash)) == policy["hash"],
            policy["hash"],
        )
    else:
        _check(checks, "policy_hash", False, "missing policy hash")
    _check(
        checks,
        "rate_source_identity",
        _rate_source_hash_matches(manifest),
        {
            "source_sha256": inputs.get("source", {}).get("sha256")
            if isinstance(inputs.get("source"), dict)
            else None,
            "supplier": manifest.get("supplier"),
        },
    )
    code_identity = manifest.get("code_identity")
    _check(
        checks,
        "code_identity_hash",
        _code_identity_hash_matches(code_identity),
        code_identity.get("sha256") if isinstance(code_identity, dict) else None,
    )

    source_record = inputs.get("source", {}) if isinstance(inputs.get("source"), dict) else {}
    catalog_record = inputs.get("catalog", {}) if isinstance(inputs.get("catalog"), dict) else {}
    config_record = inputs.get("config", {}) if isinstance(inputs.get("config"), dict) else {}
    _external_check(checks, "source", Path(source) if source is not None else None, source_record)
    _external_check(checks, "catalog", Path(catalog) if catalog is not None else None, catalog_record)
    if config is not None and config_record.get("status") == "not_provided":
        _check(checks, "external_config_manifest", False, "run has no bundled config")
    _external_check(checks, "config", Path(config) if config is not None else None, config_record)

    summary_evidence = files.get("reports/summary.json")
    try:
        summary = json.loads(summary_evidence.data.decode("utf-8")) if summary_evidence else None
        _check(checks, "summary_present", isinstance(summary, dict), "parsed")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        summary = None
        _check(checks, "summary_present", False, str(exc))
    if not isinstance(summary, dict):
        return _result(checks)

    manifest_summary = manifest.get("summary")
    summary_keys = (
        "source_items",
        "catalog_scope_items",
        "matches",
        "proposals",
        "feed_completeness",
        "missing_product_state",
        "content_enrichment",
        "duckdb_content_sha256",
        "production_writes",
    )
    _check(
        checks,
        "manifest_summary_consistency",
        isinstance(manifest_summary, dict)
        and all(manifest_summary.get(key) == summary.get(key) for key in summary_keys),
        {key: summary.get(key) for key in summary_keys},
    )
    _check(
        checks,
        "production_writes_zero",
        summary.get("mode") == "read_only" and summary.get("production_writes") == 0,
        {"mode": summary.get("mode"), "production_writes": summary.get("production_writes")},
    )
    previous_state_payload: dict[str, Any] | None = None
    previous_state_record = inputs.get("previous_state")
    if isinstance(previous_state_record, dict) and previous_state_record.get("status") != "not_provided":
        previous_state_bundle = previous_state_record.get("bundle_path")
        previous_state_evidence = files.get(previous_state_bundle) if _safe_bundle_path(previous_state_bundle) else None
        try:
            candidate_previous = json.loads(previous_state_evidence.data.decode("utf-8")) if previous_state_evidence else None
            previous_state_payload = candidate_previous if isinstance(candidate_previous, dict) else {"invalid": True}
            _check(
                checks,
                "previous_state_input_structure",
                isinstance(candidate_previous, dict),
                "parsed",
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            previous_state_payload = {"invalid": True}
            _check(checks, "previous_state_input_structure", False, "invalid JSON")
    elif isinstance(previous_state_record, dict) and previous_state_record.get("status") == "not_provided":
        _check(checks, "previous_state_input_structure", True, "not_provided")
    else:
        previous_state_payload = {"invalid": True}
        _check(checks, "previous_state_input_structure", False, "invalid input record")
    state_evidence = files.get("state/next-missing-state.json")
    state_payload: dict[str, Any] | None = None
    if state_evidence is not None:
        try:
            candidate_state = json.loads(state_evidence.data.decode("utf-8"))
            state_payload = candidate_state if isinstance(candidate_state, dict) else None
            _check(
                checks,
                "missing_state_present",
                state_payload is not None
                and state_payload.get("schema_version") == 1
                and state_payload.get("supplier") == summary.get("supplier")
                and isinstance(state_payload.get("products"), dict),
                "parsed",
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _check(checks, "missing_state_present", False, str(exc))
    else:
        _check(checks, "missing_state_present", False, "missing")
    artifact_names = {
        "normalized": "normalized/items.csv",
        "normalized_jsonl": "normalized/items.jsonl",
        "matches": "matches/matches.csv",
        "source_only": "matches/source_only.csv",
        "review_queue": "matches/review_queue.csv",
        "proposals": "proposals/proposals.csv",
        "category_mapping": "proposals/category-mapping-proposals.csv",
        "product_categories": "proposals/product-category-proposals.csv",
        "missing": "matches/catalog_missing_supplier.csv",
    }
    rows: dict[str, list[dict[str, str]]] = {}
    for label, name in artifact_names.items():
        evidence = files.get(name)
        if evidence is None:
            _check(checks, f"artifact_{label}", False, "missing")
            rows[label] = []
            continue
        try:
            if label == "normalized_jsonl":
                parsed = _jsonl_rows(evidence.data)
            else:
                parsed = _csv_rows(evidence.data)
            rows[label] = parsed
            _check(checks, f"artifact_{label}", True, len(parsed))
        except (UnicodeDecodeError, csv.Error, json.JSONDecodeError, TypeError, ValueError) as exc:
            rows[label] = []
            _check(checks, f"artifact_{label}", False, str(exc))

    expected_counts = {
        "normalized": summary.get("source_items"),
        "normalized_jsonl": summary.get("source_items"),
        "matches": summary.get("source_items"),
        "proposals": summary.get("source_items"),
        "source_only": summary.get("source_only"),
        "review_queue": summary.get("review_queue"),
        "category_mapping": summary.get("category_mapping", {}).get("source_categories"),
        "product_categories": summary.get("category_mapping", {}).get("source_only_products"),
        "missing": summary.get("catalog_missing_supplier"),
    }
    for label, expected in expected_counts.items():
        _check(checks, f"count_{label}", expected is not None and len(rows[label]) == expected, {"actual": len(rows[label]), "expected": expected})

    feed_completeness = summary.get("feed_completeness")
    missing_decision = summary.get("missing_product_state")
    catalog_scope: dict[str, str] = {}
    catalog_scope_error: str | None = None
    try:
        catalog_evidence = files[catalog_record["bundle_path"]]
        prefix = summary.get("catalog_sku_prefix", manifest.get("catalog_sku_prefix"))
        catalog_scope = _catalog_scope_map(catalog_evidence.data, prefix)
    except (KeyError, TypeError, ValueError) as exc:
        catalog_scope_error = str(exc)
    _check(
        checks,
        "catalog_scope_reconciliation",
        catalog_scope_error is None,
        catalog_scope_error or {"items": len(catalog_scope)},
    )
    source_hash = source_record.get("sha256")
    catalog_hash = catalog_record.get("sha256")
    expected_state_run_id = None
    if isinstance(summary.get("supplier"), str) and isinstance(source_hash, str) and isinstance(catalog_hash, str):
        expected_state_run_id = (
            f"{summary['supplier']}-{source_hash[:12]}-catalog-{catalog_hash[:12]}"
        )
    completeness_ok, completeness_detail = _missing_action_gate(
        feed_completeness,
        missing_decision,
        state_payload,
        rows["missing"],
        summary.get("catalog_scope_items"),
        supplier=summary.get("supplier"),
        source_items=summary.get("source_items"),
        catalog_scope=catalog_scope,
        previous_state_payload=previous_state_payload,
        expected_run_id=expected_state_run_id,
        missing_policy=summary.get("missing_product_policy"),
    )
    _check(checks, "missing_action_gate", completeness_ok, completeness_detail)

    normalized = rows["normalized"]
    normalized_jsonl = rows["normalized_jsonl"]
    _check(
        checks,
        "normalized_identity_unique",
        len({row.get("supplier_item_id") for row in normalized}) == len(normalized)
        and len({row.get("catalog_sku") for row in normalized}) == len(normalized),
        len(normalized),
    )
    _check(
        checks,
        "normalized_jsonl_identity_parity",
        [row.get("supplier_item_id") for row in normalized_jsonl] == [row.get("supplier_item_id") for row in normalized],
        len(normalized_jsonl),
    )
    match_counts = dict(sorted(Counter(row.get("status") for row in rows["matches"]).items()))
    proposal_counts = dict(sorted(Counter(row.get("status") for row in rows["proposals"]).items()))
    _check(checks, "match_status_counts", match_counts == summary.get("matches"), match_counts)
    _check(checks, "proposal_status_counts", proposal_counts == summary.get("proposals"), proposal_counts)
    netlab_pricing_ok, netlab_pricing_detail = _netlab_pricing_semantics(manifest, files, rows)
    _check(checks, "netlab_pricing_semantics", netlab_pricing_ok, netlab_pricing_detail)
    netlab_content_ok, netlab_content_detail = _netlab_content_semantics(manifest, files, rows)
    _check(checks, "netlab_content_semantics", netlab_content_ok, netlab_content_detail)
    netlab_artifacts_ok, netlab_artifacts_detail = _netlab_artifact_reconciliation(manifest, files, summary)
    _check(checks, "netlab_artifact_reconciliation", netlab_artifacts_ok, netlab_artifacts_detail)

    database_evidence = files.get("pilot.duckdb")
    if database_evidence is None:
        _check(checks, "duckdb_counts", False, "missing database")
    else:
        table_names = (
            "normalized_items",
            "matches",
            "source_only",
            "review_queue",
            "proposals",
            "category_mapping_proposals",
            "product_category_proposals",
            "catalog_missing_supplier",
        )
        expected_db = {
            "normalized_items": len(rows["normalized"]),
            "matches": len(rows["matches"]),
            "source_only": len(rows["source_only"]),
            "review_queue": len(rows["review_queue"]),
            "proposals": len(rows["proposals"]),
            "category_mapping_proposals": len(rows["category_mapping"]),
            "product_category_proposals": len(rows["product_categories"]),
            "catalog_missing_supplier": len(rows["missing"]),
        }
        with tempfile.NamedTemporaryFile(prefix="verify-run-", suffix=".duckdb", delete=False) as handle:
            handle.write(database_evidence.data)
            database_path = Path(handle.name)
        try:
            actual_db = read_only_table_counts(database_path, table_names)
            _check(checks, "duckdb_counts", actual_db == expected_db, {"actual": actual_db, "expected": expected_db})
            actual_digest = database_content_sha256(database_path)
            _check(
                checks,
                "duckdb_content_digest",
                actual_digest == summary.get("duckdb_content_sha256"),
                {"actual": actual_digest, "expected": summary.get("duckdb_content_sha256")},
            )
        except Exception as exc:  # noqa: BLE001 - verifier reports any database mismatch
            _check(checks, "duckdb_counts", False, str(exc))
        finally:
            database_path.unlink(missing_ok=True)

    return _result(checks)
