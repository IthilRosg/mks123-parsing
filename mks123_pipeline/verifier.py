from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import duckdb

from .db_digest import database_content_sha256
from .integrity import load_sealed_run
from .manifest import MANIFEST_NAME

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


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


def _external_check(
    checks: dict[str, dict[str, Any]],
    label: str,
    path: Path | None,
    record: dict[str, Any],
) -> None:
    if path is None:
        return
    try:
        data = path.read_bytes()
        actual = {"sha256": _sha256(data), "size": len(data)}
        expected = {"sha256": record.get("sha256"), "size": record.get("size")}
        _check(checks, f"external_{label}_hash", actual == expected, {"actual": actual, "expected": expected})
    except OSError as exc:
        _check(checks, f"external_{label}_hash", False, str(exc))


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

    required_manifest = {"manifest_version", "run_id", "canonical_run_id", "supplier", "inputs", "policy", "summary"}
    _check(
        checks,
        "manifest_structure",
        manifest.get("manifest_version") == 1
        and required_manifest <= set(manifest)
        and manifest.get("run_id") == manifest.get("canonical_run_id")
        and isinstance(manifest.get("supplier"), str)
        and _RUN_ID.fullmatch(manifest["run_id"]) is not None,
        {"run_id": manifest.get("run_id"), "supplier": manifest.get("supplier")},
    )

    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        _check(checks, "manifest_inputs", False, "inputs must be an object")
        inputs = {}
    else:
        _check(checks, "manifest_inputs", True, sorted(inputs))

    for label in ("source", "catalog"):
        record = inputs.get(label)
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
    feed_completeness = summary.get("feed_completeness")
    missing_decision = summary.get("missing_product_state")
    completeness_gate = isinstance(feed_completeness, dict) and isinstance(missing_decision, dict)
    if completeness_gate and feed_completeness.get("status") == "blocked_incomplete":
        completeness_gate = (
            feed_completeness.get("missing_actions_allowed") is False
            and missing_decision.get("actions_allowed") is False
            and not missing_decision.get("proposed_actions")
        )
    _check(checks, "missing_action_gate", completeness_gate, {
        "feed_completeness": feed_completeness,
        "missing_product_state": missing_decision,
    })

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
            with duckdb.connect(str(database_path), read_only=True) as db:
                actual_db = {name: db.execute(f"select count(*) from {name}").fetchone()[0] for name in table_names}
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
