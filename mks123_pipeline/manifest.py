from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .pricing import PricingContext

MANIFEST_NAME = "run-manifest.json"
MANIFEST_VERSION = 1
_SAFE_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,12}$")
_SECRET_VALUE = re.compile(
    r"(?im)^\s*(?:password|passwd|token|api[_-]?key|secret)\s*:\s*['\"]?\S+"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    if path.read_bytes() != data:
        raise RuntimeError(f"manifest read-back mismatch: {path.name}")


def _capture_file(
    source: Path,
    target: Path,
    *,
    original_name: str,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    data = source.read_bytes()
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError(f"source size exceeds byte limit: {max_bytes}")
    _write_exclusive(target, data)
    captured = target.read_bytes()
    digest = _sha256(data)
    if captured != data or _sha256(captured) != digest:
        raise RuntimeError(f"captured input read-back mismatch: {target.name}")
    return {
        "original_name": original_name,
        "bundle_path": target.relative_to(target.parents[1]).as_posix(),
        "sha256": digest,
        "size": len(data),
    }


def capture_run_inputs(
    output_dir: Path,
    source_path: Path,
    catalog_path: Path,
    config_path: Path | None = None,
    previous_state_path: Path | None = None,
    source_max_bytes: int | None = None,
) -> tuple[dict[str, dict[str, Any]], Path, Path, Path | None, Path | None]:
    inputs_dir = output_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    suffix = source_path.suffix.lower()
    source_suffix = suffix if _SAFE_SUFFIX.fullmatch(suffix) else ".feed"
    bundled_source = inputs_dir / f"source{source_suffix}"
    bundled_catalog = inputs_dir / "catalog.csv"
    records = {
        "source": _capture_file(
            source_path,
            bundled_source,
            original_name=source_path.name,
            max_bytes=source_max_bytes,
        ),
        "catalog": _capture_file(catalog_path, bundled_catalog, original_name=catalog_path.name),
    }
    bundled_config: Path | None = None
    if config_path is not None:
        config_text = config_path.read_text(encoding="utf-8")
        if _SECRET_VALUE.search(config_text):
            raise ValueError("config contains an inline secret; use a credential reference")
        bundled_config = inputs_dir / "config.yaml"
        records["config"] = _capture_file(config_path, bundled_config, original_name=config_path.name)
    else:
        records["config"] = {"status": "not_provided"}
    bundled_state: Path | None = None
    if previous_state_path is not None:
        bundled_state = inputs_dir / "previous-state.json"
        records["previous_state"] = _capture_file(
            previous_state_path,
            bundled_state,
            original_name=previous_state_path.name,
            max_bytes=4 * 1024 * 1024,
        )
    else:
        records["previous_state"] = {"status": "not_provided"}
    return records, bundled_source, bundled_catalog, bundled_config, bundled_state


def _policy_payload(pricing: PricingContext) -> dict[str, Any]:
    rule = None
    if pricing.rule is not None:
        rule = {
            "id": pricing.rule.id,
            "version": pricing.rule.version,
            "approved": pricing.rule.approved,
            "multiplier": str(pricing.rule.multiplier),
        }
    return {
        "vat_basis": pricing.vat_basis,
        "max_delta_pct": str(pricing.max_delta_pct),
        "rule": rule,
    }


def _code_identity(project_root: Path, adapter_module: Path | None) -> dict[str, Any]:
    paths = [
        project_root / "mks123_pipeline/runner.py",
        project_root / "mks123_pipeline/manifest.py",
        project_root / "mks123_pipeline/models.py",
        project_root / "mks123_pipeline/matcher.py",
        project_root / "mks123_pipeline/pricing.py",
    ]
    if adapter_module is not None:
        paths.append(adapter_module)
    files: dict[str, dict[str, Any]] = {}
    for path in paths:
        if not path.is_file():
            continue
        data = path.read_bytes()
        files[path.relative_to(project_root).as_posix()] = {"sha256": _sha256(data), "size": len(data)}
    return {"schema_version": "1", "files": files}


def build_run_manifest(
    output_dir: Path,
    *,
    source_path: Path,
    catalog_path: Path,
    config_path: Path | None,
    input_records: dict[str, dict[str, Any]],
    adapter: Any,
    snapshot: Any,
    fetched_at: str,
    pricing: PricingContext,
    summary: dict[str, Any],
) -> dict[str, Any]:
    policy = _policy_payload(pricing)
    policy_hash = _sha256(_canonical_bytes(policy))
    source_record = input_records["source"]
    catalog_record = input_records["catalog"]
    canonical_run_id = (
        f"{adapter.supplier_id}-{source_record['sha256'][:12]}-"
        f"catalog-{catalog_record['sha256'][:12]}-policy-{policy_hash[:12]}"
    )
    adapter_module = None
    module = getattr(adapter, "__class__", None)
    module_name = getattr(module, "__module__", "")
    if module_name:
        try:
            import importlib

            loaded = importlib.import_module(module_name)
            module_file = getattr(loaded, "__file__", None)
            adapter_module = Path(module_file).resolve() if module_file else None
        except (ImportError, OSError, RuntimeError):
            adapter_module = None
    project_root = Path(__file__).resolve().parents[1]
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "run_id": canonical_run_id,
        "canonical_run_id": canonical_run_id,
        "supplier": adapter.supplier_id,
        "catalog_sku_prefix": adapter.catalog_sku_prefix,
        "adapter": {
            "id": adapter.supplier_id,
            "class": f"{adapter.__class__.__module__}.{adapter.__class__.__name__}",
        },
        "inputs": input_records,
        "fetched_at": fetched_at,
        "source_catalog_date": snapshot.catalog_date,
        "policy": {**policy, "hash": policy_hash},
        "code_identity": _code_identity(project_root, adapter_module),
        "diagnostics": {
            "source_path": str(source_path),
            "catalog_path": str(catalog_path),
            "config_path": str(config_path) if config_path is not None else None,
        },
        "summary": {
            "source_items": summary["source_items"],
            "catalog_scope_items": summary["catalog_scope_items"],
            "matches": summary["matches"],
            "proposals": summary["proposals"],
            "feed_completeness": summary.get("feed_completeness"),
            "missing_product_state": summary.get("missing_product_state"),
            "duckdb_content_sha256": summary.get("duckdb_content_sha256"),
            "production_writes": summary["production_writes"],
        },
    }
    return manifest


def write_run_manifest(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    payload = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_exclusive(path, payload.encode("utf-8"))
    return manifest


def read_run_manifest(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid run manifest") from exc
    if not isinstance(payload, dict) or payload.get("manifest_version") != MANIFEST_VERSION:
        raise ValueError("invalid run manifest structure")
    return payload
