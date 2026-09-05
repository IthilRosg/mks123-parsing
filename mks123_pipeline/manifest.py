from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any

from .integrity import read_evidence
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
    if read_evidence(path).data != data:
        raise RuntimeError(f"manifest read-back mismatch: {path.name}")


def _capture_file(
    source: Path,
    target: Path,
    *,
    original_name: str,
    max_bytes: int | None = None,
) -> dict[str, Any]:
    evidence = read_evidence(source, max_bytes=max_bytes)
    data = evidence.data
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError(f"source size exceeds byte limit: {max_bytes}")
    _write_exclusive(target, data)
    captured = read_evidence(target)
    digest = _sha256(data)
    if captured.data != data or captured.sha256 != digest:
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
    source_metadata_path: Path | None = None,
    properties_path: Path | None = None,
    properties_metadata_path: Path | None = None,
    source_max_bytes: int | None = None,
) -> tuple[
    dict[str, dict[str, Any]],
    Path,
    Path,
    Path | None,
    Path | None,
    Path | None,
    Path | None,
    Path | None,
]:
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
        bundled_config = inputs_dir / "config.yaml"
        records["config"] = _capture_file(config_path, bundled_config, original_name=config_path.name)
        config_text = read_evidence(bundled_config).data.decode("utf-8")
        if _SECRET_VALUE.search(config_text):
            raise ValueError("config contains an inline secret; use a credential reference")
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
    bundled_source_metadata: Path | None = None
    if source_metadata_path is not None:
        bundled_source_metadata = inputs_dir / "source-metadata.json"
        records["source_metadata"] = _capture_file(
            source_metadata_path,
            bundled_source_metadata,
            original_name=source_metadata_path.name,
            max_bytes=4 * 1024 * 1024,
        )
    else:
        records["source_metadata"] = {"status": "not_provided"}
    bundled_properties: Path | None = None
    bundled_properties_metadata: Path | None = None
    if (properties_path is None) != (properties_metadata_path is None):
        raise ValueError("properties and properties metadata must be provided together")
    if properties_path is not None and properties_metadata_path is not None:
        bundled_properties = inputs_dir / "properties.zip"
        bundled_properties_metadata = inputs_dir / "properties-metadata.json"
        records["properties"] = _capture_file(
            properties_path,
            bundled_properties,
            original_name=properties_path.name,
            max_bytes=source_max_bytes,
        )
        records["properties_metadata"] = _capture_file(
            properties_metadata_path,
            bundled_properties_metadata,
            original_name=properties_metadata_path.name,
            max_bytes=4 * 1024 * 1024,
        )
    else:
        records["properties"] = {"status": "not_provided"}
        records["properties_metadata"] = {"status": "not_provided"}
    return (
        records,
        bundled_source,
        bundled_catalog,
        bundled_config,
        bundled_state,
        bundled_source_metadata,
        bundled_properties,
        bundled_properties_metadata,
    )


def policy_payload(pricing: PricingContext) -> dict[str, Any]:
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
        "rates": {
            currency: {
                "currency": rate.currency,
                "rub_per_unit": str(rate.rub_per_unit),
                "source": rate.source,
                "observed_at": rate.observed_at,
                "approved": rate.approved,
                "supplier_id": rate.supplier_id,
                "source_sha256": rate.source_sha256,
            }
            for currency, rate in sorted(pricing.rates.items())
        },
    }


def policy_sha256(pricing: PricingContext) -> str:
    return _sha256(_canonical_bytes(policy_payload(pricing)))


def code_identity(project_root: Path, adapter_module: Path | None = None) -> dict[str, Any]:
    paths = set((project_root / "mks123_pipeline").glob("*.py"))
    paths.update(
        project_root / relative
        for relative in (
            "run_pilot.py",
            "verify_run.py",
            "scripts/fetch_netlab_current.py",
            "scripts/run_netlab_shadow.py",
            "pyproject.toml",
            "uv.lock",
        )
    )
    if adapter_module is not None and adapter_module.is_file():
        paths.add(adapter_module)
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(paths, key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        data = read_evidence(path).data
        files[path.relative_to(project_root).as_posix()] = {"sha256": _sha256(data), "size": len(data)}
    dependencies = {}
    for distribution in ("defusedxml", "duckdb", "fsspec", "pandas", "pydantic", "PyYAML"):
        try:
            dependencies[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            dependencies[distribution] = "not-installed"
    runtime = {
        "implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "cache_tag": sys.implementation.cache_tag,
        "dependencies": dependencies,
    }
    identity_payload = {"files": files, "runtime": runtime}
    return {
        "schema_version": "1",
        "files": files,
        "runtime": runtime,
        "sha256": _sha256(_canonical_bytes(identity_payload)),
    }


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
    policy = policy_payload(pricing)
    policy_hash = _sha256(_canonical_bytes(policy))
    source_record = input_records["source"]
    catalog_record = input_records["catalog"]
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
    executable_identity = code_identity(project_root, adapter_module)
    config_record = input_records["config"]
    config_hash = config_record.get("sha256")
    if not isinstance(config_hash, str):
        config_hash = _sha256(_canonical_bytes(config_record))
    canonical_run_id = (
        f"{adapter.supplier_id}-{source_record['sha256'][:12]}-"
        f"catalog-{catalog_record['sha256'][:12]}-config-{config_hash[:12]}-"
        f"policy-{policy_hash[:12]}-code-{executable_identity['sha256'][:12]}"
    )
    properties_record = input_records.get("properties")
    if isinstance(properties_record, dict) and isinstance(properties_record.get("sha256"), str):
        canonical_run_id += f"-properties-{properties_record['sha256'][:12]}"
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
        "code_identity": executable_identity,
        "diagnostics": {
            "source_path": source_record.get("bundle_path"),
            "catalog_path": catalog_record.get("bundle_path"),
            "config_path": config_record.get("bundle_path")
            if isinstance(config_record, dict)
            else None,
        },
        "summary": {
            "source_items": summary["source_items"],
            "catalog_scope_items": summary["catalog_scope_items"],
            "matches": summary["matches"],
            "proposals": summary["proposals"],
            "feed_completeness": summary.get("feed_completeness"),
            "missing_product_state": summary.get("missing_product_state"),
            "content_enrichment": summary.get("content_enrichment"),
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
        payload = json.loads(read_evidence(Path(path)).data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid run manifest") from exc
    if not isinstance(payload, dict) or payload.get("manifest_version") != MANIFEST_VERSION:
        raise ValueError("invalid run manifest structure")
    return payload
