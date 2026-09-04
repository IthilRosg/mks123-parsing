from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from mks123_pipeline.adapters import create_adapter
from mks123_pipeline.config import load_pilot_config, pricing_context_from_config
from mks123_pipeline.runner import run_pilot
from mks123_pipeline.verifier import verify_run

SUPPLIER_CONFIGS = {
    "electrozone": "pilot.yaml",
    "netlab": "netlab.yaml",
    "vetcom": "vetcom.yaml",
}
_SAFE_STAMP = re.compile(r"[^A-Za-z0-9_.-]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _parse_sources(values: list[str]) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    for value in values:
        supplier, separator, raw_path = value.partition("=")
        if not separator or supplier not in SUPPLIER_CONFIGS or not raw_path:
            raise ValueError(f"source must use supplier=path for one of {sorted(SUPPLIER_CONFIGS)}")
        if supplier in sources:
            raise ValueError(f"duplicate source for supplier: {supplier}")
        sources[supplier] = Path(raw_path)
    return sources


def _run_name(supplier: str, source: Path, fetched_at: str) -> str:
    stamp = _SAFE_STAMP.sub("-", fetched_at).strip("-.") or "run"
    return f"{supplier}-{stamp}-{_sha256(source)[:12]}"


def _install_state(run_dir: Path, state_root: Path, supplier: str) -> dict[str, Any]:
    source = run_dir / "state/next-missing-state.json"
    data = source.read_bytes()
    state_root.mkdir(parents=True, exist_ok=True)
    destination = state_root / f"{supplier}.json"
    fd, temporary_name = tempfile.mkstemp(prefix=f".{supplier}.state-", dir=state_root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.read_bytes() != data:
            raise RuntimeError("state promotion read-back mismatch")
        os.replace(temporary, destination)
        if destination.read_bytes() != data:
            raise RuntimeError("state promotion destination read-back mismatch")
    finally:
        temporary.unlink(missing_ok=True)
    return {"path": str(destination), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _blocked(supplier: str, reason: str, *, config_path: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "supplier": supplier,
        "status": "BLOCKED",
        "reason": reason,
        "production_writes": 0,
    }
    if config_path is not None:
        result["config"] = str(config_path)
    return result


def _write_approval_template(run_dir: Path, approval_root: Path) -> Path:
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "reports/summary.json").read_text(encoding="utf-8"))
    seal_bytes = (run_dir / "seal.json").read_bytes()
    manifest_bytes = (run_dir / "run-manifest.json").read_bytes()
    blockers: list[str] = []
    if summary.get("mode") != "read_only" or summary.get("production_writes") != 0:
        blockers.append("run_not_read_only")
    if summary.get("feed_completeness", {}).get("status") != "complete":
        blockers.append("feed_incomplete")
    payload = {
        "schema_version": 1,
        "status": "pending_approval",
        "eligible": not blockers,
        "requires_human_approval": True,
        "supplier": manifest["supplier"],
        "run_id": manifest["run_id"],
        "seal_sha256": hashlib.sha256(seal_bytes).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "blockers": blockers,
        "allowed_scope": {
            "operation": "review_only",
            "fields": ["proposed_price", "availability", "category_proposal"],
        },
        "production_writes": 0,
    }
    approval_root.mkdir(parents=True, exist_ok=True)
    destination = approval_root / f"{manifest['supplier']}-{manifest['run_id'][:32]}.json"
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if destination.exists():
        if destination.read_bytes() == data:
            return destination
        raise FileExistsError(f"approval artifact already exists with different content: {destination.name}")
    temporary = approval_root / f".{destination.name}.tmp"
    try:
        temporary.write_bytes(data)
        if temporary.read_bytes() != data:
            raise RuntimeError("approval artifact read-back mismatch")
        os.replace(temporary, destination)
        if destination.read_bytes() != data:
            raise RuntimeError("approval artifact destination read-back mismatch")
        os.chmod(destination, stat.S_IREAD)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def _run_supplier(
    supplier: str,
    *,
    source: Path | None,
    catalog: Path,
    output_root: Path,
    config_path: Path,
    fetched_at: str,
    state_root: Path | None,
    install_state: bool,
) -> dict[str, Any]:
    try:
        config = load_pilot_config(config_path)
        adapter = create_adapter(
            config.supplier.id,
            expected_catalog_sku_prefix=config.supplier.scope.catalog_sku_prefix,
        )
    except (OSError, TypeError, ValueError) as exc:
        return _blocked(supplier, f"invalid_config: {exc}", config_path=config_path)
    if source is None:
        return _blocked(supplier, "source_not_provided", config_path=config_path)
    if not source.is_file():
        return _blocked(supplier, f"source_not_found: {source}", config_path=config_path)
    if not catalog.is_file():
        return _blocked(supplier, f"catalog_not_found: {catalog}", config_path=config_path)

    run_dir = output_root / _run_name(supplier, source, fetched_at)
    previous_state = state_root / f"{supplier}.json" if state_root is not None else None
    if previous_state is not None and not previous_state.is_file():
        previous_state = None
    try:
        summary = run_pilot(
            source,
            catalog,
            run_dir,
            fetched_at,
            min_source_items=config.supplier.source.min_offer_count,
            max_source_items=config.supplier.source.max_offer_count,
            max_source_bytes=config.supplier.source.max_response_bytes,
            adapter=adapter,
            pricing=pricing_context_from_config(config.pricing, observed_at=fetched_at),
            config_path=config_path,
            previous_state_path=previous_state,
            missing_product_action=(config.stock.missing_product_policy.action if config.stock else None),
            consecutive_missing_runs=(config.stock.missing_product_policy.consecutive_missing_runs if config.stock else None),
        )
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        return {
            "supplier": supplier,
            "status": "BLOCKED",
            "reason": f"feed_rejected: {exc}",
            "config": str(config_path),
            "source": str(source),
            "production_writes": 0,
        }
    verification = verify_run(run_dir, source=source, catalog=catalog, config=config_path)
    result: dict[str, Any] = {
        "supplier": supplier,
        "status": "PASS" if verification["status"] == "PASS" else "FAIL",
        "run_dir": str(run_dir),
        "config": str(config_path),
        "source": str(source),
        "summary": summary,
        "verification": {
            "status": verification["status"],
            "checks_passed": verification["checks_passed"],
            "checks_total": verification["checks_total"],
        },
        "production_writes": 0,
    }
    if result["status"] == "PASS":
        try:
            result["approval_artifact"] = str(_write_approval_template(run_dir, output_root / "approval"))
        except (OSError, RuntimeError, ValueError) as exc:
            result["status"] = "FAIL"
            result["approval_error"] = str(exc)
    if result["status"] == "PASS" and install_state:
        if state_root is None:
            result["status"] = "FAIL"
            result["state_install_error"] = "--install-state requires --state-root"
        else:
            try:
                result["state_install"] = _install_state(run_dir, state_root, supplier)
            except (OSError, RuntimeError) as exc:
                result["status"] = "FAIL"
                result["state_install_error"] = str(exc)
    return result


def _write_aggregate(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    if temporary.read_bytes() != data:
        raise RuntimeError("aggregate read-back mismatch")
    os.replace(temporary, path)
    if path.read_bytes() != data:
        raise RuntimeError("aggregate destination read-back mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only supplier shadow previews")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--fetched-at", required=True)
    parser.add_argument("--config-dir", type=Path, default=Path(__file__).parent / "config")
    parser.add_argument("--source", action="append", default=[], metavar="SUPPLIER=PATH")
    parser.add_argument("--state-root", type=Path, default=None)
    parser.add_argument("--install-state", action="store_true")
    args = parser.parse_args()

    try:
        sources = _parse_sources(args.source)
    except ValueError as exc:
        parser.error(str(exc))
    results = []
    for supplier, config_name in SUPPLIER_CONFIGS.items():
        results.append(_run_supplier(
            supplier,
            source=sources.get(supplier),
            catalog=args.catalog,
            output_root=args.output_root,
            config_path=args.config_dir / config_name,
            fetched_at=args.fetched_at,
            state_root=args.state_root,
            install_state=args.install_state,
        ))
    status_counts = dict(sorted(Counter(result["status"] for result in results).items()))
    aggregate = {
        "schema_version": 1,
        "mode": "read_only",
        "write_capability": "absent",
        "fetched_at": args.fetched_at,
        "catalog": str(args.catalog),
        "status_counts": status_counts,
        "production_writes": 0,
        "suppliers": results,
    }
    aggregate_path = args.output_root / "aggregate.json"
    _write_aggregate(aggregate_path, aggregate)
    print(json.dumps(aggregate, ensure_ascii=False, sort_keys=True))
    if status_counts.get("FAIL"):
        return 1
    if status_counts.get("BLOCKED"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
