from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

if os.name == "nt":
    import msvcrt
else:
    import fcntl

sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.config import load_pilot_config, pricing_context_from_config
from mks123_pipeline.integrity import Evidence, load_sealed_run, read_evidence
from mks123_pipeline.manifest import code_identity, policy_sha256

PROCESSING_LIMIT_BYTES = 128 * 1024 * 1024


def _sha256(path: Path) -> str:
    return read_evidence(path).sha256


def _code_sha256(project_root: Path = PROJECT_ROOT) -> str:
    return str(code_identity(project_root)["sha256"])


def _run_name(
    source_hash: str,
    catalog_hash: str,
    config_hash: str,
    policy_hash: str,
    code_hash: str,
    properties_hash: str | None = None,
) -> str:
    values = (source_hash, catalog_hash, config_hash, policy_hash, code_hash)
    if any(not _SHA256.fullmatch(value) for value in values):
        raise ValueError("run identity requires valid SHA-256 values")
    if properties_hash is not None and not _SHA256.fullmatch(properties_hash):
        raise ValueError("properties run identity requires a valid SHA-256 value")
    name = (
        f"netlab-{source_hash[:12]}-catalog-{catalog_hash[:12]}-"
        f"config-{config_hash[:12]}-policy-{policy_hash[:12]}-code-{code_hash[:12]}"
    )
    return f"{name}-properties-{properties_hash[:12]}" if properties_hash else name


def _run_json(command: list[str]) -> dict[str, Any]:
    script = Path(command[1]).resolve()
    command_root = script.parent.parent if script.parent.name == "scripts" else script.parent
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(command_root)
    result = subprocess.run(
        command,
        cwd=command_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit={result.returncode}"
        raise RuntimeError(detail)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("command did not return exactly one JSON result")
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise RuntimeError("command returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("command JSON result must be an object")
    return payload


def _verify_command(
    *,
    project_root: Path,
    run_dir: Path,
    source: Path,
    catalog: Path,
    config: Path,
) -> list[str]:
    return [
        sys.executable,
        str(project_root / "verify_run.py"),
        "--run",
        str(run_dir),
        "--source",
        str(source),
        "--catalog",
        str(catalog),
        "--config",
        str(config),
        "--no-deterministic-replay",
    ]


def _capture_file(source: Path | Evidence, target: Path, *, max_bytes: int) -> tuple[str, int]:
    evidence = (
        source
        if isinstance(source, Evidence)
        else read_evidence(source, max_bytes=max_bytes)
    )
    data = evidence.data
    source_name = evidence.path.name
    if len(data) > max_bytes:
        raise ValueError(f"private input exceeds byte limit: {source_name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    captured = read_evidence(target)
    if captured.data != data or captured.sha256 != evidence.sha256:
        raise RuntimeError(f"private input read-back mismatch: {target.name}")
    return evidence.sha256, len(data)


def _capture_code_project(target_root: Path) -> dict[str, Any]:
    paths = list((PROJECT_ROOT / "mks123_pipeline").glob("*.py"))
    paths.extend(
        PROJECT_ROOT / relative
        for relative in (
            "run_pilot.py",
            "verify_run.py",
            "scripts/fetch_netlab_current.py",
            "scripts/run_netlab_shadow.py",
            "pyproject.toml",
            "uv.lock",
        )
    )
    for source in sorted((path for path in paths if path.is_file()), key=lambda item: item.as_posix()):
        target = target_root / source.relative_to(PROJECT_ROOT)
        _capture_file(source, target, max_bytes=8 * 1024 * 1024)
    return code_identity(target_root)


def _assert_run_identity(
    run_dir: Path,
    *,
    run_name: str,
    source_hash: str,
    source_size: int,
    catalog_hash: str,
    catalog_size: int,
    config_hash: str,
    config_size: int,
    source_metadata_hash: str,
    source_metadata_size: int,
    properties_hash: str,
    properties_size: int,
    properties_metadata_hash: str,
    properties_metadata_size: int,
    policy_hash: str,
    executable_identity: dict[str, Any],
) -> None:
    sealed = load_sealed_run(run_dir, read_content=False)
    evidence = read_evidence(run_dir / "run-manifest.json")
    sealed_record = sealed.files.get("run-manifest.json")
    if sealed_record is None:
        raise RuntimeError("sealed run has no manifest record")
    sealed_size = sealed_record.size if sealed_record.size is not None else len(sealed_record.data)
    if (
        evidence.sha256 != sealed_record.sha256
        or evidence.size != sealed_size
        or evidence.file_identity != sealed_record.file_identity
        or evidence.canonical_path != sealed_record.canonical_path
    ):
        raise RuntimeError("sealed manifest changed after metadata verification")
    if evidence is None:
        raise RuntimeError("sealed run has no manifest")
    manifest = json.loads(evidence.data)
    expected_inputs = {
        "source": {"sha256": source_hash, "size": source_size},
        "catalog": {"sha256": catalog_hash, "size": catalog_size},
        "config": {"sha256": config_hash, "size": config_size},
        "source_metadata": {"sha256": source_metadata_hash, "size": source_metadata_size},
        "properties": {"sha256": properties_hash, "size": properties_size},
        "properties_metadata": {
            "sha256": properties_metadata_hash,
            "size": properties_metadata_size,
        },
    }
    if manifest.get("run_id") != run_name or manifest.get("canonical_run_id") != run_name:
        raise RuntimeError("sealed manifest run identity does not match supervisor key")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise TypeError("sealed manifest inputs are invalid")
    for label, expected in expected_inputs.items():
        record = inputs.get(label)
        actual = (
            {"sha256": record.get("sha256"), "size": record.get("size")}
            if isinstance(record, dict)
            else None
        )
        if actual != expected:
            raise RuntimeError(f"sealed manifest {label} identity does not match supervisor key")
    policy = manifest.get("policy")
    if not isinstance(policy, dict) or policy.get("hash") != policy_hash:
        raise RuntimeError("sealed manifest policy identity does not match supervisor key")
    if manifest.get("code_identity") != executable_identity:
        raise RuntimeError("sealed manifest code/runtime identity does not match supervisor key")


def _policy_hash(source: Path, config: Path, fetched_at: str) -> str:
    loaded = load_pilot_config(config)
    if loaded.supplier.id != "netlab":
        raise ValueError("Netlab shadow requires the Netlab supplier config")
    snapshot = NetlabAdapter().parse(
        source,
        fetched_at=fetched_at,
        min_items=loaded.supplier.source.min_offer_count,
        max_items=loaded.supplier.source.max_offer_count,
        max_bytes=loaded.supplier.source.max_response_bytes,
    )
    pricing = pricing_context_from_config(
        loaded.pricing,
        observed_at=snapshot.catalog_date or fetched_at,
        supplier_id="netlab",
        supplier_rates=snapshot.currencies,
        source_sha256=snapshot.source_sha256,
    )
    return policy_sha256(pricing)


def _assert_private_inputs_stable(
    *,
    source: Path,
    source_hash: str,
    catalog: Path,
    catalog_hash: str,
    config: Path,
    config_hash: str,
    source_metadata: Path,
    source_metadata_hash: str,
    properties: Path,
    properties_hash: str,
    properties_metadata: Path,
    properties_metadata_hash: str,
    project_root: Path,
    executable_identity: dict[str, Any],
) -> None:
    if (
        _sha256(source) != source_hash
        or _sha256(catalog) != catalog_hash
        or _sha256(config) != config_hash
        or _sha256(source_metadata) != source_metadata_hash
        or _sha256(properties) != properties_hash
        or _sha256(properties_metadata) != properties_metadata_hash
    ):
        raise RuntimeError("private run input changed during shadow cycle")
    if code_identity(project_root) != executable_identity:
        raise RuntimeError("private code/runtime identity changed during shadow cycle")


def _accepted_snapshot(
    *,
    raw_root: Path,
    fetched: dict[str, Any],
    label: str,
) -> tuple[Evidence, Evidence, str, str]:
    if fetched.get("production_writes") != 0:
        raise RuntimeError(f"{label} fetch result is not read-only")
    source_hash = fetched.get("sha256")
    local_file = fetched.get("local_file")
    if not isinstance(source_hash, str) or not _SHA256.fullmatch(source_hash):
        raise RuntimeError(f"{label} fetch result has invalid source hash")
    if (
        not isinstance(local_file, str)
        or Path(local_file).name != local_file
        or "/" in local_file
        or "\\" in local_file
        or not local_file.casefold().endswith(".zip")
    ):
        raise RuntimeError(f"{label} fetch result has invalid local filename")
    source_path = raw_root / local_file
    metadata_path = raw_root / Path(local_file).with_suffix(".metadata.json").name
    try:
        source_evidence = read_evidence(source_path, max_bytes=PROCESSING_LIMIT_BYTES)
        metadata_evidence = read_evidence(metadata_path, max_bytes=2 * 1024 * 1024)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{label} accepted source or metadata is invalid") from exc
    expected_root = os.path.normcase(os.path.normpath(str(raw_root.resolve(strict=True))))
    if os.path.dirname(source_evidence.canonical_path) != expected_root:
        raise RuntimeError(f"{label} accepted source escapes raw root")
    if os.path.dirname(metadata_evidence.canonical_path) != expected_root:
        raise RuntimeError(f"{label} acquisition metadata escapes raw root")
    if source_evidence.sha256 != source_hash:
        raise RuntimeError(f"{label} accepted source hash does not match fetch result")
    fetched_at = fetched.get("fetched_at_utc")
    if not isinstance(fetched_at, str) or not fetched_at:
        raise RuntimeError(f"{label} fetch result has no immutable fetched_at_utc")
    return source_evidence, metadata_evidence, source_hash, fetched_at


@contextmanager
def _cycle_lock(runs_root: Path):
    lock_path = runs_root / ".netlab-shadow.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        try:
            if os.name == "nt":
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"\\0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("another Netlab shadow cycle is already running") from exc
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _run_cycle_locked(
    *,
    catalog: Path,
    config: Path,
    raw_root: Path,
    runs_root: Path,
) -> dict[str, Any]:
    catalog = catalog.resolve(strict=True)
    config = config.resolve(strict=True)
    raw_root = raw_root.resolve()
    runs_root = runs_root.resolve()
    raw_root.mkdir(parents=True, exist_ok=True)
    runs_root.mkdir(parents=True, exist_ok=True)

    price_fetched = _run_json(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts/fetch_netlab_current.py"),
            "--kind",
            "price",
            "--raw-root",
            str(raw_root),
        ]
    )
    properties_fetched = _run_json(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts/fetch_netlab_current.py"),
            "--kind",
            "properties",
            "--raw-root",
            str(raw_root),
        ]
    )
    accepted_source, accepted_source_metadata, fetched_hash, fetched_at = _accepted_snapshot(
        raw_root=raw_root,
        fetched=price_fetched,
        label="price",
    )
    accepted_properties, accepted_properties_metadata, properties_hash, properties_fetched_at = (
        _accepted_snapshot(raw_root=raw_root, fetched=properties_fetched, label="properties")
    )

    with tempfile.TemporaryDirectory(prefix=".netlab-cycle-", dir=runs_root) as temporary:
        private_root = Path(temporary)
        private_inputs = private_root / "private-inputs"
        source = private_inputs / "source.zip"
        source_metadata = private_inputs / "source-metadata.json"
        properties = private_inputs / "properties.zip"
        properties_metadata = private_inputs / "properties-metadata.json"
        captured_catalog = private_inputs / "catalog.csv"
        captured_config = private_inputs / "config.yaml"
        source_hash, source_size = _capture_file(
            accepted_source,
            source,
            max_bytes=PROCESSING_LIMIT_BYTES,
        )
        if source_hash != fetched_hash:
            raise RuntimeError("accepted price source hash changed before private capture")
        source_metadata_hash, source_metadata_size = _capture_file(
            accepted_source_metadata,
            source_metadata,
            max_bytes=2 * 1024 * 1024,
        )
        properties_hash_actual, properties_size = _capture_file(
            accepted_properties,
            properties,
            max_bytes=PROCESSING_LIMIT_BYTES,
        )
        if properties_hash_actual != properties_hash:
            raise RuntimeError("accepted properties source hash changed before private capture")
        properties_metadata_hash, properties_metadata_size = _capture_file(
            accepted_properties_metadata,
            properties_metadata,
            max_bytes=2 * 1024 * 1024,
        )
        catalog_hash, catalog_size = _capture_file(
            catalog,
            captured_catalog,
            max_bytes=512 * 1024 * 1024,
        )
        config_hash, config_size = _capture_file(
            config,
            captured_config,
            max_bytes=2 * 1024 * 1024,
        )
        loaded_config = load_pilot_config(captured_config)
        max_source_bytes = loaded_config.supplier.source.max_response_bytes
        if max_source_bytes < PROCESSING_LIMIT_BYTES:
            raise RuntimeError("Netlab config processing limit is below the proven content high-water")
        captured_project = private_root / "project"
        executable_identity = _capture_code_project(captured_project)
        code_hash = str(executable_identity["sha256"])
        pricing_hash = _policy_hash(source, captured_config, fetched_at)
        run_name = _run_name(
            source_hash,
            catalog_hash,
            config_hash,
            pricing_hash,
            code_hash,
            properties_hash,
        )
        run_dir = runs_root / run_name
        verify_command = _verify_command(
            project_root=captured_project,
            run_dir=run_dir,
            source=source,
            catalog=captured_catalog,
            config=captured_config,
        )
        identity_arguments = {
            "run_name": run_name,
            "source_hash": source_hash,
            "source_size": source_size,
            "catalog_hash": catalog_hash,
            "catalog_size": catalog_size,
            "config_hash": config_hash,
            "config_size": config_size,
            "source_metadata_hash": source_metadata_hash,
            "source_metadata_size": source_metadata_size,
            "properties_hash": properties_hash,
            "properties_size": properties_size,
            "properties_metadata_hash": properties_metadata_hash,
            "properties_metadata_size": properties_metadata_size,
            "policy_hash": pricing_hash,
            "executable_identity": executable_identity,
        }
        if run_dir.exists():
            _assert_run_identity(run_dir, **identity_arguments)
            verification = _run_json(verify_command)
            if verification.get("status") != "PASS":
                raise RuntimeError("existing Netlab shadow run failed verification")
            _assert_private_inputs_stable(
                source=source,
                source_hash=source_hash,
                catalog=captured_catalog,
                catalog_hash=catalog_hash,
                config=captured_config,
                config_hash=config_hash,
                source_metadata=source_metadata,
                source_metadata_hash=source_metadata_hash,
                properties=properties,
                properties_hash=properties_hash,
                properties_metadata=properties_metadata,
                properties_metadata_hash=properties_metadata_hash,
                project_root=captured_project,
                executable_identity=executable_identity,
            )
            return {
                "status": "NO_CHANGE",
                "source_sha256": source_hash,
                "properties_sha256": properties_hash,
                "run": str(run_dir),
                "checks_passed": verification.get("checks_passed"),
                "checks_total": verification.get("checks_total"),
                "production_writes": 0,
            }

        run_result = _run_json(
            [
                sys.executable,
                str(captured_project / "run_pilot.py"),
                "--source",
                str(source),
                "--source-metadata",
                str(source_metadata),
                "--properties",
                str(properties),
                "--properties-metadata",
                str(properties_metadata),
                "--properties-fetched-at",
                properties_fetched_at,
                "--max-source-bytes",
                str(max_source_bytes),
                "--catalog",
                str(captured_catalog),
                "--output",
                str(run_dir),
                "--fetched-at",
                fetched_at,
                "--config",
                str(captured_config),
            ]
        )
        if run_result.get("production_writes") != 0:
            raise RuntimeError("shadow result is not read-only")
        _assert_run_identity(run_dir, **identity_arguments)
        verification = _run_json(verify_command)
        if verification.get("status") != "PASS":
            raise RuntimeError("new Netlab shadow run failed verification")
        _assert_private_inputs_stable(
            source=source,
            source_hash=source_hash,
            catalog=captured_catalog,
            catalog_hash=catalog_hash,
            config=captured_config,
            config_hash=config_hash,
            source_metadata=source_metadata,
            source_metadata_hash=source_metadata_hash,
            properties=properties,
            properties_hash=properties_hash,
            properties_metadata=properties_metadata,
            properties_metadata_hash=properties_metadata_hash,
            project_root=captured_project,
            executable_identity=executable_identity,
        )
        return {
            "status": "UPDATED_SHADOW",
            "source_sha256": source_hash,
            "properties_sha256": properties_hash,
            "run": str(run_dir),
            "proposals": run_result.get("proposals"),
            "content_enrichment": run_result.get("content_enrichment"),
            "checks_passed": verification.get("checks_passed"),
            "checks_total": verification.get("checks_total"),
            "production_writes": 0,
        }


def run_cycle(
    *,
    catalog: Path,
    config: Path,
    raw_root: Path,
    runs_root: Path,
) -> dict[str, Any]:
    resolved_runs_root = runs_root.resolve()
    with _cycle_lock(resolved_runs_root):
        return _run_cycle_locked(
            catalog=catalog,
            config=config,
            raw_root=raw_root,
            runs_root=resolved_runs_root,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch, SHA-gate, run and verify one Netlab read-only shadow cycle")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "config/netlab.yaml")
    parser.add_argument("--raw-root", type=Path, default=PROJECT_ROOT / "raw")
    parser.add_argument("--runs-root", type=Path, default=PROJECT_ROOT / "runs")
    args = parser.parse_args(argv)
    try:
        result = run_cycle(
            catalog=args.catalog,
            config=args.config,
            raw_root=args.raw_root,
            runs_root=args.runs_root,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise SystemExit(f"NETLAB_SHADOW_FAILED {exc}") from exc
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
