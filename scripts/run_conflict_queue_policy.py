from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
import types
from argparse import ArgumentParser
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


def _policy_path() -> Path:
    return Path(__file__).resolve().parents[1] / "mks123_pipeline" / "conflict_policy.py"


def _policy_module(source_bytes: bytes):
    module_name = f"mks123_policy_snapshot_{_sha256_bytes(source_bytes)[:16]}"
    module = types.ModuleType(module_name)
    module.__file__ = str(_policy_path())
    module.__package__ = "mks123_pipeline"
    sys.modules[module_name] = module
    exec(compile(source_bytes, str(_policy_path()), "exec", dont_inherit=True), module.__dict__)  # noqa: S102 - exact captured source snapshot only
    return module


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_source_snapshot() -> tuple[dict[Path, bytes], dict[str, str]]:
    paths = {_policy_path(), Path(__file__).resolve()}
    contents = {path: path.read_bytes() for path in paths}
    hashes = {str(path): _sha256_bytes(data) for path, data in contents.items()}
    return contents, hashes


def _assert_sources_unchanged(snapshot: dict[Path, bytes]) -> None:
    for path, expected in snapshot.items():
        if path.read_bytes() != expected:
            raise RuntimeError(f"policy source changed during run: {path}")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return
        raise
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise
    finally:
        os.close(fd)


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _render_report(artifact: dict[str, Any]) -> str:
    summary = artifact["summary"]
    lines = [
        "# Conflict queue policy dry-run",
        "",
        f"- Scope: **{summary['items']} products**",
        f"- Conflict entries: **{summary['conflict_entries']}**",
        f"- Products with a human-review action after filtering: **{summary['items_with_any_review_after_filter']}**",
        "- This is classification only; no value, category, relation, image or production record was changed.",
        "",
        "## Actions",
        "",
    ]
    for action, count in sorted(summary["actions"].items(), key=lambda pair: (-pair[1], pair[0])):
        lines.append(f"- `{action}`: **{count}**")
    lines += [
        "",
        "## Policy",
        "",
        "- Placeholder/unknown/internal fields leave the human queue but remain in audit.",
        "- Formatting-only candidates are proposal-only and retain raw provenance.",
        "- Documentation, compatibility, descriptions, physical dimensions and dictionaries are grouped review queues.",
        "- No value replacement or approval is performed by this command.",
        "",
        "## Guarantees",
        "",
        f"- `production_writes={artifact['production_writes']}`",
        f"- `publication_enabled={str(artifact['publication_enabled']).lower()}`",
        "- Compatibility relations created: `0`",
    ]
    return "\n".join(lines) + "\n"


def build_artifact(
    preview_path: Path,
    preview_bytes: bytes,
    preview_items: list[Mapping[str, Any]],
    tolerance: Decimal,
    source_hashes: dict[str, str],
    policy_source_bytes: bytes | None = None,
) -> dict[str, Any]:
    policy_module = _policy_module(policy_source_bytes if policy_source_bytes is not None else _policy_path().read_bytes())
    classification = policy_module.classify_preview(preview_items, tolerance=tolerance)
    module_path = str(_policy_path())
    runner_path = str(Path(__file__).resolve())
    return {
        "policy_version": "conflict-queue-v1",
        "input_preview": str(preview_path),
        "input_preview_sha256": _sha256_bytes(preview_bytes),
        "input_preview_bytes": len(preview_bytes),
        "tolerance": str(tolerance),
        "policy_module_sha256": source_hashes[module_path],
        "runner_sha256": source_hashes[runner_path],
        "read_only": True,
        "production_writes": 0,
        "publication_enabled": False,
        "compatibility_relations_created": 0,
        "summary": classification.summary,
        "entries": list(classification.entries),
    }


def _same_directory(path: Path, expected_stat: os.stat_result) -> bool:
    try:
        return path.is_dir() and os.path.samestat(os.stat(path, follow_symlinks=False), expected_stat)
    except FileNotFoundError:
        return False


def _remove_owned_directory(path: Path, expected_stat: os.stat_result, names: tuple[str, ...]) -> None:
    if not _same_directory(path, expected_stat):
        raise RuntimeError(f"directory identity changed; retained path: {path}")
    for name in names:
        candidate = path / name
        if not os.path.lexists(candidate):
            continue
        candidate_stat = os.lstat(candidate)
        if stat.S_ISLNK(candidate_stat.st_mode) or not stat.S_ISREG(candidate_stat.st_mode):
            raise RuntimeError(f"unexpected owned artifact type; retained path: {candidate}")
        candidate.unlink()
    path.rmdir()


def _publish_bundle(output: Path, artifact: dict[str, Any]) -> None:
    parent = output.parent
    if not parent.is_dir():
        raise RuntimeError(f"output parent must already exist: {parent}")
    staging: Path | None = None
    staging_stat: os.stat_result | None = None
    output_stat: os.stat_result | None = None
    committed = False
    payloads = {
        "QUEUE_DRY_RUN.json": json.dumps(artifact, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
        "REPORT.md": _render_report(artifact).encode("utf-8"),
    }
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
        staging_stat = os.stat(staging, follow_symlinks=False)
        for name, data in payloads.items():
            _write_exclusive(staging / name, data)
        _fsync_directory(staging)

        # mkdir is the atomic no-replace reservation for the final directory.
        os.mkdir(output)
        output_stat = os.stat(output, follow_symlinks=False)
        _fsync_directory(parent)
        for name in payloads:
            os.link(staging / name, output / name)
        _fsync_directory(output)
        _fsync_directory(parent)
        marker = {
            "bundle": "conflict-queue-bundle-v1",
            "files": {name: {"sha256": _sha256_bytes(data), "size": len(data)} for name, data in payloads.items()},
        }
        _write_exclusive(output / "COMMITTED", json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
        _fsync_directory(output)
        _fsync_directory(parent)
        committed = True
    except BaseException:
        if output_stat is not None and not committed:
            _remove_owned_directory(output, output_stat, ("QUEUE_DRY_RUN.json", "REPORT.md", "COMMITTED"))
        raise
    finally:
        if staging is not None and staging_stat is not None and staging.exists():
            _remove_owned_directory(staging, staging_stat, tuple(payloads))


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Build a read-only conflict queue classification.")
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tolerance", default="0.03")
    args = parser.parse_args(argv)
    if not args.preview.is_file():
        parser.error(f"preview does not exist: {args.preview}")
    try:
        tolerance = Decimal(args.tolerance)
        preview_bytes = args.preview.read_bytes()
        preview_data = json.loads(preview_bytes)
        if not isinstance(preview_data, dict) or not isinstance(preview_data.get("items"), list):
            raise TypeError("preview must be an object with an items list")
        source_snapshot, source_hashes = _read_source_snapshot()
        _assert_sources_unchanged(source_snapshot)
        artifact = build_artifact(
            preview_path=args.preview,
            preview_bytes=preview_bytes,
            preview_items=preview_data["items"],
            tolerance=tolerance,
            source_hashes=source_hashes,
            policy_source_bytes=source_snapshot[_policy_path()],
        )
        _assert_sources_unchanged(source_snapshot)
        _publish_bundle(args.output, artifact)
    except (InvalidOperation, TypeError, ValueError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "PASS", "output": str(args.output), "summary": artifact["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
