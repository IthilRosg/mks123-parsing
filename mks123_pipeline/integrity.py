from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SEAL_NAME = "seal.json"


@dataclass(frozen=True)
class Evidence:
    path: Path
    data: bytes
    sha256: str


@dataclass(frozen=True)
class SealedRunEvidence:
    seal: dict[str, Any]
    seal_evidence: Evidence
    files: dict[str, Evidence]


def read_evidence(path: str | Path) -> Evidence:
    resolved = Path(path)
    data = resolved.read_bytes()
    return Evidence(path=resolved, data=data, sha256=hashlib.sha256(data).hexdigest())


def _file_paths(run_dir: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for path in run_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"sealed run does not allow symlink entries: {path.name}")
        if not path.is_file():
            continue
        relative = path.relative_to(run_dir).as_posix()
        if relative == SEAL_NAME:
            continue
        try:
            if getattr(path.stat(), "st_nlink", 1) > 1:
                raise ValueError(f"sealed run does not allow hard-link entries: {relative}")
        except OSError as exc:
            raise ValueError(f"cannot inspect sealed run entry: {relative}") from exc
        result[relative] = path
    return result


def _set_readonly(path: Path) -> None:
    os.chmod(path, stat.S_IREAD)


def _assert_evidence_unchanged(path: Path, evidence: Evidence, label: str) -> None:
    try:
        current = read_evidence(path)
    except OSError as exc:
        raise ValueError(f"sealed run file disappeared during verification: {label}") from exc
    if current.sha256 != evidence.sha256 or len(current.data) != len(evidence.data):
        raise ValueError(f"sealed run file changed during verification: {label}")


def build_run_seal(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    seal_path = run_dir / SEAL_NAME
    if seal_path.exists():
        raise FileExistsError(f"run seal already exists: {seal_path}")
    files: dict[str, dict[str, Any]] = {}
    for relative, path in sorted(_file_paths(run_dir).items()):
        evidence = read_evidence(path)
        files[relative] = {"sha256": evidence.sha256, "size": len(evidence.data)}
    seal: dict[str, Any] = {"version": 1, "files": files}
    payload = (json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with seal_path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if seal_path.read_bytes() != payload:
        raise RuntimeError("run seal read-back mismatch")
    for path in [*(entry for entry in _file_paths(run_dir).values()), seal_path]:
        _set_readonly(path)
    return seal


def load_sealed_run(run_dir: str | Path) -> SealedRunEvidence:
    run_dir = Path(run_dir)
    seal_evidence = read_evidence(run_dir / SEAL_NAME)
    try:
        seal = json.loads(seal_evidence.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid run seal") from exc
    if seal.get("version") != 1 or not isinstance(seal.get("files"), dict):
        raise ValueError("invalid run seal structure")
    expected = set(seal["files"])
    paths_before = _file_paths(run_dir)
    if set(paths_before) != expected:
        raise ValueError("sealed run file set mismatch")
    files: dict[str, Evidence] = {}
    for relative in sorted(expected):
        evidence = read_evidence(paths_before[relative])
        files[relative] = evidence
        record = seal["files"][relative]
        if evidence.sha256 != record.get("sha256"):
            raise ValueError(f"sealed run hash mismatch: {relative}")
        if len(evidence.data) != record.get("size"):
            raise ValueError(f"sealed run size mismatch: {relative}")
    if set(_file_paths(run_dir)) != expected:
        raise ValueError("sealed run file set changed during verification")
    _assert_evidence_unchanged(run_dir / SEAL_NAME, seal_evidence, SEAL_NAME)
    for relative in sorted(expected):
        _assert_evidence_unchanged(paths_before[relative], files[relative], relative)
    return SealedRunEvidence(seal=seal, seal_evidence=seal_evidence, files=files)


def verify_run_seal(run_dir: str | Path) -> dict[str, Any]:
    return load_sealed_run(run_dir).seal
