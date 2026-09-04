import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from mks123_pipeline import integrity
from mks123_pipeline.integrity import build_run_seal, read_evidence, verify_run_seal


def test_evidence_hash_and_content_come_from_one_read(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"original bytes")

    evidence = read_evidence(source)
    source.write_bytes(b"replacement bytes")

    assert evidence.data == b"original bytes"
    assert evidence.sha256 == hashlib.sha256(b"original bytes").hexdigest()


def test_run_seal_rejects_added_or_modified_files(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "reports").mkdir(parents=True)
    (run / "a.txt").write_text("A", encoding="utf-8")
    (run / "reports/summary.json").write_text("{}\n", encoding="utf-8")

    seal = build_run_seal(run)

    assert verify_run_seal(run) == seal
    (run / "extra.txt").write_text("not sealed", encoding="utf-8")
    with pytest.raises(ValueError, match="file set"):
        verify_run_seal(run)
    (run / "extra.txt").unlink()
    os.chmod(run / "a.txt", stat.S_IREAD | stat.S_IWRITE)
    (run / "a.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_run_seal(run)


def test_seal_records_exact_file_hashes_and_sizes(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    payload = b"artifact"
    (run / "artifact.bin").write_bytes(payload)

    build_run_seal(run)
    stored = json.loads((run / "seal.json").read_text(encoding="utf-8"))

    assert stored["files"] == {
        "artifact.bin": {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    }


def test_load_sealed_run_rejects_artifact_changed_after_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"original")
    build_run_seal(run)
    original_read = integrity.read_evidence
    mutated = False

    def read_then_mutate(path: str | Path):
        nonlocal mutated
        evidence = original_read(path)
        if Path(path) == artifact and not mutated:
            mutated = True
            os.chmod(artifact, stat.S_IREAD | stat.S_IWRITE)
            artifact.write_bytes(b"changed after capture")
        return evidence

    monkeypatch.setattr(integrity, "read_evidence", read_then_mutate)
    with pytest.raises(ValueError, match="changed during verification"):
        verify_run_seal(run)


def test_completed_bundle_artifacts_are_read_only(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.txt"
    artifact.write_text("immutable", encoding="utf-8")

    build_run_seal(run)

    with pytest.raises(PermissionError):
        artifact.write_text("tampered", encoding="utf-8")
    assert artifact.read_text(encoding="utf-8") == "immutable"
