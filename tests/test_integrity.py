import hashlib
import inspect
import json
import os
import stat
from pathlib import Path

import pytest

from mks123_pipeline import integrity
from mks123_pipeline.integrity import (
    build_run_seal,
    load_sealed_run,
    read_evidence,
    verify_run_seal,
)


def test_evidence_hash_and_content_come_from_one_read(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"original bytes")

    evidence = read_evidence(source)
    source.write_bytes(b"replacement bytes")

    assert evidence.data == b"original bytes"
    assert evidence.sha256 == hashlib.sha256(b"original bytes").hexdigest()


def test_read_evidence_rejects_data_over_limit(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"12345")

    for invalid_limit in (True, False):
        with pytest.raises(ValueError, match="max_bytes"):
            read_evidence(source, max_bytes=invalid_limit)

    with pytest.raises(ValueError, match="max_bytes"):
        read_evidence(source, max_bytes=4)


def test_read_evidence_identity_only_skips_content_hash(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"identity-only")

    evidence = read_evidence(source, calculate_hash=False, read_content=False)

    assert evidence.data == b""
    assert evidence.sha256 == ""
    assert evidence.file_identity


def test_read_evidence_rejects_hard_link_entries(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    linked = tmp_path / "linked.bin"
    source.write_bytes(b"immutable")
    os.link(source, linked)

    with pytest.raises(ValueError, match="hard-link"):
        read_evidence(linked)


def test_read_evidence_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    target = real_parent / "source.bin"
    target.write_bytes(b"immutable")
    symlink_parent = tmp_path / "parent-link"
    try:
        symlink_parent.symlink_to(real_parent, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises((OSError, ValueError)):
        read_evidence(symlink_parent / "source.bin")


def test_non_following_open_binds_parent_during_read() -> None:
    opener = inspect.getsource(integrity._open_non_following)
    posix_opener = inspect.getsource(integrity._open_posix_non_following)
    reader = inspect.getsource(integrity.read_evidence)
    assert "_open_posix_non_following" in opener
    assert "dir_fd=" in posix_opener
    assert "O_NOFOLLOW" in posix_opener
    assert "parent_handles" in opener
    assert "_close_parent_handles(parent_handles)" in reader


def test_run_seal_rejects_added_or_modified_files(tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "reports").mkdir(parents=True)
    (run / "a.txt").write_text("A", encoding="utf-8")
    (run / "reports/summary.json").write_text("{}\n", encoding="utf-8")

    seal = build_run_seal(run)

    assert verify_run_seal(run) == seal
    sealed_root_mode = stat.S_IMODE(run.stat().st_mode)
    os.chmod(run, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    (run / "extra.txt").write_text("not sealed", encoding="utf-8")
    os.chmod(run, sealed_root_mode)
    with pytest.raises(ValueError, match="file set"):
        verify_run_seal(run)

    modified_run = tmp_path / "modified-run"
    modified_run.mkdir()
    modified_artifact = modified_run / "a.txt"
    modified_artifact.write_text("A", encoding="utf-8")
    build_run_seal(modified_run)
    os.chmod(modified_artifact, stat.S_IREAD | stat.S_IWRITE)
    modified_artifact.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_run_seal(modified_run)


def test_sealed_run_metadata_verification_does_not_materialize_payload(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    payload = run / "large.bin"
    payload.write_bytes(b"x" * (2 * 1024 * 1024))
    build_run_seal(run)

    sealed = load_sealed_run(run, read_content=False)

    assert sealed.files["large.bin"].data == b""
    assert sealed.files["large.bin"].size == payload.stat().st_size
    assert sealed.files["large.bin"].sha256 == hashlib.sha256(payload.read_bytes()).hexdigest()


def test_windows_environment_cannot_enable_unfrozen_sealing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows-only policy")
    monkeypatch.setenv("MKS123_ALLOW_UNFROZEN_WINDOWS_TEST_ONLY", "1")
    monkeypatch.setattr(
        integrity,
        "_WINDOWS_TEST_SEAL_BUILDER_ENABLED",
        False,
        raising=False,
    )
    with pytest.raises(RuntimeError, match="requires POSIX directory freeze"):
        integrity.build_run_seal(tmp_path / "run")


def test_seal_failure_restores_original_file_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"artifact")
    original_mode = stat.S_IMODE(artifact.stat().st_mode)
    if os.name == "nt":
        original_set_readonly_fd = integrity._set_readonly_fd

        def fail_after_mode_change(path: Path, fd: int) -> None:
            original_set_readonly_fd(path, fd)
            raise RuntimeError("injected seal failure")

        monkeypatch.setattr(integrity, "_set_readonly_fd", fail_after_mode_change)
    else:
        def fail_after_mode_change(_fd: int, _path: Path) -> integrity.Evidence:
            raise RuntimeError("injected seal failure")

        monkeypatch.setattr(integrity, "_read_evidence_from_fd", fail_after_mode_change)
    with pytest.raises(RuntimeError, match="injected seal failure"):
        build_run_seal(run)

    assert stat.S_IMODE(artifact.stat().st_mode) == original_mode
    seal_path = run / "seal.json"
    assert seal_path.read_bytes() == b""


def test_seal_race_does_not_delete_concurrent_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"artifact")
    seal_path = run / "seal.json"
    original_mode = stat.S_IMODE(artifact.stat().st_mode)
    if os.name == "nt":
        original_open = Path.open

        def create_concurrent_seal(path: Path, mode: str = "r", *args: object, **kwargs: object):
            if path == seal_path and "x" in mode:
                seal_path.write_text("concurrent seal\n", encoding="utf-8")
            return original_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(Path, "open", create_concurrent_seal)
    else:
        original_open = os.open
        injected = False

        def create_concurrent_seal(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal injected
            if path == integrity.SEAL_NAME and dir_fd is not None and flags & os.O_EXCL and not injected:
                injected = True
                concurrent_fd = original_open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
                try:
                    os.write(concurrent_fd, b"concurrent seal\n")
                finally:
                    os.close(concurrent_fd)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(os, "open", create_concurrent_seal)
    with pytest.raises(FileExistsError):
        build_run_seal(run)

    assert seal_path.read_text(encoding="utf-8") == "concurrent seal\n"
    assert stat.S_IMODE(artifact.stat().st_mode) == original_mode


def test_posix_verifier_is_descriptor_rooted() -> None:
    verifier = inspect.getsource(integrity._load_sealed_run_posix)

    assert "_open_posix_directory_non_following" in verifier
    assert "_scan_posix_tree" in verifier
    assert "dir_fd=root_fd" in verifier
    assert "_file_paths" not in verifier
    assert "_seal_directory_paths" not in verifier
    assert ".rglob(" not in verifier


def test_posix_builder_is_descriptor_rooted() -> None:
    builder = inspect.getsource(integrity._build_run_seal_posix)
    scanner = inspect.getsource(integrity._scan_posix_tree)

    assert "_scan_posix_tree" in builder
    assert "dir_fd=root_fd" in builder
    assert "os.fdopen" in builder
    assert ".rglob(" not in builder
    assert "dir_fd=parent_fd" in scanner
    assert "O_NOFOLLOW" in scanner
    assert ".rglob(" not in scanner
    assert integrity._relative_depth(".") == 0
    assert integrity._relative_depth("child") == 1
    assert integrity._relative_depth("child/nested") == 2


def test_posix_intermediate_symlink_swap_cannot_chmod_outside_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX descriptor-relative traversal test")
    run = tmp_path / "run"
    child = run / "child"
    outside = tmp_path / "outside"
    child.mkdir(parents=True)
    outside.mkdir()
    (run / "artifact.bin").write_bytes(b"artifact")
    outside_mode = stat.S_IMODE(outside.stat().st_mode)
    original_open = os.open
    swapped = False

    def swap_child_for_symlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == child.name and dir_fd is not None and not swapped:
            swapped = True
            child.rename(run / "displaced-child")
            child.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_child_for_symlink)
    with pytest.raises((OSError, ValueError)):
        build_run_seal(run)

    assert swapped
    assert stat.S_IMODE(outside.stat().st_mode) == outside_mode


def test_directory_replacement_is_rejected_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enumerated = tmp_path / "enumerated"
    replacement = tmp_path / "replacement"
    enumerated.mkdir()
    replacement.mkdir()
    expected_identity = integrity._file_identity(enumerated.stat())
    replacement_stat = replacement.stat()
    chmod_calls: list[tuple[int, int]] = []

    monkeypatch.setattr(integrity.os, "fstat", lambda _fd: replacement_stat)
    monkeypatch.setattr(
        integrity.os,
        "fchmod",
        lambda fd, mode: chmod_calls.append((fd, mode)),
        raising=False,
    )

    with pytest.raises(ValueError, match="identity changed before freeze"):
        integrity._freeze_posix_directory(
            123,
            expected_identity=expected_identity,
            path=enumerated,
            write_bits=stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH,
        )

    assert chmod_calls == []


def test_seal_rejects_file_added_during_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"artifact")
    extra = run / "extra.bin"
    calls = 0
    if os.name == "nt":
        original_file_paths = integrity._file_paths

        def add_after_enumeration(path: Path) -> dict[str, Path]:
            nonlocal calls
            calls += 1
            paths = original_file_paths(path)
            if calls == 1:
                extra.write_bytes(b"concurrent artifact")
            return paths

        monkeypatch.setattr(integrity, "_file_paths", add_after_enumeration)
        error = "file set changed"
    else:
        original_listdir = os.listdir

        def add_after_enumeration(path: int) -> list[str]:
            nonlocal calls
            calls += 1
            names = original_listdir(path)
            if calls == 1:
                extra.write_bytes(b"concurrent artifact")
            return names

        monkeypatch.setattr(os, "listdir", add_after_enumeration)
        error = "file or directory set changed"
    with pytest.raises(ValueError, match=error):
        build_run_seal(run)

    assert extra.exists()


def test_seal_rejects_same_path_inode_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"original artifact")
    moved_original = tmp_path / "moved-original.bin"
    replaced = False
    if os.name == "nt":
        original_open = integrity._open_non_following

        def replace_same_path(path: Path):
            nonlocal replaced
            opened = original_open(path)
            if path == artifact and not replaced:
                replaced = True
                path.replace(moved_original)
                path.write_bytes(b"replacement artifact")
            return opened

        monkeypatch.setattr(integrity, "_open_non_following", replace_same_path)
    else:
        original_open = os.open

        def replace_same_path(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal replaced
            opened = original_open(path, flags, mode, dir_fd=dir_fd)
            if path == artifact.name and dir_fd is not None and not replaced:
                replaced = True
                artifact.replace(moved_original)
                artifact.write_bytes(b"replacement artifact")
            return opened

        monkeypatch.setattr(os, "open", replace_same_path)
    with pytest.raises(ValueError, match="identity|inode|canonical path"):
        build_run_seal(run)

    assert replaced is True

    assert moved_original.read_bytes() == b"original artifact"
    assert artifact.read_bytes() == b"replacement artifact"


def test_seal_records_exact_file_hashes_and_sizes(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    payload = b"artifact"
    artifact = run / "artifact.bin"
    artifact.write_bytes(payload)

    build_run_seal(run)
    evidence = read_evidence(artifact)
    parent_canonical_path = integrity._normalized_physical_path(Path(evidence.canonical_path).parent)
    stored = json.loads((run / "seal.json").read_text(encoding="utf-8"))
    run_stat = run.stat()

    assert stored["version"] == integrity.SEAL_VERSION
    assert stored["directories"] == {
        ".": {
            "file_identity": list(integrity._directory_identity(run_stat)),
            "mode": stat.S_IMODE(run_stat.st_mode),
        }
    }
    assert stored["files"] == {
        "artifact.bin": {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "file_identity": list(evidence.file_identity),
            "canonical_path": evidence.canonical_path,
            "canonical_parent_path": parent_canonical_path,
        }
    }


def test_seal_verification_ignores_timestamp_metadata_changes(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX seal contract test")
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "catalog.csv"
    artifact.write_bytes(b"product_id,sku\n1,SKU-1\n")

    seal = build_run_seal(run)
    original_stat = artifact.stat()
    os.utime(
        artifact,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
    )

    assert verify_run_seal(run) == seal


def test_load_sealed_run_rejects_added_empty_directory(tmp_path: Path) -> None:
    run = tmp_path / "run"
    reports = run / "reports"
    reports.mkdir(parents=True)
    (run / "artifact.bin").write_bytes(b"artifact")
    build_run_seal(run)

    os.chmod(reports, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    (reports / "empty").mkdir()
    with pytest.raises(ValueError, match="directory set"):
        verify_run_seal(run)


def test_load_sealed_run_rejects_non_object_json(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "seal.json").write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid run seal structure"):
        verify_run_seal(run)


def test_load_sealed_run_rejects_previous_seal_version(tmp_path: Path) -> None:
    payload = json.dumps({"version": integrity.SEAL_VERSION - 1, "directories": {}, "files": {}}).encode()
    evidence = integrity.Evidence(
        path=tmp_path / "seal.json",
        data=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        file_identity=(1, 2, len(payload), 1),
        canonical_path=str(tmp_path / "seal.json"),
    )

    with pytest.raises(ValueError, match="invalid run seal structure"):
        integrity._decode_run_seal(evidence)


def test_seal_verification_ignores_metadata_only_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "catalog.csv"
    artifact.write_bytes(b"product_id,sku\n1,SKU-1\n")
    if os.name == "nt":
        monkeypatch.setattr(integrity, "_WINDOWS_TEST_SEAL_BUILDER_ENABLED", True)

    seal = build_run_seal(run)
    sealed_root_mode = stat.S_IMODE(run.stat().st_mode)
    original_stat = artifact.stat()
    os.chmod(run, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    os.chmod(artifact, stat.S_IREAD | stat.S_IWRITE)
    os.chmod(run, sealed_root_mode)
    os.utime(
        artifact,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
    )

    assert verify_run_seal(run) == seal


def test_load_sealed_run_rejects_relative_canonical_path_binding(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"artifact")
    build_run_seal(run)

    seal_path = run / "seal.json"
    seal_path.chmod(stat.S_IREAD | stat.S_IWRITE)
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["files"]["artifact.bin"]["canonical_path"] = "artifact.bin"
    seal_path.write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="canonical path"):
        verify_run_seal(run)


def test_load_sealed_run_rejects_parent_path_binding_mismatch(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"artifact")
    build_run_seal(run)

    seal_path = run / "seal.json"
    seal_path.chmod(stat.S_IREAD | stat.S_IWRITE)
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["files"]["artifact.bin"]["canonical_parent_path"] = "wrong-parent"
    seal_path.write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="parent path"):
        verify_run_seal(run)


def test_load_sealed_run_rejects_artifact_changed_after_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"original")
    build_run_seal(run)
    mutated = False
    if os.name == "nt":
        original_read = integrity.read_evidence

        def read_then_mutate(path: str | Path):
            nonlocal mutated
            evidence = original_read(path)
            if Path(path) == artifact and not mutated:
                mutated = True
                os.chmod(artifact, stat.S_IREAD | stat.S_IWRITE)
                artifact.write_bytes(b"changed after capture")
            return evidence

        monkeypatch.setattr(integrity, "read_evidence", read_then_mutate)
    else:
        original_read_fd = integrity._read_evidence_from_fd

        def read_then_mutate(fd: int, path: Path, **kwargs: object) -> integrity.Evidence:
            nonlocal mutated
            evidence = original_read_fd(fd, path, **kwargs)
            if path == artifact and not mutated:
                mutated = True
                os.chmod(artifact, stat.S_IREAD | stat.S_IWRITE)
                artifact.write_bytes(b"changed after capture")
            return evidence

        monkeypatch.setattr(integrity, "_read_evidence_from_fd", read_then_mutate)
    with pytest.raises(ValueError, match="changed during verification"):
        verify_run_seal(run)


def test_fd_evidence_can_repeat_without_shared_offset_drift(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    fd = os.open(source, os.O_RDONLY)
    try:
        first = integrity._read_evidence_from_fd(fd, source)
        second = integrity._read_evidence_from_fd(fd, source)
    finally:
        os.close(fd)

    assert first.data == second.data == b"payload"
    assert first.sha256 == second.sha256
    assert first.file_identity == second.file_identity


def test_fd_evidence_rejects_hard_link_added_after_open(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    alias = tmp_path / "alias.bin"
    source.write_bytes(b"payload")
    fd = os.open(source, os.O_RDONLY)
    try:
        os.link(source, alias)
        with pytest.raises(ValueError, match="hard-link"):
            integrity._read_evidence_from_fd(fd, source)
    finally:
        os.close(fd)


def test_read_evidence_rejects_handle_for_different_canonical_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.bin"
    alternate = tmp_path / "alternate.bin"
    source.write_bytes(b"same bytes")
    alternate.write_bytes(b"same bytes")
    original_open = integrity._open_non_following

    def open_alternate(_path: Path) -> int:
        return original_open(alternate)

    monkeypatch.setattr(integrity, "_open_non_following", open_alternate)
    with pytest.raises(ValueError, match="canonical path"):
        read_evidence(source)


def test_load_sealed_run_rejects_same_bytes_with_new_file_identity(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"same bytes")
    build_run_seal(run)

    sealed_root_mode = stat.S_IMODE(run.stat().st_mode)
    os.chmod(run, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    replacement = run / "replacement.bin"
    replacement.write_bytes(b"same bytes")
    os.chmod(artifact, stat.S_IREAD | stat.S_IWRITE)
    os.replace(replacement, artifact)
    os.chmod(run, sealed_root_mode)

    with pytest.raises(ValueError, match="identity mismatch|changed during verification"):
        verify_run_seal(run)


def test_load_sealed_run_rejects_canonical_path_record_tamper(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.bin"
    artifact.write_bytes(b"payload")
    build_run_seal(run)

    seal_path = run / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["files"]["artifact.bin"]["canonical_path"] = "C:\\attacker\\artifact.bin"
    os.chmod(seal_path, stat.S_IREAD | stat.S_IWRITE)
    seal_path.write_text(json.dumps(seal), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical path|identity mismatch"):
        verify_run_seal(run)


@pytest.mark.skipif(os.name != "nt" and os.geteuid() == 0, reason="root bypasses POSIX write-permission checks")
def test_completed_bundle_artifacts_are_read_only(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "artifact.txt"
    artifact.write_text("immutable", encoding="utf-8")

    build_run_seal(run)

    with pytest.raises(PermissionError):
        artifact.write_text("tampered", encoding="utf-8")
    assert artifact.read_text(encoding="utf-8") == "immutable"


def test_netlab_service_imports_from_root_owned_checkout() -> None:
    service = (
        Path(__file__).parents[1] / "deploy" / "mks123-netlab-shadow.service"
    ).read_text(encoding="utf-8")

    assert (
        service.count("Environment=PYTHONPATH=/opt/mks123/supplier-pipeline") == 1
    )
    assert "Environment=PYTHONPATH=." not in service
