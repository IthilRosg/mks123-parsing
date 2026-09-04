import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mks123_pipeline import snapshot_store
from mks123_pipeline.snapshot_store import install_snapshot, snapshot_target


def _part(root: Path, name: str, payload: bytes = b"<yml_catalog />") -> Path:
    path = root / name
    path.write_bytes(payload)
    return path


def test_snapshot_target_rejects_untrusted_feed_date_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid feed catalog date"):
        snapshot_target(tmp_path, "x/../../outside", "a" * 64)


def test_snapshot_target_includes_supplier_identity(tmp_path: Path) -> None:
    target = snapshot_target(tmp_path, "2026-09-01 13:20", "a" * 64, supplier_id="netlab")
    assert target.name.startswith("netlab-live-")


def test_concurrent_snapshot_install_is_atomic_no_clobber(tmp_path: Path) -> None:
    payload = b"immutable supplier payload"
    parts = [_part(tmp_path, f".{index}.part", payload) for index in range(2)]

    def install(part: Path):
        return install_snapshot(
            part,
            tmp_path,
            feed_date="2026-09-01 13:20",
            content_hash=hashlib.sha256(payload).hexdigest(),
            metadata={"supplier": "electrozone", "offer_count": 2163},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(install, parts))

    targets = {result.target for result in results}
    assert len(targets) == 1
    target = targets.pop()
    assert target.read_bytes() == payload
    assert sorted(result.created for result in results) == [False, True]
    assert target.with_suffix(".metadata.json").is_file()


def test_deduplicated_snapshot_repairs_missing_metadata(tmp_path: Path) -> None:
    payload = b"immutable supplier payload"
    content_hash = hashlib.sha256(payload).hexdigest()
    first = install_snapshot(
        _part(tmp_path, ".first.part", payload),
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=content_hash,
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )
    snapshot_store._remove_readonly(first.target.with_suffix(".metadata.json"))

    repaired = install_snapshot(
        _part(tmp_path, ".second.part", payload),
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=content_hash,
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )

    assert repaired.created is False
    assert repaired.metadata_created is True
    assert repaired.target.with_suffix(".metadata.json").is_file()


def test_installed_snapshot_is_not_a_writable_alias_of_source_part(tmp_path: Path) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)
    installed = install_snapshot(
        part,
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=hashlib.sha256(payload).hexdigest(),
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )

    part.write_bytes(b"tampered after install")

    assert installed.target.read_bytes() == payload


def test_source_part_mutation_after_capture_cannot_change_published_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)
    original_publish = snapshot_store._publish_exclusive_readonly

    def mutate_after_capture(path: Path, data: bytes) -> bool:
        if path.suffix == ".yml":
            part.write_bytes(b"tampered after capture")
        return original_publish(path, data)

    monkeypatch.setattr(snapshot_store, "_publish_exclusive_readonly", mutate_after_capture)
    installed = install_snapshot(
        part,
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=hashlib.sha256(payload).hexdigest(),
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )

    assert installed.target.read_bytes() == payload


def test_snapshot_publication_uses_no_hardlink_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)

    def reject_hardlink(*args, **kwargs):
        raise AssertionError("snapshot publication must not create a writable hard-link alias")

    monkeypatch.setattr(snapshot_store.os, "link", reject_hardlink)
    installed = install_snapshot(
        part,
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=hashlib.sha256(payload).hexdigest(),
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )

    assert installed.target.read_bytes() == payload
    assert list(tmp_path.glob(".snapshot-stage-*.part")) == []


def test_final_snapshot_name_rejects_a_second_writer_during_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    content_hash = hashlib.sha256(payload).hexdigest()
    part = _part(tmp_path, ".source.part", payload)
    original_read_handle = snapshot_store._read_handle
    checked = False

    def check_exclusive_handle(handle: int) -> bytes:
        nonlocal checked
        if not checked:
            checked = True
            target = next(tmp_path.glob("electrozone-live-*.yml"))
            competing = snapshot_store._KERNEL32.CreateFileW(
                str(target),
                snapshot_store._GENERIC_WRITE,
                0x1 | 0x2 | 0x4,
                None,
                snapshot_store._OPEN_EXISTING,
                snapshot_store._FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if competing != snapshot_store._INVALID_HANDLE_VALUE:
                snapshot_store._KERNEL32.CloseHandle(competing)
                raise AssertionError("a competing writer opened the snapshot during read-back")
            assert snapshot_store.ctypes.get_last_error() == 32
        return original_read_handle(handle)

    monkeypatch.setattr(snapshot_store, "_read_handle", check_exclusive_handle)
    installed = install_snapshot(
        part,
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=content_hash,
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )

    assert installed.target.read_bytes() == payload
    assert installed.metadata["sha256"] == content_hash
    assert checked is True


def test_target_publish_readback_failure_removes_new_snapshot_and_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)
    original_read_handle = snapshot_store._read_handle
    calls = 0

    def fail_first_readback(handle: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected target read-back failure")
        return original_read_handle(handle)

    monkeypatch.setattr(snapshot_store, "_read_handle", fail_first_readback)
    with pytest.raises(OSError, match="injected target read-back failure"):
        install_snapshot(
            part,
            tmp_path,
            feed_date="2026-09-01 13:20",
            content_hash=hashlib.sha256(payload).hexdigest(),
            metadata={"supplier": "electrozone", "offer_count": 2163},
        )

    assert list(tmp_path.glob("electrozone-live-*.yml")) == []
    assert list(tmp_path.glob("electrozone-live-*.metadata.json")) == []


def test_published_manifest_is_readonly_and_uses_no_hardlink_alias(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)

    def reject_hardlink(*args, **kwargs):
        raise AssertionError("manifest publication must not create a writable hard-link alias")

    monkeypatch.setattr(snapshot_store.os, "link", reject_hardlink)
    installed = install_snapshot(
        part,
        tmp_path,
        feed_date="2026-09-01 13:20",
        content_hash=hashlib.sha256(payload).hexdigest(),
        metadata={"supplier": "electrozone", "offer_count": 2163},
    )
    metadata_path = installed.target.with_suffix(".metadata.json")

    with pytest.raises(PermissionError):
        metadata_path.write_text('{"local_file":"wrong.yml","sha256":"0000"}', encoding="utf-8")
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["sha256"] == installed.metadata["sha256"]


def test_partial_manifest_write_leaves_no_temporary_or_published_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    part = _part(tmp_path, ".source.part", payload)

    original_write = snapshot_store._KERNEL32.WriteFile
    calls = 0

    def fail_metadata_write(handle, buffer, length, count, overlapped):
        nonlocal calls
        calls += 1
        if calls == 2:
            partial = snapshot_store.ctypes.create_string_buffer(b"partial")
            written = snapshot_store.wintypes.DWORD()
            original_write(handle, partial, len(b"partial"), snapshot_store.ctypes.byref(written), None)
            snapshot_store.ctypes.set_last_error(5)
            return 0
        return original_write(handle, buffer, length, count, overlapped)

    monkeypatch.setattr(snapshot_store._KERNEL32, "WriteFile", fail_metadata_write)
    with pytest.raises(OSError):
        install_snapshot(
            part,
            tmp_path,
            feed_date="2026-09-01 13:20",
            content_hash=hashlib.sha256(payload).hexdigest(),
            metadata={"supplier": "electrozone", "offer_count": 2163},
        )

    assert list(tmp_path.glob("electrozone-live-*.yml")) == []
    assert list(tmp_path.glob("*.metadata.json")) == []
    assert list(tmp_path.glob("*.metadata.json.*.part")) == []


def test_failed_creator_cannot_delete_snapshot_adopted_by_concurrent_installer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"immutable supplier payload"
    content_hash = hashlib.sha256(payload).hexdigest()
    a_at_hash = threading.Event()
    allow_a_failure = threading.Event()
    b_finished = threading.Event()
    original_sha256 = snapshot_store.hashlib.sha256
    thread_calls: dict[str, int] = {}

    def coordinated_hash(data: bytes = b""):
        thread_name = threading.current_thread().name
        thread_calls[thread_name] = thread_calls.get(thread_name, 0) + 1
        if thread_name == "installer-a" and thread_calls[thread_name] == 2:
            a_at_hash.set()
            assert allow_a_failure.wait(timeout=10)
            raise OSError("injected creator verification failure")
        return original_sha256(data)

    monkeypatch.setattr(snapshot_store.hashlib, "sha256", coordinated_hash)
    outcomes: dict[str, object] = {}

    def installer_a() -> None:
        try:
            install_snapshot(
                _part(tmp_path, ".a.part", payload),
                tmp_path,
                feed_date="2026-09-01 13:20",
                content_hash=content_hash,
                metadata={"supplier": "electrozone", "offer_count": 2163},
            )
        except OSError as exc:
            outcomes["a"] = exc

    def installer_b() -> None:
        assert a_at_hash.wait(timeout=10)
        try:
            outcomes["b"] = install_snapshot(
                _part(tmp_path, ".b.part", payload),
                tmp_path,
                feed_date="2026-09-01 13:20",
                content_hash=content_hash,
                metadata={"supplier": "electrozone", "offer_count": 2163},
            )
        finally:
            b_finished.set()

    a = threading.Thread(target=installer_a, name="installer-a")
    b = threading.Thread(target=installer_b, name="installer-b")
    a.start()
    assert a_at_hash.wait(timeout=10)
    b.start()
    assert not b_finished.wait(timeout=0.2)
    allow_a_failure.set()
    a.join(timeout=15)
    b.join(timeout=15)

    assert isinstance(outcomes.get("a"), OSError)
    assert outcomes["b"].target.read_bytes() == payload
    assert outcomes["b"].target.with_suffix(".metadata.json").is_file()


def test_failed_install_preserves_preexisting_mismatched_metadata(tmp_path: Path) -> None:
    payload = b"immutable supplier payload"
    content_hash = hashlib.sha256(payload).hexdigest()
    target = snapshot_target(tmp_path, "2026-09-01 13:20", content_hash)
    metadata_path = target.with_suffix(".metadata.json")
    original_metadata = '{"local_file":"other.yml","sha256":"' + "0" * 64 + '"}\n'
    metadata_path.write_text(original_metadata, encoding="utf-8")

    with pytest.raises(RuntimeError, match="identity mismatch"):
        install_snapshot(
            _part(tmp_path, ".source.part", payload),
            tmp_path,
            feed_date="2026-09-01 13:20",
            content_hash=content_hash,
            metadata={"supplier": "electrozone", "offer_count": 2163},
        )

    assert not target.exists()
    assert metadata_path.read_text(encoding="utf-8") == original_metadata


def test_failed_install_with_metadata_directory_cleans_new_target(
    tmp_path: Path,
) -> None:
    payload = b"immutable supplier payload"
    content_hash = hashlib.sha256(payload).hexdigest()
    target = snapshot_target(tmp_path, "2026-09-01 13:20", content_hash)
    metadata_path = target.with_suffix(".metadata.json")
    metadata_path.mkdir()
    sentinel = metadata_path / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises((OSError, RuntimeError)):
        install_snapshot(
            _part(tmp_path, ".source.part", payload),
            tmp_path,
            feed_date="2026-09-01 13:20",
            content_hash=content_hash,
            metadata={"supplier": "electrozone", "offer_count": 2163},
        )

    assert not target.exists()
    assert metadata_path.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_target_lock_timeout_applies_to_same_process_contention(tmp_path: Path) -> None:
    target = snapshot_target(tmp_path, "2026-09-01 13:20", "a" * 64)
    acquired = threading.Event()
    release = threading.Event()
    contender_done = threading.Event()
    outcome: dict[str, object] = {}

    def holder() -> None:
        with snapshot_store._target_lock(target, timeout=1.0):
            acquired.set()
            release.wait(timeout=2.0)

    def contender() -> None:
        started = time.monotonic()
        try:
            with snapshot_store._target_lock(target, timeout=0.1):
                outcome["status"] = "acquired"
        except TimeoutError:
            outcome["status"] = "timed_out"
        finally:
            outcome["elapsed"] = time.monotonic() - started
            contender_done.set()

    first = threading.Thread(target=holder)
    second = threading.Thread(target=contender)
    first.start()
    assert acquired.wait(timeout=2.0)
    second.start()
    assert contender_done.wait(timeout=0.4)
    release.set()
    first.join(timeout=2.0)
    second.join(timeout=2.0)

    assert not first.is_alive() and not second.is_alive()
    assert outcome["status"] == "timed_out"
    assert float(outcome["elapsed"]) < 0.4
