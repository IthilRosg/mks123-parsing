from __future__ import annotations

import ctypes
import hashlib
import json
import msvcrt
import os
import re
import threading
import time as time_module
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from datetime import date, time
from pathlib import Path
from typing import Any

from .integrity import read_evidence

_FEED_DATE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUPPLIER_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SOURCE_SUFFIX = re.compile(r"^\.(?:feed|xml|yml|zip)$")
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_WRITE_ATTRIBUTES = 0x0100
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_READONLY = 0x00000001
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_BEGIN = 0
_FILE_BASIC_INFO_CLASS = 0
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", wintypes.DWORD),
    ]


_KERNEL32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
_KERNEL32.CreateFileW.restype = wintypes.HANDLE
_KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
_KERNEL32.CloseHandle.restype = wintypes.BOOL
_KERNEL32.WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_KERNEL32.WriteFile.restype = wintypes.BOOL
_KERNEL32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
_KERNEL32.ReadFile.restype = wintypes.BOOL
_KERNEL32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
_KERNEL32.FlushFileBuffers.restype = wintypes.BOOL
_KERNEL32.SetFilePointerEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_longlong,
    ctypes.POINTER(ctypes.c_longlong),
    wintypes.DWORD,
]
_KERNEL32.SetFilePointerEx.restype = wintypes.BOOL
_KERNEL32.GetFileInformationByHandleEx.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
]
_KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
_KERNEL32.SetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
]
_KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
_KERNEL32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
_KERNEL32.SetFileAttributesW.restype = wintypes.BOOL


@dataclass(frozen=True)
class SnapshotInstallResult:
    target: Path
    created: bool
    metadata_created: bool
    metadata: dict[str, Any]


def _win_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def _read_handle(handle: int) -> bytes:
    new_position = ctypes.c_longlong()
    if not _KERNEL32.SetFilePointerEx(handle, 0, ctypes.byref(new_position), _FILE_BEGIN):
        raise _win_error()
    chunks: list[bytes] = []
    while True:
        buffer = ctypes.create_string_buffer(1024 * 1024)
        count = wintypes.DWORD()
        if not _KERNEL32.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None):
            raise _win_error()
        if count.value == 0:
            return b"".join(chunks)
        chunks.append(buffer.raw[: count.value])


def _set_handle_readonly(handle: int) -> None:
    basic = _FileBasicInfo()
    size = ctypes.sizeof(basic)
    if not _KERNEL32.GetFileInformationByHandleEx(
        handle,
        _FILE_BASIC_INFO_CLASS,
        ctypes.byref(basic),
        size,
    ):
        raise _win_error()
    basic.FileAttributes |= _FILE_ATTRIBUTE_READONLY
    if not _KERNEL32.SetFileInformationByHandle(
        handle,
        _FILE_BASIC_INFO_CLASS,
        ctypes.byref(basic),
        size,
    ):
        raise _win_error()


def _remove_readonly(path: Path) -> None:
    if not path.exists():
        return
    if not path.is_file():
        return
    _KERNEL32.SetFileAttributesW(str(path), _FILE_ATTRIBUTE_NORMAL)
    path.unlink(missing_ok=True)


def _publish_exclusive_readonly(path: Path, data: bytes) -> bool:
    handle = _KERNEL32.CreateFileW(
        str(path),
        _GENERIC_READ | _GENERIC_WRITE | _FILE_WRITE_ATTRIBUTES,
        0,
        None,
        _CREATE_NEW,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
            return False
        raise ctypes.WinError(error)
    succeeded = False
    try:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            count = wintypes.DWORD()
            if not _KERNEL32.WriteFile(handle, buffer, len(chunk), ctypes.byref(count), None):
                raise _win_error()
            if count.value != len(chunk):
                raise OSError("short write while publishing immutable file")
            offset += count.value
        if not _KERNEL32.FlushFileBuffers(handle):
            raise _win_error()
        if _read_handle(handle) != data:
            raise RuntimeError(f"published file read-back mismatch: {path.name}")
        _set_handle_readonly(handle)
        succeeded = True
        return True
    finally:
        _KERNEL32.CloseHandle(handle)
        if not succeeded:
            _remove_readonly(path)


def _read_existing_exclusive_readonly(path: Path) -> bytes:
    handle = _KERNEL32.CreateFileW(
        str(path),
        _GENERIC_READ | _FILE_WRITE_ATTRIBUTES,
        0,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise _win_error()
    try:
        data = _read_handle(handle)
        _set_handle_readonly(handle)
        return data
    finally:
        _KERNEL32.CloseHandle(handle)


@contextmanager
def _target_lock(target: Path, timeout: float = 30.0):
    key = str(target)
    with _THREAD_LOCKS_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(key, threading.Lock())
    deadline = time_module.monotonic() + timeout
    remaining = max(0.0, deadline - time_module.monotonic())
    if not thread_lock.acquire(timeout=remaining):
        raise TimeoutError(f"timed out waiting for snapshot lock: {target.name}")
    try:
        lock_path = target.with_suffix(target.suffix + ".lock")
        with lock_path.open("a+b") as handle:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            while True:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time_module.monotonic() >= deadline:
                        raise TimeoutError(f"timed out waiting for snapshot lock: {target.name}")
                    time_module.sleep(0.02)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    finally:
        thread_lock.release()


def snapshot_target(
    root: str | Path,
    feed_date: str,
    content_hash: str,
    *,
    supplier_id: str = "electrozone",
    source_suffix: str = ".yml",
) -> Path:
    root = Path(root).resolve()
    if not _SUPPLIER_ID.fullmatch(supplier_id):
        raise ValueError("invalid supplier id for snapshot target")
    if not _SOURCE_SUFFIX.fullmatch(source_suffix):
        raise ValueError("invalid snapshot source suffix")
    if not _FEED_DATE.fullmatch(feed_date):
        raise ValueError("invalid feed catalog date; expected YYYY-MM-DD HH:MM")
    try:
        feed_day = date.fromisoformat(feed_date[:10])
        feed_time = time.fromisoformat(feed_date[11:])
    except ValueError as exc:
        raise ValueError("invalid feed catalog date; expected YYYY-MM-DD HH:MM") from exc
    if not _SHA256.fullmatch(content_hash):
        raise ValueError("invalid SHA-256 content hash")
    stamp = f"{feed_day:%Y%m%d}T{feed_time:%H%M}"
    target = (root / f"{supplier_id}-live-{stamp}-{content_hash[:12]}{source_suffix}").resolve()
    if target.parent != root:
        raise ValueError("snapshot target escapes configured root")
    return target


def _install_metadata(
    target: Path,
    content_hash: str,
    metadata: dict[str, Any],
    required_existing_metadata: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any]]:
    metadata_path = target.with_suffix(".metadata.json")
    required = {**metadata, "local_file": target.name, "sha256": content_hash}
    expected = (json.dumps(required, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    created = _publish_exclusive_readonly(metadata_path, expected)
    if created:
        return True, required
    try:
        existing = json.loads(_read_existing_exclusive_readonly(metadata_path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid snapshot metadata: {metadata_path.name}") from exc
    if existing.get("local_file") != target.name or existing.get("sha256") != required["sha256"]:
        raise RuntimeError(f"snapshot metadata identity mismatch: {metadata_path.name}")
    for key, expected_value in (required_existing_metadata or {}).items():
        if existing.get(key) != expected_value:
            raise RuntimeError(f"snapshot metadata conflict for {key}: {metadata_path.name}")
    return False, existing


def install_snapshot(
    part: str | Path,
    root: str | Path,
    *,
    feed_date: str,
    content_hash: str,
    metadata: dict[str, Any],
    required_existing_metadata: dict[str, Any] | None = None,
    source_suffix: str = ".yml",
) -> SnapshotInstallResult:
    part = Path(part)
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    if part.resolve().parent != root:
        raise ValueError("snapshot temporary file must be inside configured root")
    source_data = read_evidence(part, calculate_hash=False).data
    if hashlib.sha256(source_data).hexdigest() != content_hash:
        raise ValueError("snapshot temporary file hash mismatch")
    supplier_id = metadata.get("supplier")
    if not isinstance(supplier_id, str) or not _SUPPLIER_ID.fullmatch(supplier_id):
        raise ValueError("snapshot metadata requires a valid supplier id")
    target = snapshot_target(
        root,
        feed_date,
        content_hash,
        supplier_id=supplier_id,
        source_suffix=source_suffix,
    )
    with _target_lock(target):
        created = _publish_exclusive_readonly(target, source_data)
        metadata_created = False
        try:
            installed_data = source_data if created else _read_existing_exclusive_readonly(target)
            if hashlib.sha256(installed_data).hexdigest() != content_hash:
                raise RuntimeError(f"immutable snapshot hash mismatch: {target.name}")
            metadata_created, stored_metadata = _install_metadata(
                target,
                content_hash,
                metadata,
                required_existing_metadata,
            )
            return SnapshotInstallResult(
                target=target,
                created=created,
                metadata_created=metadata_created,
                metadata=stored_metadata,
            )
        except BaseException:
            if created:
                if metadata_created:
                    _remove_readonly(target.with_suffix(".metadata.json"))
                _remove_readonly(target)
            raise
