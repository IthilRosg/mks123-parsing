from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

SEAL_NAME = "seal.json"
SEAL_VERSION = 4


@dataclass(frozen=True)
class Evidence:
    path: Path
    data: bytes
    sha256: str
    file_identity: tuple[int, int, int, int, int, int]
    canonical_path: str


@dataclass(frozen=True)
class SealedRunEvidence:
    seal: dict[str, Any]
    seal_evidence: Evidence
    files: dict[str, Evidence]


if os.name == "nt":
    _GENERIC_READ = 0x80000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_BASIC_INFO_CLASS = 0
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
    _KERNEL32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _KERNEL32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _KERNEL32.GetFinalPathNameByHandleW.restype = wintypes.DWORD


def _normalized_physical_path(value: str | Path) -> str:
    text = os.path.abspath(os.fspath(value))
    if os.name == "nt":
        if text.startswith("\\\\?\\UNC\\"):
            text = "\\\\" + text[8:]
        elif text.startswith("\\\\?\\"):
            text = text[4:]
    return os.path.normcase(os.path.normpath(text))


def _canonical_path_from_fd(fd: int) -> str:
    if os.name == "nt":
        handle = msvcrt.get_osfhandle(fd)
        buffer = ctypes.create_unicode_buffer(32768)
        length = _KERNEL32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if length == 0 or length >= len(buffer):
            raise _win_error()
        return _normalized_physical_path(buffer.value)
    try:
        return _normalized_physical_path(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError as exc:
        raise ValueError("cannot determine evidence canonical path") from exc


def _win_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def _open_windows_parent_directories(path: Path) -> list[int]:
    if os.name != "nt":
        return []
    handles: list[int] = []
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        for parent in reversed(tuple(absolute.parents)):
            handle = _KERNEL32.CreateFileW(
                str(parent),
                _GENERIC_READ,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                None,
                _OPEN_EXISTING,
                _FILE_ATTRIBUTE_NORMAL
                | _FILE_FLAG_OPEN_REPARSE_POINT
                | _FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise _win_error()
            basic = _FileBasicInfo()
            if not _KERNEL32.GetFileInformationByHandleEx(
                handle,
                _FILE_BASIC_INFO_CLASS,
                ctypes.byref(basic),
                ctypes.sizeof(basic),
            ):
                _KERNEL32.CloseHandle(handle)
                raise _win_error()
            if basic.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                _KERNEL32.CloseHandle(handle)
                raise ValueError(f"evidence parent is a reparse point: {parent}")
            if not basic.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
                _KERNEL32.CloseHandle(handle)
                raise ValueError(f"evidence parent is not a directory: {parent}")
            handles.append(int(handle))
        return handles
    except BaseException:
        for handle in handles:
            _KERNEL32.CloseHandle(handle)
        raise


def _close_windows_parent_directories(handles: list[int]) -> None:
    if os.name == "nt":
        for handle in handles:
            _KERNEL32.CloseHandle(handle)


def _open_non_following(path: Path) -> int:
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)

    parent_handles = _open_windows_parent_directories(path)
    handle = _INVALID_HANDLE_VALUE
    transferred = False
    try:
        handle = _KERNEL32.CreateFileW(
            str(path),
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise _win_error()
        basic = _FileBasicInfo()
        if not _KERNEL32.GetFileInformationByHandleEx(
            handle,
            _FILE_BASIC_INFO_CLASS,
            ctypes.byref(basic),
            ctypes.sizeof(basic),
        ):
            raise _win_error()
        if basic.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError(f"evidence path is a reparse point: {path.name}")
        if basic.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
            raise ValueError(f"evidence path is a directory: {path.name}")
        fd = msvcrt.open_osfhandle(int(handle), os.O_RDONLY | os.O_BINARY)
        transferred = True
        return fd
    finally:
        if not transferred and handle != _INVALID_HANDLE_VALUE:
            _KERNEL32.CloseHandle(handle)
        _close_windows_parent_directories(parent_handles)


def _file_identity(file_stat: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
        getattr(file_stat, "st_nlink", 1),
    )


def read_evidence(
    path: str | Path,
    *,
    max_bytes: int | None = None,
    calculate_hash: bool = True,
) -> Evidence:
    source_path = Path(path)
    if max_bytes is not None and (not isinstance(max_bytes, int) or max_bytes < 0):
        raise ValueError("evidence max_bytes must be a non-negative integer")
    expected_canonical_path = _normalized_physical_path(source_path.resolve(strict=True))
    fd: int | None = None
    try:
        fd = _open_non_following(source_path)
        opened_canonical_path = _canonical_path_from_fd(fd)
        if opened_canonical_path != expected_canonical_path:
            raise ValueError(f"evidence canonical path changed: {source_path.name}")
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"evidence path is not a regular file: {source_path.name}")
        if getattr(before, "st_nlink", 1) > 1:
            raise ValueError(f"evidence path is a hard-link entry: {source_path.name}")
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            read_limit = max_bytes + 1 if max_bytes is not None else -1
            data = handle.read(read_limit)
            after = os.fstat(handle.fileno())
        identity = _file_identity(before)
        if identity != _file_identity(after):
            raise ValueError(f"evidence file changed while reading: {source_path.name}")
    finally:
        if fd is not None:
            os.close(fd)
    return Evidence(
        path=source_path,
        data=data,
        sha256=(hashlib.sha256(data).hexdigest() if calculate_hash else ""),
        file_identity=identity,
        canonical_path=opened_canonical_path,
    )


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
    if (
        (evidence.sha256 and current.sha256 != evidence.sha256)
        or len(current.data) != len(evidence.data)
        or current.file_identity != evidence.file_identity
        or current.canonical_path != evidence.canonical_path
    ):
        raise ValueError(f"sealed run file changed during verification: {label}")


def build_run_seal(run_dir: str | Path) -> dict[str, Any]:
    run_dir = Path(run_dir)
    seal_path = run_dir / SEAL_NAME
    if seal_path.exists():
        raise FileExistsError(f"run seal already exists: {seal_path}")
    files: dict[str, dict[str, Any]] = {}
    for relative, path in sorted(_file_paths(run_dir).items()):
        evidence = read_evidence(path)
        files[relative] = {
            "sha256": evidence.sha256,
            "size": len(evidence.data),
            "file_identity": list(evidence.file_identity),
            "canonical_path": relative,
        }
    seal: dict[str, Any] = {"version": SEAL_VERSION, "files": files}
    payload = (json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with seal_path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    if read_evidence(seal_path).data != payload:
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
    if seal.get("version") != SEAL_VERSION or not isinstance(seal.get("files"), dict):
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
        if not isinstance(record, dict):
            raise TypeError(f"sealed run record is invalid: {relative}")
        if evidence.sha256 != record.get("sha256"):
            raise ValueError(f"sealed run hash mismatch: {relative}")
        if len(evidence.data) != record.get("size"):
            raise ValueError(f"sealed run size mismatch: {relative}")
        expected_identity = record.get("file_identity")
        if (
            not isinstance(expected_identity, list)
            or len(expected_identity) != len(evidence.file_identity)
            or tuple(expected_identity) != evidence.file_identity
        ):
            raise ValueError(f"sealed run identity mismatch: {relative}")
        if record.get("canonical_path") != relative:
            raise ValueError(f"sealed run canonical path mismatch: {relative}")
    if set(_file_paths(run_dir)) != expected:
        raise ValueError("sealed run file set changed during verification")
    _assert_evidence_unchanged(run_dir / SEAL_NAME, seal_evidence, SEAL_NAME)
    for relative in sorted(expected):
        _assert_evidence_unchanged(paths_before[relative], files[relative], relative)
    return SealedRunEvidence(seal=seal, seal_evidence=seal_evidence, files=files)


def verify_run_seal(run_dir: str | Path) -> dict[str, Any]:
    return load_sealed_run(run_dir).seal
