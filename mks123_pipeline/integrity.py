from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class IntegrityDeadlineExceeded(RuntimeError):
    """Raised when a bounded integrity operation exceeds its caller deadline."""


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

SEAL_NAME = "seal.json"
SEAL_VERSION = 6
_MAX_SEALED_TREE_ENTRIES = 100_000
_MAX_SEAL_BYTES = 16 * 1024 * 1024
_WINDOWS_TEST_SEAL_BUILDER_ENABLED = False
_PLATFORM_OS_OPEN = os.open
_PLATFORM_OS_STAT = os.stat
_PLATFORM_OS_LISTDIR = os.listdir


@dataclass(frozen=True)
class Evidence:
    path: Path
    data: bytes
    sha256: str
    file_identity: tuple[int, int, int, int]
    canonical_path: str
    size: int | None = None


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


def _canonical_parent_path(canonical_path: str) -> str:
    return _normalized_physical_path(Path(canonical_path).parent)


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


def _close_parent_handles(handles: list[int]) -> None:
    if os.name == "nt":
        _close_windows_parent_directories(handles)
        return
    for handle in reversed(handles):
        try:
            os.close(handle)
        except OSError:
            pass


def _open_posix_non_following(path: Path) -> tuple[int, list[int]]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_handles: list[int] = []
    try:
        parent_fd = os.open(os.sep, directory_flags)
        parent_handles.append(parent_fd)
        for component in absolute.parts[1:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            parent_handles.append(child_fd)
            parent_fd = child_fd
        filename = absolute.parts[-1]
        fd = os.open(
            filename,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        return fd, parent_handles
    except BaseException:
        _close_parent_handles(parent_handles)
        raise


def _open_non_following(path: Path) -> tuple[int, list[int]]:
    if os.name != "nt":
        return _open_posix_non_following(path)

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
        return fd, parent_handles
    finally:
        if not transferred:
            if handle != _INVALID_HANDLE_VALUE:
                _KERNEL32.CloseHandle(handle)
            _close_windows_parent_directories(parent_handles)


def _file_identity(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    """Return identity fields stable across chmod, rename, and timestamp updates."""
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        getattr(file_stat, "st_nlink", 1),
    )


def _directory_identity(directory_stat: os.stat_result) -> tuple[int, int, int]:
    return (
        directory_stat.st_dev,
        directory_stat.st_ino,
        getattr(directory_stat, "st_nlink", 1),
    )


def read_evidence(
    path: str | Path,
    *,
    max_bytes: int | None = None,
    calculate_hash: bool = True,
    read_content: bool = True,
) -> Evidence:
    source_path = Path(path)
    if max_bytes is not None and (
        not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0
    ):
        raise ValueError("evidence max_bytes must be a non-negative integer")
    if not read_content and max_bytes is not None:
        raise ValueError("max_bytes cannot be used for identity-only evidence")

    expected_canonical_path = _normalized_physical_path(source_path.resolve(strict=True))
    fd: int | None = None
    parent_handles: list[int] = []
    try:
        opened = _open_non_following(source_path)
        if isinstance(opened, tuple):
            fd, parent_handles = opened
        else:  # Backwards-compatible seam for tests and older internal callers.
            fd = opened
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
            if read_content:
                read_limit = max_bytes + 1 if max_bytes is not None else -1
                data = handle.read(read_limit)
                if max_bytes is not None and len(data) > max_bytes:
                    raise ValueError(
                        f"evidence exceeds byte limit (max_bytes): {source_path.name}"
                    )
                sha256 = hashlib.sha256(data).hexdigest() if calculate_hash else ""
            else:
                data = b""
                digest = hashlib.sha256() if calculate_hash else None
                if digest is not None:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha256 = digest.hexdigest() if digest is not None else ""
            after = os.fstat(handle.fileno())
        identity = _file_identity(before)
        if identity != _file_identity(after):
            raise ValueError(f"evidence file changed while reading: {source_path.name}")
    finally:
        if fd is not None:
            os.close(fd)
        _close_parent_handles(parent_handles)
    return Evidence(
        path=source_path,
        data=data,
        sha256=sha256,
        file_identity=identity,
        canonical_path=opened_canonical_path,
        size=before.st_size,
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


def _set_readonly_fd(path: Path, fd: int) -> None:
    if os.name == "nt":
        _set_readonly(path)
    else:
        os.fchmod(fd, stat.S_IREAD)


def _seal_directory_paths(run_dir: Path) -> list[Path]:
    if run_dir.is_symlink():
        raise ValueError(f"sealed run does not allow symlink entries: {run_dir.name}")
    directories = [run_dir]
    for path in run_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"sealed run does not allow symlink entries: {path.name}")
        if path.is_dir():
            directories.append(path)
    return sorted(directories, key=lambda path: (len(path.parts), path.as_posix()))


def _relative_directory_name(run_dir: Path, directory: Path) -> str:
    return "." if directory == run_dir else directory.relative_to(run_dir).as_posix()


def _open_posix_directory_non_following(path: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(path)))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current_fd = os.open(os.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        os.close(current_fd)
        raise
    return current_fd


def _freeze_posix_directory(
    fd: int,
    *,
    expected_identity: tuple[int, int, int, int],
    path: Path,
    write_bits: int,
) -> None:
    before = os.fstat(fd)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError(f"sealed run path is not a directory: {path}")
    if _file_identity(before) != expected_identity:
        raise ValueError(f"sealed run directory identity changed before freeze: {path}")
    original_mode = stat.S_IMODE(before.st_mode)
    os.fchmod(fd, original_mode & ~write_bits)
    after = os.fstat(fd)
    if not os.path.samestat(before, after):
        raise ValueError(f"sealed run directory identity changed during freeze: {path}")
    if stat.S_IMODE(after.st_mode) & write_bits:
        raise ValueError(f"sealed run directory remains writable: {path}")


def _assert_evidence_unchanged(path: Path, evidence: Evidence, label: str) -> None:
    try:
        current = read_evidence(path)
    except OSError as exc:
        raise ValueError(f"sealed run file disappeared during verification: {label}") from exc
    if (
        (evidence.sha256 and current.sha256 != evidence.sha256)
        or current.size != evidence.size
        or current.file_identity != evidence.file_identity
        or current.canonical_path != evidence.canonical_path
    ):
        raise ValueError(f"sealed run file changed during verification: {label}")


def _require_posix_seal_capabilities() -> None:
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "supports_dir_fd", "supports_fd")
    if any(not hasattr(os, name) for name in required):
        raise RuntimeError("sealed run publication requires POSIX descriptor primitives")
    if _PLATFORM_OS_OPEN not in os.supports_dir_fd or _PLATFORM_OS_STAT not in os.supports_dir_fd:
        raise RuntimeError("sealed run publication requires descriptor-relative open/stat")
    if _PLATFORM_OS_LISTDIR not in os.supports_fd:
        raise RuntimeError("sealed run publication requires descriptor directory enumeration")


def _read_fd_from_start(
    fd: int,
    expected_size: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> bytes:
    if hasattr(os, "pread"):
        chunks: list[bytes] = []
        offset = 0
        remaining = expected_size + 1
        while remaining:
            if deadline_check is not None:
                deadline_check()
            chunk = os.pread(fd, min(1024 * 1024, remaining), offset)
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    original_offset = os.lseek(fd, 0, os.SEEK_CUR)
    duplicate = os.dup(fd)
    try:
        with os.fdopen(duplicate, "rb", closefd=True) as handle:
            duplicate = -1
            chunks: list[bytes] = []
            remaining = expected_size + 1
            while remaining:
                if deadline_check is not None:
                    deadline_check()
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        os.lseek(fd, original_offset, os.SEEK_SET)


def _hash_fd_from_start(
    fd: int,
    expected_size: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> str:
    digest = hashlib.sha256()
    offset = 0
    total = 0
    if hasattr(os, "pread"):
        while total < expected_size:
            if deadline_check is not None:
                deadline_check()
            chunk = os.pread(fd, min(1024 * 1024, expected_size - total), offset)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            offset += len(chunk)
    else:
        duplicate = os.dup(fd)
        try:
            with os.fdopen(duplicate, "rb", closefd=True) as handle:
                duplicate = -1
                while total < expected_size:
                    if deadline_check is not None:
                        deadline_check()
                    chunk = handle.read(min(1024 * 1024, expected_size - total))
                    if not chunk:
                        break
                    digest.update(chunk)
                    total += len(chunk)
        finally:
            if duplicate >= 0:
                os.close(duplicate)
    if total != expected_size:
        raise ValueError("sealed run file size changed while hashing")
    return digest.hexdigest()


def _read_evidence_from_fd(
    fd: int,
    display_path: Path,
    *,
    read_content: bool = True,
    deadline_check: Callable[[], None] | None = None,
    max_content_bytes: int | None = None,
) -> Evidence:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"sealed run path is not a regular file: {display_path}")
    if getattr(before, "st_nlink", 1) > 1:
        raise ValueError(f"sealed run path is a hard-link entry: {display_path}")
    if read_content and max_content_bytes is not None and before.st_size > max_content_bytes:
        raise ValueError(f"sealed run file content exceeds size limit: {display_path}")
    data = (
        _read_fd_from_start(fd, before.st_size, deadline_check=deadline_check)
        if read_content
        else b""
    )
    if read_content:
        digest = hashlib.sha256()
        for offset in range(0, len(data), 1024 * 1024):
            if deadline_check is not None:
                deadline_check()
            digest.update(data[offset : offset + 1024 * 1024])
        sha256 = digest.hexdigest()
    else:
        sha256 = _hash_fd_from_start(fd, before.st_size, deadline_check=deadline_check)
    after_read = os.fstat(fd)
    after = os.fstat(fd)
    if _file_identity(before) != _file_identity(after_read) or _file_identity(before) != _file_identity(after):
        raise ValueError(f"sealed run file changed while reading: {display_path}")
    return Evidence(
        path=display_path,
        data=data,
        sha256=sha256,
        file_identity=_file_identity(after),
        canonical_path=_canonical_path_from_fd(fd),
        size=before.st_size,
    )


def _relative_depth(relative: str) -> int:
    return 0 if relative == "." else relative.count("/") + 1


def _scan_posix_tree(
    root_fd: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directories: dict[str, dict[str, Any]] = {
        ".": {
            "relative": ".",
            "fd": root_fd,
            "parent": None,
            "name": None,
            "original_mode": None,
        }
    }
    files: dict[str, dict[str, Any]] = {}
    pending = ["."]
    entry_count = 0
    try:
        while pending:
            if deadline_check is not None:
                deadline_check()
            parent_relative = pending.pop()
            parent_fd = directories[parent_relative]["fd"]
            names: list[str] = []
            with os.scandir(parent_fd) as iterator:
                for entry in iterator:
                    if deadline_check is not None:
                        deadline_check()
                    entry_count += 1
                    if entry_count > _MAX_SEALED_TREE_ENTRIES:
                        raise ValueError("sealed run exceeds entry-count limit")
                    names.append(entry.name)
            for name in sorted(names):
                if deadline_check is not None:
                    deadline_check()
                if name in {".", ".."} or "/" in name or "\\" in name:
                    raise ValueError(f"invalid sealed run entry name: {name}")
                if parent_relative == "." and name == SEAL_NAME:
                    continue
                relative = name if parent_relative == "." else f"{parent_relative}/{name}"
                entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(entry_stat.st_mode):
                    raise ValueError(f"sealed run does not allow symlink entries: {relative}")
                if stat.S_ISDIR(entry_stat.st_mode):
                    child_fd = os.open(name, directory_flags, dir_fd=parent_fd)
                    try:
                        opened_stat = os.fstat(child_fd)
                        if not stat.S_ISDIR(opened_stat.st_mode) or not os.path.samestat(entry_stat, opened_stat):
                            raise ValueError(f"sealed run directory changed while opening: {relative}")
                    except BaseException:
                        os.close(child_fd)
                        raise
                    directories[relative] = {
                        "relative": relative,
                        "fd": child_fd,
                        "parent": parent_relative,
                        "name": name,
                        "original_mode": None,
                    }
                    pending.append(relative)
                elif stat.S_ISREG(entry_stat.st_mode):
                    file_fd = os.open(name, file_flags, dir_fd=parent_fd)
                    try:
                        opened_stat = os.fstat(file_fd)
                        if not stat.S_ISREG(opened_stat.st_mode) or not os.path.samestat(entry_stat, opened_stat):
                            raise ValueError(f"sealed run file changed while opening: {relative}")
                        if getattr(opened_stat, "st_nlink", 1) > 1:
                            raise ValueError(f"sealed run path is a hard-link entry: {relative}")
                    except BaseException:
                        os.close(file_fd)
                        raise
                    files[relative] = {
                        "relative": relative,
                        "fd": file_fd,
                        "parent": parent_relative,
                        "name": name,
                        "original_mode": None,
                        "evidence": None,
                    }
                else:
                    raise ValueError(f"sealed run path has unsupported type: {relative}")
        return directories, files
    except BaseException:
        for capture in files.values():
            os.close(capture["fd"])
        for relative in sorted(
            (key for key in directories if key != "."),
            key=_relative_depth,
            reverse=True,
        ):
            os.close(directories[relative]["fd"])
        raise


def _validate_posix_tree(
    directories: Mapping[str, Mapping[str, Any]],
    files: Mapping[str, Mapping[str, Any]],
    seal_fd: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    expected_children: dict[str, dict[str, tuple[str, int]]] = {
        relative: {} for relative in directories
    }
    for relative, capture in directories.items():
        if deadline_check is not None:
            deadline_check()
        if relative != ".":
            expected_children[capture["parent"]][capture["name"]] = ("directory", capture["fd"])
    for capture in files.values():
        if deadline_check is not None:
            deadline_check()
        expected_children[capture["parent"]][capture["name"]] = ("file", capture["fd"])
    expected_children["."][SEAL_NAME] = ("seal", seal_fd)

    for relative, capture in directories.items():
        if deadline_check is not None:
            deadline_check()
        directory_fd = capture["fd"]
        actual_names: set[str] = set()
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                if deadline_check is not None:
                    deadline_check()
                actual_names.add(entry.name)
        expected_names = set(expected_children[relative])
        if actual_names != expected_names:
            raise ValueError("sealed run file or directory set changed during capture")
        for name, (kind, child_fd) in expected_children[relative].items():
            if deadline_check is not None:
                deadline_check()
            entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            child_stat = os.fstat(child_fd)
            if not os.path.samestat(entry_stat, child_stat):
                raise ValueError(f"sealed run {kind} identity changed during capture: {name}")
            if kind == "directory" and not stat.S_ISDIR(entry_stat.st_mode):
                raise ValueError(f"sealed run path is not a directory: {name}")
            if kind in {"file", "seal"} and not stat.S_ISREG(entry_stat.st_mode):
                raise ValueError(f"sealed run path is not a regular file: {name}")


def _close_posix_tree(
    directories: Mapping[str, dict[str, Any]],
    files: Mapping[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for relative, capture in files.items():
        fd = capture.get("fd")
        if fd is not None:
            try:
                os.close(fd)
            except OSError as exc:
                errors.append(f"close artifact {relative}: {exc}")
            capture["fd"] = None
    for relative in sorted(directories, key=_relative_depth, reverse=True):
        fd = directories[relative].get("fd")
        if fd is not None:
            try:
                os.close(fd)
            except OSError as exc:
                errors.append(f"close directory {relative}: {exc}")
            directories[relative]["fd"] = None
    return errors


def _build_run_seal_posix(
    run_dir: Path,
    *,
    canonical_path_root: Path,
    run_dir_fd: int | None = None,
) -> dict[str, Any]:
    """Seal an exclusively owned, disposable staging tree.

    The returned seal proves captured bytes and topology at the atomic adoption
    boundary. Callers must not expose writable descriptors or permit
    non-cooperating writers during build, seal, verification, and rename;
    chmod cannot revoke a writable descriptor opened before sealing.
    """
    _require_posix_seal_capabilities()
    write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    root_fd: int | None = None
    seal_fd: int | None = None
    seal_handle = None
    directories: dict[str, dict[str, Any]] = {}
    files: dict[str, dict[str, Any]] = {}
    try:
        if run_dir_fd is None:
            expected_root = _normalized_physical_path(run_dir.resolve(strict=True))
            root_fd = _open_posix_directory_non_following(run_dir)
            root_canonical = _canonical_path_from_fd(root_fd)
            if root_canonical != expected_root:
                raise ValueError("sealed run root changed while opening")
        else:
            root_fd = os.dup(run_dir_fd)
            root_canonical = _canonical_path_from_fd(root_fd)
        seal_fd = os.open(
            SEAL_NAME,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_fd,
        )
        seal_handle = os.fdopen(seal_fd, "w+b", closefd=True)
        seal_fd = None
        directories, files = _scan_posix_tree(root_fd)
        root_fd = None

        for relative, capture in sorted(files.items()):
            before = os.fstat(capture["fd"])
            capture["original_mode"] = stat.S_IMODE(before.st_mode)
            os.fchmod(capture["fd"], capture["original_mode"] & ~write_bits)
            evidence = _read_evidence_from_fd(capture["fd"], run_dir / Path(relative))
            expected_canonical = _normalized_physical_path(Path(root_canonical) / Path(relative))
            if evidence.canonical_path != expected_canonical:
                raise ValueError(f"sealed run canonical path changed during capture: {relative}")
            if stat.S_IMODE(os.fstat(capture["fd"]).st_mode) & write_bits:
                raise ValueError(f"sealed run artifact remains writable: {relative}")
            capture["evidence"] = evidence

        for relative in sorted(directories, key=_relative_depth, reverse=True):
            capture = directories[relative]
            before = os.fstat(capture["fd"])
            capture["original_mode"] = stat.S_IMODE(before.st_mode)
            os.fchmod(capture["fd"], capture["original_mode"] & ~write_bits)
            after = os.fstat(capture["fd"])
            if not os.path.samestat(before, after):
                raise ValueError(f"sealed run directory identity changed during freeze: {relative}")
            if stat.S_IMODE(after.st_mode) & write_bits:
                raise ValueError(f"sealed run directory remains writable: {relative}")

        _validate_posix_tree(directories, files, seal_handle.fileno())
        file_records: dict[str, dict[str, Any]] = {}
        for relative, capture in sorted(files.items()):
            initial = capture["evidence"]
            final = _read_evidence_from_fd(capture["fd"], run_dir / Path(relative))
            if (
                final.sha256 != initial.sha256
                or len(final.data) != len(initial.data)
                or final.file_identity != initial.file_identity
                or final.canonical_path != initial.canonical_path
            ):
                raise ValueError(f"sealed run content changed during freeze: {relative}")
            sealed_canonical_path = _normalized_physical_path(canonical_path_root / Path(relative))
            file_records[relative] = {
                "sha256": final.sha256,
                "size": len(final.data),
                "file_identity": list(final.file_identity),
                "canonical_path": sealed_canonical_path,
                "canonical_parent_path": _canonical_parent_path(sealed_canonical_path),
            }

        directory_records = {
            relative: {
                "file_identity": list(_directory_identity(os.fstat(capture["fd"]))),
                "mode": stat.S_IMODE(os.fstat(capture["fd"]).st_mode),
            }
            for relative, capture in sorted(directories.items())
        }
        seal: dict[str, Any] = {
            "version": SEAL_VERSION,
            "directories": directory_records,
            "files": file_records,
        }
        payload = (json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        seal_handle.write(payload)
        seal_handle.truncate()
        seal_handle.flush()
        os.fsync(seal_handle.fileno())
        os.fchmod(seal_handle.fileno(), stat.S_IREAD)
        seal_evidence = _read_evidence_from_fd(seal_handle.fileno(), run_dir / SEAL_NAME)
        if seal_evidence.data != payload:
            raise RuntimeError("run seal read-back mismatch")
        _validate_posix_tree(directories, files, seal_handle.fileno())
        for relative, capture in files.items():
            final = _read_evidence_from_fd(capture["fd"], run_dir / Path(relative))
            record = file_records[relative]
            if final.sha256 != record["sha256"] or list(final.file_identity) != record["file_identity"]:
                raise ValueError(f"sealed run content changed after seal write: {relative}")

        seal_handle.close()
        seal_handle = None
        close_errors = _close_posix_tree(directories, files)
        if close_errors:
            raise RuntimeError("run seal handle cleanup failed: " + "; ".join(close_errors))
        return seal
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if seal_handle is not None:
            try:
                seal_handle.close()
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run seal: {cleanup_exc}")
        elif seal_fd is not None:
            try:
                os.close(seal_fd)
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run seal: {cleanup_exc}")
        for relative, capture in files.items():
            if capture.get("fd") is not None and capture.get("original_mode") is not None:
                try:
                    os.fchmod(capture["fd"], capture["original_mode"])
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"restore artifact {relative}: {cleanup_exc}")
        for relative in sorted(directories, key=_relative_depth):
            capture = directories[relative]
            if capture.get("fd") is not None and capture.get("original_mode") is not None:
                try:
                    os.fchmod(capture["fd"], capture["original_mode"])
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"restore directory {relative}: {cleanup_exc}")
        cleanup_errors.extend(_close_posix_tree(directories, files))
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run root: {cleanup_exc}")
        if cleanup_errors:
            raise RuntimeError("run seal cleanup failed: " + "; ".join(cleanup_errors)) from exc
        raise


def _build_run_seal_windows_test_only(
    run_dir: str | Path,
    *,
    canonical_path_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build a seal in a disposable staging directory.

    Files remain bound to open descriptors while they are made read-only and
    checked. On failure, the reserved seal is intentionally left in place:
    deleting a pathname after a race-sensitive ownership check could remove
    another process's file. The atomic staging caller discards the complete
    directory.
    """
    run_dir = Path(run_dir)
    canonical_root = Path(canonical_path_root) if canonical_path_root is not None else run_dir
    seal_path = run_dir / SEAL_NAME
    write_bits = stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    artifact_captures: list[dict[str, Any]] = []
    directory_captures: list[dict[str, Any]] = []
    seal_handle = None
    try:
        try:
            seal_handle = seal_path.open("x+b")
        except FileExistsError as exc:
            raise FileExistsError(f"run seal already exists: {seal_path}") from exc

        initial_paths = _file_paths(run_dir)
        for relative, path in sorted(initial_paths.items()):
            opened = _open_non_following(path)
            if isinstance(opened, tuple):
                fd, parent_handles = opened
            else:  # Backwards-compatible seam for tests and older internal callers.
                fd, parent_handles = opened, []
            capture: dict[str, Any] = {
                "relative": relative,
                "path": path,
                "fd": fd,
                "parent_handles": parent_handles,
                "original_mode": None,
                "evidence": None,
            }
            artifact_captures.append(capture)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError(f"sealed run path is not a regular file: {relative}")
            if getattr(before, "st_nlink", 1) > 1:
                raise ValueError(f"sealed run path is a hard-link entry: {relative}")
            capture["original_mode"] = stat.S_IMODE(before.st_mode)
            _set_readonly_fd(path, fd)
            evidence = read_evidence(path)
            after = os.fstat(fd)
            current_path_stat = path.stat()
            if not os.path.samestat(before, after) or not os.path.samestat(after, current_path_stat):
                raise ValueError(f"sealed run inode changed during capture: {relative}")
            if evidence.file_identity != _file_identity(after):
                raise ValueError(f"sealed run identity changed during capture: {relative}")
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                raise ValueError(f"sealed run content changed during capture: {relative}")
            if stat.S_IMODE(after.st_mode) & write_bits:
                raise ValueError(f"sealed run artifact remains writable: {relative}")
            expected_staging_path = _normalized_physical_path(run_dir / Path(relative))
            if evidence.canonical_path != expected_staging_path:
                raise ValueError(f"sealed run canonical path changed during capture: {relative}")
            capture["evidence"] = evidence

        directory_paths = _seal_directory_paths(run_dir)
        directory_identities: dict[Path, tuple[int, int, int, int, int, int]] = {}
        for directory in directory_paths:
            directory_stat = directory.stat(follow_symlinks=False)
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise ValueError(f"sealed run path is not a directory: {directory}")
            directory_identities[directory] = _file_identity(directory_stat)

        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
            directory_fds: dict[Path, int] = {}
            for directory in directory_paths:
                if directory == run_dir:
                    directory_fd = _open_posix_directory_non_following(directory)
                else:
                    parent_fd = directory_fds.get(directory.parent)
                    if parent_fd is None:
                        raise ValueError(f"sealed run directory parent is not open: {directory}")
                    directory_fd = os.open(directory.name, directory_flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
                directory_fds[directory] = directory_fd
                directory_capture: dict[str, Any] = {
                    "path": directory,
                    "fd": directory_fd,
                    "original_mode": None,
                }
                directory_captures.append(directory_capture)
                directory_before = os.fstat(directory_fd)
                if not stat.S_ISDIR(directory_before.st_mode):
                    raise ValueError(f"sealed run path is not a directory: {directory}")
                if _file_identity(directory_before) != directory_identities[directory]:
                    raise ValueError(
                        f"sealed run directory identity changed before freeze: {directory}"
                    )
                directory_capture["original_mode"] = stat.S_IMODE(directory_before.st_mode)
                _freeze_posix_directory(
                    directory_fd,
                    expected_identity=directory_identities[directory],
                    path=directory,
                    write_bits=write_bits,
                )
        else:
            for directory in directory_paths:
                directory_stat = directory.stat()
                directory_captures.append(
                    {
                        "path": directory,
                        "fd": None,
                        "original_mode": stat.S_IMODE(directory_stat.st_mode),
                        "initial_identity": _file_identity(directory_stat),
                    }
                )

        current_paths = _file_paths(run_dir)
        expected_paths = {capture["relative"] for capture in artifact_captures}
        if set(current_paths) != expected_paths:
            raise ValueError("sealed run file set changed during capture")

        current_directories = _seal_directory_paths(run_dir)
        expected_directories = {
            _relative_directory_name(run_dir, directory) for directory in current_directories
        }
        captured_directories = {
            _relative_directory_name(run_dir, capture["path"])
            for capture in directory_captures
        }
        if captured_directories != expected_directories:
            raise ValueError("sealed run directory set changed during capture")

        for directory_capture in directory_captures:
            directory_fd = directory_capture["fd"]
            directory_fd_stat = (
                os.fstat(directory_fd) if directory_fd is not None else directory_capture["path"].stat()
            )
            directory_path_stat = directory_capture["path"].stat()
            if not os.path.samestat(directory_fd_stat, directory_path_stat):
                raise ValueError(
                    f"sealed run directory identity changed during capture: {directory_capture['path']}"
                )
            if directory_fd is not None and stat.S_IMODE(directory_fd_stat.st_mode) & write_bits:
                raise ValueError(
                    f"sealed run directory remains writable: {directory_capture['path']}"
                )
            if (
                directory_fd is None
                and directory_capture["initial_identity"] != _file_identity(directory_path_stat)
            ):
                raise ValueError(
                    f"sealed run directory identity changed during capture: {directory_capture['path']}"
                )

        files: dict[str, dict[str, Any]] = {}
        for capture in artifact_captures:
            fd_stat = os.fstat(capture["fd"])
            path_stat = capture["path"].stat()
            evidence = capture["evidence"]
            if not os.path.samestat(fd_stat, path_stat):
                raise ValueError(f"sealed run inode changed during freeze: {capture['relative']}")
            if evidence.file_identity != _file_identity(fd_stat):
                raise ValueError(f"sealed run identity changed during freeze: {capture['relative']}")
            if stat.S_IMODE(fd_stat.st_mode) & write_bits:
                raise ValueError(f"sealed run artifact became writable: {capture['relative']}")
            final_evidence = read_evidence(capture["path"])
            if (
                final_evidence.sha256 != evidence.sha256
                or len(final_evidence.data) != len(evidence.data)
                or final_evidence.file_identity != evidence.file_identity
                or final_evidence.canonical_path != evidence.canonical_path
            ):
                raise ValueError(f"sealed run content changed during freeze: {capture['relative']}")
            evidence = final_evidence
            capture["evidence"] = evidence
            sealed_canonical_path = _normalized_physical_path(canonical_root / Path(capture["relative"]))
            files[capture["relative"]] = {
                "sha256": evidence.sha256,
                "size": len(evidence.data),
                "file_identity": list(evidence.file_identity),
                "canonical_path": sealed_canonical_path,
                "canonical_parent_path": _canonical_parent_path(sealed_canonical_path),
            }

        directories: dict[str, dict[str, Any]] = {}
        for directory_capture in directory_captures:
            directory_fd = directory_capture["fd"]
            directory_stat = (
                os.fstat(directory_fd) if directory_fd is not None else directory_capture["path"].stat()
            )
            directory_name = _relative_directory_name(run_dir, directory_capture["path"])
            directories[directory_name] = {
                "file_identity": list(_directory_identity(directory_stat)),
                "mode": stat.S_IMODE(directory_stat.st_mode),
            }

        seal: dict[str, Any] = {
            "version": SEAL_VERSION,
            "directories": directories,
            "files": files,
        }
        payload = (json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        seal_handle.seek(0)
        seal_handle.write(payload)
        seal_handle.truncate()
        seal_handle.flush()
        os.fsync(seal_handle.fileno())
        if os.name != "nt":
            os.fchmod(seal_handle.fileno(), stat.S_IREAD)
        else:
            _set_readonly(seal_path)
        seal_handle.close()
        seal_handle = None
        if read_evidence(seal_path).data != payload:
            raise RuntimeError("run seal read-back mismatch")

        close_errors: list[str] = []
        for capture in artifact_captures:
            try:
                os.close(capture["fd"])
            except OSError as close_exc:
                close_errors.append(f"close artifact {capture['relative']}: {close_exc}")
            capture["fd"] = None
            _close_parent_handles(capture["parent_handles"])
            capture["parent_handles"] = []
        for directory_capture in directory_captures:
            directory_fd = directory_capture["fd"]
            if directory_fd is not None:
                try:
                    os.close(directory_fd)
                except OSError as close_exc:
                    close_errors.append(f"close directory {directory_capture['path']}: {close_exc}")
                directory_capture["fd"] = None
        if close_errors:
            raise RuntimeError("run seal handle cleanup failed: " + "; ".join(close_errors))
        return seal
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if seal_handle is not None:
            try:
                seal_handle.close()
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run seal: {cleanup_exc}")
        for capture in reversed(artifact_captures):
            fd = capture["fd"]
            original_mode = capture["original_mode"]
            if fd is not None and original_mode is not None:
                try:
                    if os.name != "nt":
                        os.fchmod(fd, original_mode)
                    else:
                        current_path_stat = capture["path"].stat()
                        if os.path.samestat(os.fstat(fd), current_path_stat):
                            os.chmod(capture["path"], original_mode)
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"restore artifact {capture['relative']}: {cleanup_exc}")
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"close artifact {capture['relative']}: {cleanup_exc}")
                capture["fd"] = None
            _close_parent_handles(capture["parent_handles"])
            capture["parent_handles"] = []
        for directory_capture in reversed(directory_captures):
            fd = directory_capture["fd"]
            original_mode = directory_capture["original_mode"]
            if fd is not None and original_mode is not None:
                try:
                    os.fchmod(fd, original_mode)
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"restore directory {directory_capture['path']}: {cleanup_exc}")
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as cleanup_exc:
                    cleanup_errors.append(f"close directory {directory_capture['path']}: {cleanup_exc}")
                directory_capture["fd"] = None
        if cleanup_errors:
            raise RuntimeError("run seal cleanup failed: " + "; ".join(cleanup_errors)) from exc
        raise


def build_run_seal(
    run_dir: str | Path,
    *,
    canonical_path_root: str | Path | None = None,
    run_dir_fd: int | None = None,
) -> dict[str, Any]:
    """Seal an owner-controlled staging tree before atomic adoption.

    Direct callers own cleanup of the complete staging directory on failure.
    This API cannot make an untrusted shared directory transactional or revoke
    writable descriptors already held by another process.
    """
    run_path = Path(run_dir)
    canonical_root = Path(canonical_path_root) if canonical_path_root is not None else run_path
    if os.name == "nt":
        if not _WINDOWS_TEST_SEAL_BUILDER_ENABLED:
            raise RuntimeError("sealed run publication requires POSIX directory freeze")
        return _build_run_seal_windows_test_only(
            run_path,
            canonical_path_root=canonical_root,
        )
    return _build_run_seal_posix(
        run_path,
        canonical_path_root=canonical_root,
        run_dir_fd=run_dir_fd,
    )


def _decode_run_seal(seal_evidence: Evidence) -> dict[str, Any]:
    if len(seal_evidence.data) > _MAX_SEAL_BYTES:
        raise ValueError("run seal exceeds size limit")
    try:
        seal = json.loads(seal_evidence.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid run seal") from exc
    if (
        not isinstance(seal, dict)
        or seal.get("version") != SEAL_VERSION
        or not isinstance(seal.get("directories"), dict)
        or not isinstance(seal.get("files"), dict)
    ):
        raise ValueError("invalid run seal structure")
    return seal


def _validate_directory_record(relative: str, record: Any, directory_stat: os.stat_result) -> None:
    if not isinstance(record, dict):
        raise TypeError(f"sealed run directory record is invalid: {relative}")
    expected_identity = record.get("file_identity")
    if (
        not isinstance(expected_identity, list)
        or len(expected_identity) != len(_directory_identity(directory_stat))
        or tuple(expected_identity) != _directory_identity(directory_stat)
    ):
        raise ValueError(f"sealed run directory identity mismatch: {relative}")
    expected_mode = record.get("mode")
    if not isinstance(expected_mode, int) or isinstance(expected_mode, bool):
        raise TypeError(f"sealed run directory mode is invalid: {relative}")
    if stat.S_IMODE(directory_stat.st_mode) != expected_mode:
        raise ValueError(f"sealed run directory mode mismatch: {relative}")


def _validate_file_record(relative: str, record: Any, evidence: Evidence) -> None:
    if not isinstance(record, dict):
        raise TypeError(f"sealed run record is invalid: {relative}")
    if evidence.sha256 != record.get("sha256"):
        raise ValueError(f"sealed run hash mismatch: {relative}")
    evidence_size = evidence.size if evidence.size is not None else len(evidence.data)
    if evidence_size != record.get("size"):
        raise ValueError(f"sealed run size mismatch: {relative}")
    expected_identity = record.get("file_identity")
    if (
        not isinstance(expected_identity, list)
        or len(expected_identity) != len(evidence.file_identity)
        or tuple(expected_identity) != evidence.file_identity
    ):
        raise ValueError(f"sealed run identity mismatch: {relative}")
    if record.get("canonical_path") != evidence.canonical_path:
        raise ValueError(f"sealed run canonical path mismatch: {relative}")
    if record.get("canonical_parent_path") != _canonical_parent_path(evidence.canonical_path):
        raise ValueError(f"sealed run parent path mismatch: {relative}")


def _load_sealed_run_posix(
    run_dir: Path,
    *,
    read_content: bool,
    deadline_check: Callable[[], None] | None = None,
    content_filter: Callable[[str], bool] | None = None,
) -> SealedRunEvidence:
    _require_posix_seal_capabilities()
    if deadline_check is not None:
        deadline_check()
    root_fd: int | None = None
    seal_fd: int | None = None
    directories: dict[str, dict[str, Any]] = {}
    files: dict[str, dict[str, Any]] = {}
    try:
        expected_root = _normalized_physical_path(run_dir.resolve(strict=True))
        if deadline_check is not None:
            deadline_check()
        root_fd = _open_posix_directory_non_following(run_dir)
        if _canonical_path_from_fd(root_fd) != expected_root:
            raise ValueError("sealed run root changed while opening")
        seal_fd = os.open(
            SEAL_NAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        seal_evidence = _read_evidence_from_fd(
            seal_fd,
            run_dir / SEAL_NAME,
            deadline_check=deadline_check,
            max_content_bytes=_MAX_SEAL_BYTES,
        )
        directories, files = _scan_posix_tree(root_fd, deadline_check=deadline_check)
        root_fd = None
        _validate_posix_tree(directories, files, seal_fd, deadline_check=deadline_check)
        seal = _decode_run_seal(seal_evidence)

        expected_directories = set(seal["directories"])
        if set(directories) != expected_directories:
            raise ValueError("sealed run directory set mismatch")
        for relative in sorted(expected_directories):
            if deadline_check is not None:
                deadline_check()
            _validate_directory_record(
                relative,
                seal["directories"][relative],
                os.fstat(directories[relative]["fd"]),
            )

        expected_files = set(seal["files"])
        if set(files) != expected_files:
            raise ValueError("sealed run file set mismatch")
        captured_files: dict[str, Evidence] = {}
        for relative in sorted(expected_files):
            if deadline_check is not None:
                deadline_check()
            evidence = _read_evidence_from_fd(
                files[relative]["fd"],
                run_dir / Path(relative),
                read_content=content_filter(relative) if content_filter is not None else read_content,
                deadline_check=deadline_check,
            )
            _validate_file_record(relative, seal["files"][relative], evidence)
            captured_files[relative] = evidence

        _validate_posix_tree(directories, files, seal_fd, deadline_check=deadline_check)
        final_seal = _read_evidence_from_fd(
            seal_fd,
            run_dir / SEAL_NAME,
            deadline_check=deadline_check,
            max_content_bytes=_MAX_SEAL_BYTES,
        )
        if final_seal != seal_evidence:
            raise ValueError("sealed run seal changed during verification")
        for relative, evidence in captured_files.items():
            if deadline_check is not None:
                deadline_check()
            final = _read_evidence_from_fd(
                files[relative]["fd"],
                run_dir / Path(relative),
                read_content=content_filter(relative) if content_filter is not None else read_content,
                deadline_check=deadline_check,
            )
            if final != evidence:
                raise ValueError(f"sealed run file changed during verification: {relative}")

        os.close(seal_fd)
        seal_fd = None
        close_errors = _close_posix_tree(directories, files)
        if close_errors:
            raise RuntimeError("run seal verification cleanup failed: " + "; ".join(close_errors))
        return SealedRunEvidence(seal=seal, seal_evidence=seal_evidence, files=captured_files)
    except BaseException as exc:
        cleanup_errors: list[str] = []
        if seal_fd is not None:
            try:
                os.close(seal_fd)
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run seal: {cleanup_exc}")
        cleanup_errors.extend(_close_posix_tree(directories, files))
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError as cleanup_exc:
                cleanup_errors.append(f"close run root: {cleanup_exc}")
        if cleanup_errors:
            message = "run seal verification cleanup failed: " + "; ".join(cleanup_errors)
            if isinstance(exc, IntegrityDeadlineExceeded):
                exc.add_note(message)
                raise
            raise RuntimeError(message) from exc
        raise


def _load_sealed_run_windows_test_only(
    run_dir: str | Path,
    *,
    read_content: bool,
) -> SealedRunEvidence:
    run_dir = Path(run_dir)
    seal_evidence = read_evidence(run_dir / SEAL_NAME)
    try:
        seal = json.loads(seal_evidence.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid run seal") from exc
    if (
        not isinstance(seal, dict)
        or seal.get("version") != SEAL_VERSION
        or not isinstance(seal.get("directories"), dict)
        or not isinstance(seal.get("files"), dict)
    ):
        raise ValueError("invalid run seal structure")
    expected_directories = set(seal["directories"])
    directory_paths = {
        _relative_directory_name(run_dir, directory) for directory in _seal_directory_paths(run_dir)
    }
    if directory_paths != expected_directories:
        raise ValueError("sealed run directory set mismatch")
    for relative in sorted(expected_directories):
        directory = run_dir if relative == "." else run_dir / Path(relative)
        record = seal["directories"][relative]
        if not isinstance(record, dict):
            raise TypeError(f"sealed run directory record is invalid: {relative}")
        directory_stat = directory.stat()
        expected_identity = record.get("file_identity")
        if (
            not isinstance(expected_identity, list)
            or len(expected_identity) != len(_directory_identity(directory_stat))
            or tuple(expected_identity) != _directory_identity(directory_stat)
        ):
            raise ValueError(f"sealed run directory identity mismatch: {relative}")
        expected_mode = record.get("mode")
        if not isinstance(expected_mode, int) or isinstance(expected_mode, bool):
            raise TypeError(f"sealed run directory mode is invalid: {relative}")
        if stat.S_IMODE(directory_stat.st_mode) != expected_mode:
            raise ValueError(f"sealed run directory mode mismatch: {relative}")

    expected = set(seal["files"])
    paths_before = _file_paths(run_dir)
    if set(paths_before) != expected:
        raise ValueError("sealed run file set mismatch")
    files: dict[str, Evidence] = {}
    for relative in sorted(expected):
        evidence = (
            read_evidence(paths_before[relative])
            if read_content
            else read_evidence(paths_before[relative], read_content=False)
        )
        files[relative] = evidence
        record = seal["files"][relative]
        if not isinstance(record, dict):
            raise TypeError(f"sealed run record is invalid: {relative}")
        if evidence.sha256 != record.get("sha256"):
            raise ValueError(f"sealed run hash mismatch: {relative}")
        evidence_size = evidence.size if evidence.size is not None else len(evidence.data)
        if evidence_size != record.get("size"):
            raise ValueError(f"sealed run size mismatch: {relative}")
        expected_identity = record.get("file_identity")
        if (
            not isinstance(expected_identity, list)
            or len(expected_identity) != len(evidence.file_identity)
            or tuple(expected_identity) != evidence.file_identity
        ):
            raise ValueError(f"sealed run identity mismatch: {relative}")
        if record.get("canonical_path") != evidence.canonical_path:
            raise ValueError(f"sealed run canonical path mismatch: {relative}")
        if record.get("canonical_parent_path") != _canonical_parent_path(evidence.canonical_path):
            raise ValueError(f"sealed run parent path mismatch: {relative}")
    if set(_file_paths(run_dir)) != expected:
        raise ValueError("sealed run file set changed during verification")
    _assert_evidence_unchanged(run_dir / SEAL_NAME, seal_evidence, SEAL_NAME)
    for relative in sorted(expected):
        _assert_evidence_unchanged(paths_before[relative], files[relative], relative)
    return SealedRunEvidence(seal=seal, seal_evidence=seal_evidence, files=files)


def load_sealed_run(
    run_dir: str | Path,
    *,
    read_content: bool = True,
    deadline_check: Callable[[], None] | None = None,
    content_filter: Callable[[str], bool] | None = None,
) -> SealedRunEvidence:
    run_path = Path(run_dir)
    if os.name == "nt":
        if not _WINDOWS_TEST_SEAL_BUILDER_ENABLED:
            raise RuntimeError("sealed run verification requires POSIX descriptor primitives")
        return _load_sealed_run_windows_test_only(run_path, read_content=read_content)
    return _load_sealed_run_posix(
        run_path,
        read_content=read_content,
        deadline_check=deadline_check,
        content_filter=content_filter,
    )


def verify_run_seal(run_dir: str | Path) -> dict[str, Any]:
    return load_sealed_run(run_dir).seal
