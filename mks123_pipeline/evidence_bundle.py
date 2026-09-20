from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, nullcontext
from pathlib import Path

APPROVED_EVIDENCE_ROOT = Path(r"D:/ServerBackups/mks123webserver")
_MAX_MARKER_BYTES = 1_000_000
_MAX_JSON_BYTES = 25_000_000
_MAX_BUNDLE_BYTES = 50_000_000
_MAX_BUNDLE_FILES = 128
_MAX_BUNDLE_ID_LENGTH = 200
_MAX_JSON_NODES = 500_000
_WINDOWS_RESERVED_NAMES = {"con", "prn", "aux", "nul", *(f"com{number}" for number in range(1, 10)), *(f"lpt{number}" for number in range(1, 10))}
_WINDOWS_SUPERSCRIPTS = str.maketrans({"¹": "1", "²": "2", "³": "3"})
_WINDOWS_FORBIDDEN_CHARS = set('<>"|?*')
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


def _safe_filename(name: object) -> bool:
    if not isinstance(name, str) or not name or name in {".", ".."} or Path(name).name != name:
        return False
    if any(char in name for char in "\\/:\x00") or any(ord(char) < 32 for char in name) or any(char in _WINDOWS_FORBIDDEN_CHARS for char in name):
        return False
    if name.rstrip(" .") != name:
        return False
    stem = name.split(".", 1)[0].casefold().translate(_WINDOWS_SUPERSCRIPTS)
    return stem not in _WINDOWS_RESERVED_NAMES


def _filename_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _has_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    except (AttributeError, OSError):
        return False
    return attributes != 0xFFFFFFFF and bool(attributes & 0x400)


def _trusted_local_root(path: Path) -> bool:
    if os.name != "nt":
        return True
    absolute = os.path.abspath(path)
    if absolute.startswith("\\\\"):
        return False
    drive, _tail = os.path.splitdrive(absolute)
    if not drive:
        return False
    try:
        import ctypes

        return ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") == 3
    except (AttributeError, OSError):
        return False


def _plain_directory(path: Path) -> bool:
    if _has_reparse_point(path):
        return False
    try:
        path_stat = os.lstat(path)
    except (FileNotFoundError, OSError):
        return False
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISDIR(path_stat.st_mode) or os.path.realpath(path) != os.path.abspath(path):
        return False
    junction_check = getattr(os.path, "isjunction", None)
    return not callable(junction_check) or not junction_check(path)


def _within_root(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((os.path.realpath(path), os.path.realpath(root))) == os.path.realpath(root)
    except ValueError:
        return False


def _same_directory(path: Path, expected: os.stat_result) -> bool:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return os.path.samestat(current, expected) and _plain_directory(path)


def path_is_within(path: str | Path, root: str | Path) -> bool:
    return _within_root(Path(path), Path(root))


def paths_overlap(first: str | Path, second: str | Path) -> bool:
    first_path = Path(first)
    second_path = Path(second)
    return path_is_within(first_path, second_path) or path_is_within(second_path, first_path)


class BundleError(RuntimeError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _write_exclusive(path: Path, data: bytes, *, readonly: bool = False) -> None:
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        handle = kernel32.CreateFileW(str(path), 0xC0000000, 0, None, 1, 0x80, None)
        invalid_handle = ctypes.c_void_p(-1).value
        if handle == invalid_handle:
            error = ctypes.get_last_error()
            if error in {80, 183}:
                raise FileExistsError(errno.EEXIST, "bundle path already exists", str(path))
            raise OSError(error, "CreateFileW failed", str(path))
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except OSError:
            kernel32.CloseHandle(handle)
            raise
        try:
            with os.fdopen(fd, "w+b") as stream:
                fd = -1
                written = stream.write(data)
                if written != len(data):
                    raise OSError("short write while creating evidence bundle")
                stream.flush()
                os.fsync(stream.fileno())
                stream.seek(0)
                actual = stream.read(len(data))
                if actual != data:
                    raise OSError("same-handle read-back mismatch while creating evidence bundle")
                if readonly:
                    os.chmod(path, 0o444)
        finally:
            if fd >= 0:
                os.close(fd)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            written = stream.write(data)
            if written != len(data):
                raise OSError("short write while creating evidence bundle")
            stream.flush()
            os.fsync(stream.fileno())
            if readonly:
                fchmod = getattr(os, "fchmod", None)
                if callable(fchmod):
                    fchmod(stream.fileno(), 0o444)
                else:
                    os.chmod(path, 0o444)
    finally:
        if fd >= 0:
            os.close(fd)


@contextmanager
def _directory_guard(path: Path) -> Iterator[None]:
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise BundleError(f"cannot hold bundle directory guard: {path}") from exc
        try:
            yield
        finally:
            os.close(fd)
        return
    if _has_reparse_point(path):
        raise BundleError(f"bundle directory is a reparse point: {path}")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80 | 0x200000 | 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise BundleError(f"cannot hold bundle directory guard: {path}")
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    try:
        yield
    finally:
        os.close(fd)


def _open_read_fd(path: Path) -> int:
    if os.name != "nt":
        return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    handle = kernel32.CreateFileW(
        str(path),
        0x80000000,
        0,
        None,
        3,
        0x80 | 0x200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise BundleError(f"cannot open bundle file with exclusive share denial: {path}")
    info = _FileAttributeTagInfo()
    if not kernel32.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info), ctypes.sizeof(info)) or info.FileAttributes & 0x400:
        kernel32.CloseHandle(handle)
        raise BundleError(f"bundle file is a reparse point: {path}")
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel32.CloseHandle(handle)
        raise


def _read_regular_file(path: Path, *, max_bytes: int, require_readonly: bool = False) -> tuple[bytes, os.stat_result]:
    try:
        fd = _open_read_fd(path)
    except OSError as exc:
        raise BundleError(f"cannot open bundle file: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise BundleError(f"bundle file is not a single regular file: {path}")
        if require_readonly and before.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise BundleError(f"bundle file is writable: {path}")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise BundleError(f"bundle file exceeds bounded size: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise BundleError(f"bundle file ended before declared size: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if not os.path.samestat(before, after) or after.st_size != before.st_size:
            raise BundleError(f"bundle file changed during read: {path}")
        return b"".join(chunks), before
    finally:
        os.close(fd)


def _strict_json_loads(raw: bytes, path: Path) -> object:
    if len(raw) > _MAX_JSON_BYTES:
        raise BundleError(f"JSON exceeds bounded size: {path}")

    def duplicate_free(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise BundleError(f"non-standard JSON constant in {path}: {value}")

    try:
        value = json.loads(raw, object_pairs_hook=duplicate_free, parse_constant=reject_constant)
    except BundleError:
        raise
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError, MemoryError) as exc:
        raise BundleError(f"invalid JSON: {path}") from exc
    _validate_json_value(value, path)
    return value


def _validate_json_value(value: object, path: Path, *, depth: int = 0, seen: int = 0) -> int:
    if depth > 100:
        raise BundleError(f"JSON nesting exceeds bound: {path}")
    if seen >= _MAX_JSON_NODES:
        raise BundleError(f"JSON node count exceeds bound: {path}")
    seen += 1
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BundleError(f"JSON contains invalid Unicode: {path}") from exc
    elif isinstance(value, dict):
        for key, child in value.items():
            seen = _validate_json_value(key, path, depth=depth + 1, seen=seen)
            seen = _validate_json_value(child, path, depth=depth + 1, seen=seen)
    elif isinstance(value, list):
        for child in value:
            seen = _validate_json_value(child, path, depth=depth + 1, seen=seen)
    elif isinstance(value, float) and not math.isfinite(value):
        raise BundleError(f"non-finite JSON number in {path}")
    return seen


def _bounded_directory_names(root: Path) -> set[str]:
    names: list[str] = []
    try:
        for index, entry in enumerate(root.iterdir()):
            if index >= _MAX_BUNDLE_FILES + 1:
                raise BundleError(f"bundle contains too many files: {root}")
            names.append(entry.name)
    except OSError as exc:
        raise BundleError(f"cannot enumerate bundle: {root}") from exc
    return set(names)


def _read_marker(root: Path) -> tuple[dict, os.stat_result, set[str]]:
    if not _trusted_local_root(root):
        raise BundleError(f"bundle root is on an unsupported remote/UNC volume: {root}")
    try:
        root_stat = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        raise BundleError(f"cannot stat bundle root: {root}") from exc
    if not _plain_directory(root) or stat.S_ISLNK(root_stat.st_mode):
        raise BundleError(f"bundle root is not a regular directory: {root}")
    marker_path = root / "COMMITTED"
    marker_bytes, _marker_stat = _read_regular_file(marker_path, max_bytes=_MAX_MARKER_BYTES, require_readonly=True)
    marker = _strict_json_loads(marker_bytes, marker_path)
    if not isinstance(marker, dict) or not isinstance(marker.get("bundle"), str) or len(marker["bundle"]) > _MAX_BUNDLE_ID_LENGTH or not isinstance(marker.get("files"), dict) or not marker["files"] or len(marker["files"]) > _MAX_BUNDLE_FILES:
        raise BundleError(f"invalid bundle marker: {root}")
    if any(name in {"COMMITTED", ".lock"} or not _safe_filename(name) for name in marker["files"]):
        raise BundleError(f"invalid bundle file name: {root}")
    if len({_filename_key(name) for name in marker["files"]}) != len(marker["files"]):
        raise BundleError(f"case/Unicode-colliding bundle names: {root}")
    expected_names = set(marker["files"]) | {"COMMITTED"}
    if _bounded_directory_names(root) != expected_names:
        raise BundleError(f"bundle contains unexpected or missing files: {root}")
    if not _same_directory(root, root_stat):
        raise BundleError(f"bundle root changed during marker read: {root}")
    return marker, root_stat, expected_names


def _read_payloads(root: Path, marker: dict, root_stat: os.stat_result, *, hold_directory: bool = True) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    total_size = 0
    guard = _directory_guard(root) if hold_directory else nullcontext()
    with guard:
        for name, info in marker["files"].items():
            if not isinstance(info, dict) or isinstance(info.get("size"), bool) or not isinstance(info.get("size"), int) or info["size"] < 0 or info["size"] > _MAX_JSON_BYTES or not isinstance(info.get("sha256"), str) or not _SHA256_RE.fullmatch(info["sha256"]):
                raise BundleError(f"invalid bundle file record: {name!r}")
            total_size += info["size"]
            if total_size > _MAX_BUNDLE_BYTES:
                raise BundleError(f"bundle payload total exceeds bounded size: {root}")
            data, _file_stat = _read_regular_file(root / name, max_bytes=info["size"], require_readonly=True)
            if len(data) != info["size"] or _sha256(data) != info["sha256"]:
                raise BundleError(f"bundle payload hash/size mismatch: {root / name}")
            payloads[name] = data
    if not _same_directory(root, root_stat):
        raise BundleError(f"bundle root changed after payload read: {root}")
    return payloads


def read_committed_bundle(path: str | Path) -> dict:
    root = Path(path)
    marker, root_stat, _expected_names = _read_marker(root)
    _read_payloads(root, marker, root_stat)
    return marker


def read_committed_json_with_marker(path: str | Path) -> tuple[dict, dict, bytes]:
    path = Path(path)
    marker, root_stat, _expected_names = _read_marker(path.parent)
    payloads = _read_payloads(path.parent, marker, root_stat)
    raw = payloads.get(path.name)
    if raw is None:
        raise BundleError(f"committed JSON is not listed in marker: {path}")
    value = _strict_json_loads(raw, path)
    if not isinstance(value, dict):
        raise BundleError(f"{path} must contain a JSON object")
    return marker, value, raw


def read_committed_json(path: str | Path) -> tuple[dict, bytes]:
    _marker, value, raw = read_committed_json_with_marker(path)
    return value, raw


def _validate_payloads(payloads: Mapping[str, bytes]) -> dict[str, bytes]:
    if not isinstance(payloads, Mapping) or not payloads or len(payloads) > _MAX_BUNDLE_FILES:
        raise BundleError("bundle payload count is outside bounds")
    normalized: dict[str, bytes] = {}
    keys: set[str] = set()
    total_size = 0
    for name, data in payloads.items():
        if name in {"COMMITTED", ".lock"} or not _safe_filename(name):
            raise BundleError(f"payload name must be a safe non-reserved filename: {name!r}")
        key = _filename_key(name)
        if key in keys:
            raise BundleError(f"case/Unicode-colliding payload name: {name!r}")
        keys.add(key)
        if not isinstance(data, bytes) or len(data) > _MAX_JSON_BYTES:
            raise BundleError(f"payload is not bounded bytes: {name!r}")
        total_size += len(data)
        if total_size > _MAX_BUNDLE_BYTES:
            raise BundleError("bundle payload total exceeds bounded size")
        normalized[name] = data
    return normalized


def _write_bundle_contents(output: Path, root: Path, parent: Path, root_stat: os.stat_result, parent_stat: os.stat_result, payloads: dict[str, bytes], bundle_id: str) -> dict:
    with _directory_guard(output):
        output_stat = os.stat(output, follow_symlinks=False)
        _fsync_directory(parent)
        if not _same_directory(output, output_stat) or not _within_root(output, root):
            raise BundleError(f"bundle output identity changed: {output}")
        for name, data in payloads.items():
            if not _same_directory(root, root_stat) or not _same_directory(parent, parent_stat) or not _same_directory(output, output_stat) or not _within_root(output, root):
                raise BundleError(f"bundle directory identity changed before payload write: {output}")
            _write_exclusive(output / name, data, readonly=True)
        _fsync_directory(output)
        _fsync_directory(parent)
        preflight_files = {name: {"sha256": _sha256(data), "size": len(data)} for name, data in payloads.items()}
        for name, info in preflight_files.items():
            actual, _stat = _read_regular_file(output / name, max_bytes=info["size"], require_readonly=True)
            if len(actual) != info["size"] or _sha256(actual) != info["sha256"]:
                raise BundleError(f"bundle payload preflight mismatch: {output / name}")
        marker = {"bundle": bundle_id, "files": preflight_files}
        marker_bytes = json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        if len(marker_bytes) > _MAX_MARKER_BYTES:
            raise BundleError("bundle marker exceeds bounded size")
        if not _same_directory(root, root_stat) or not _same_directory(parent, parent_stat) or not _same_directory(output, output_stat):
            raise BundleError(f"bundle directory identity changed before marker write: {output}")
        _write_exclusive(output / "COMMITTED", marker_bytes, readonly=True)
        _fsync_directory(output)
        _fsync_directory(parent)
        marker_path = output / "COMMITTED"
        marker_raw, _marker_stat = _read_regular_file(marker_path, max_bytes=_MAX_MARKER_BYTES, require_readonly=True)
        readback_marker = _strict_json_loads(marker_raw, marker_path)
        if not isinstance(readback_marker, dict) or not isinstance(readback_marker.get("files"), dict):
            raise BundleError(f"bundle read-back marker is invalid: {output}")
        _read_payloads(output, readback_marker, output_stat, hold_directory=False)
        if readback_marker != marker:
            raise BundleError(f"bundle read-back mismatch: {output}")
        return marker


def _publish_bundle_unlocked(output: str | Path, payloads: Mapping[str, bytes], *, bundle_id: str, approved_root: str | Path) -> dict:
    output = Path(output)
    root = Path(approved_root)
    if not isinstance(bundle_id, str) or not bundle_id.strip() or len(bundle_id) > _MAX_BUNDLE_ID_LENGTH or any(ord(char) < 32 for char in bundle_id):
        raise BundleError("bundle_id is invalid or unbounded")
    try:
        bundle_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BundleError("bundle_id contains invalid Unicode") from exc
    payloads = _validate_payloads(payloads)
    if not _trusted_local_root(root):
        raise BundleError(f"approved root is on an unsupported remote/UNC volume: {root}")
    if not _plain_directory(root) or not _within_root(output, root):
        raise BundleError(f"output is outside approved plain root: {output}")
    parent = output.parent
    if not _plain_directory(parent) or not _safe_filename(output.name):
        raise BundleError(f"bundle parent/output must be plain safe directories: {output}")
    if os.path.lexists(output):
        raise BundleError(f"bundle already exists: {output}")
    root_stat = os.stat(root, follow_symlinks=False)
    parent_stat = os.stat(parent, follow_symlinks=False)
    if not _same_directory(root, root_stat) or not _same_directory(parent, parent_stat):
        raise BundleError("approved root/parent identity changed")

    os.mkdir(output)
    return _write_bundle_contents(output, root, parent, root_stat, parent_stat, payloads, bundle_id)


def publish_bundle(output: str | Path, payloads: Mapping[str, bytes], *, bundle_id: str, approved_root: str | Path) -> dict:
    output_path = Path(output)
    root = Path(approved_root)
    parent = output_path.parent
    if os.path.abspath(root) == os.path.abspath(parent):
        with _directory_guard(root):
            return _publish_bundle_unlocked(output_path, payloads, bundle_id=bundle_id, approved_root=root)
    with _directory_guard(root), _directory_guard(parent):
        return _publish_bundle_unlocked(output_path, payloads, bundle_id=bundle_id, approved_root=root)
