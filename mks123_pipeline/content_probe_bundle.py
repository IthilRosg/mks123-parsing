from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from . import integrity
from .integrity import build_run_seal, load_sealed_run


class BundleError(RuntimeError):
    """A read-only evidence bundle failed its integrity contract."""


MAX_FILE_BYTES = 128 * 1024 * 1024
TRUST_SCHEMA_VERSION = 2
_REQUIRED_IDENTITY_FIELDS = {
    "bundle_id", "code_identity", "source_identity", "source_seal_sha256",
    "probe_data_sha256", "probe_code_sha256", "verifier_code_sha256", "bundle_helper_sha256", "integrity_sha256",
}
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalized(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path.resolve(strict=False))))


def _inside(path: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath([_normalized(path), _normalized(parent)]) == _normalized(parent)
    except ValueError:
        return False


def _relative_file_name(name: str) -> Path:
    if not isinstance(name, str) or not name or "\\" in name:
        raise BundleError(f"invalid bundle relative path: {name!r}")
    relative = PurePosixPath(name)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise BundleError(f"invalid bundle relative path: {name!r}")
    if relative.name == "seal.json":
        raise BundleError("bundle caller cannot provide seal.json")
    return Path(*relative.parts)


def _identity_copy(identity: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(identity, Mapping) or not identity:
        raise BundleError("bundle identity is required")
    result: dict[str, str] = {}
    for key, value in identity.items():
        if not isinstance(key, str) or not key or not isinstance(value, str) or not value:
            raise BundleError("bundle identity fields must be non-empty strings")
        if len(key) > 128 or len(value) > 4096:
            raise BundleError("bundle identity field is too large")
        result[key] = value
    missing = _REQUIRED_IDENTITY_FIELDS - result.keys()
    if missing:
        raise BundleError(f"bundle identity missing fields: {sorted(missing)}")
    return result


def _validate_identity_bindings(identity: Mapping[str, str], files: Mapping[Path, bytes], *, strict: bool) -> None:
    bindings = {
        "probe_data_sha256": Path("probe-data.json"),
        "probe_code_sha256": Path("probe_content_sources10.py"),
        "verifier_code_sha256": Path("verify_content_probe10.py"),
        "bundle_helper_sha256": Path("content_probe_bundle.py"),
        "integrity_sha256": Path("integrity.py"),
    }
    for field, relative in bindings.items():
        data = files.get(relative)
        if data is None:
            if strict:
                raise BundleError(f"identity-bound artifact missing: {relative}")
            continue
        if _sha256(data) != identity[field]:
            raise BundleError(f"identity hash mismatch: {field}")


def _assert_fd_path_same(fd: int, path: Path) -> None:
    fd_stat = os.fstat(fd)
    path_stat = os.stat(path, follow_symlinks=False)
    if not os.path.samestat(fd_stat, path_stat):
        raise BundleError(f"bundle path changed during sealing: {path}")


def _require_mode(test_only_allow_unenforced: bool) -> None:
    if os.name == "nt" and not test_only_allow_unenforced:
        raise BundleError("authoritative content bundle requires POSIX descriptor primitives")
    if os.name != "nt":
        try:
            integrity._require_posix_seal_capabilities()
        except Exception as exc:
            raise BundleError("authoritative content bundle requires POSIX descriptor primitives") from exc


def _open_parent(path: Path, *, test_only_allow_unenforced: bool) -> int | None:
    if os.name == "nt":
        if not test_only_allow_unenforced:
            raise BundleError("Windows bundle mode is test-only")
        return None
    try:
        return integrity._open_posix_directory_non_following(path)
    except Exception as exc:
        raise BundleError(f"cannot open parent directory safely: {path}") from exc


def _open_existing_dir(parent_fd: int, name: str) -> int:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise BundleError(f"cannot open bundle directory component: {name}") from exc


def _write_at_posix(root_fd: int, relative: Path, data: bytes) -> None:
    current = os.dup(root_fd)
    opened: list[int] = [current]
    try:
        for component in relative.parts[:-1]:
            try:
                os.mkdir(component, 0o750, dir_fd=current)
            except FileExistsError:
                pass
            child = _open_existing_dir(current, component)
            opened.append(child)
            current = child
        fd = os.open(relative.name, _FILE_FLAGS, 0o640, dir_fd=current)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise BundleError(f"short write: {relative.as_posix()}")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def _write_exclusive(path: Path, data: bytes, *, test_only_allow_unenforced: bool) -> None:
    if os.name == "nt":
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            raise BundleError(f"trust manifest already exists: {path}") from exc
        return
    parent_fd = _open_parent(path.parent, test_only_allow_unenforced=False)
    assert parent_fd is not None  # guarded by POSIX mode above
    try:
        _write_at_posix(parent_fd, Path(path.name), data)
    except FileExistsError as exc:
        raise BundleError(f"trust manifest already exists: {path}") from exc
    finally:
        os.close(parent_fd)


def _read_external_trust(path: Path, *, expected_sha256: str) -> tuple[dict[str, Any], str]:
    try:
        first = integrity.read_evidence(path)
        first_hash = _sha256(first.data)
        if first_hash != expected_sha256:
            raise BundleError("external trust manifest hash mismatch")
        payload = json.loads(first.data.decode("utf-8"))
        second = integrity.read_evidence(path)
        if second.data != first.data or second.file_identity != first.file_identity:
            raise BundleError("external trust manifest changed during verification")
    except BundleError:
        raise
    except Exception as exc:
        raise BundleError("invalid external trust manifest") from exc
    if payload.get("schema_version") != TRUST_SCHEMA_VERSION:
        raise BundleError("unsupported trust manifest schema")
    return payload, first_hash


def create_content_bundle(
    bundle_root: str | Path,
    trust_manifest: str | Path,
    *,
    files: Mapping[str, bytes],
    identity: Mapping[str, str],
    test_only_allow_unenforced: bool = False,
) -> dict[str, Any]:
    """Create one POSIX-authoritative sealed bundle and external trust record."""
    _require_mode(test_only_allow_unenforced)
    bundle = Path(bundle_root)
    trust = Path(trust_manifest)
    if bundle.exists():
        raise BundleError(f"bundle already exists: {bundle}")
    if trust.exists():
        raise BundleError(f"trust manifest already exists: {trust}")
    if _inside(trust, bundle):
        raise BundleError("trust manifest must be outside bundle root")
    if not trust.parent.is_dir():
        raise BundleError("trust manifest parent must already exist")
    if len(files) == 0:
        raise BundleError("bundle must contain at least one artifact")
    normalized_identity = _identity_copy(identity)
    normalized_files: dict[Path, bytes] = {}
    for name, data in files.items():
        relative = _relative_file_name(name)
        if not isinstance(data, bytes):
            raise BundleError(f"bundle artifact must be bytes: {name}")
        if len(data) > MAX_FILE_BYTES:
            raise BundleError(f"bundle artifact exceeds limit: {name}")
        if relative in normalized_files:
            raise BundleError(f"duplicate bundle artifact: {name}")
        normalized_files[relative] = data
    if not test_only_allow_unenforced:
        _validate_identity_bindings(normalized_identity, normalized_files, strict=True)
        probe_data = json.loads(normalized_files[Path("probe-data.json")].decode("utf-8"))
        if probe_data.get("source_seal_sha256") != normalized_identity["source_seal_sha256"]:
            raise BundleError("source seal identity does not match probe-data")

    if not bundle.parent.is_dir():
        raise BundleError("bundle parent must already exist")
    bundle_fd: int | None = None
    parent_fd: int | None = None
    if os.name == "nt":
        try:
            bundle.mkdir()
        except FileExistsError as exc:
            raise BundleError(f"bundle already exists: {bundle}") from exc
        for relative, data in normalized_files.items():
            target = bundle / relative
            _write_exclusive(target, data, test_only_allow_unenforced=True)
    else:
        parent_fd = _open_parent(bundle.parent, test_only_allow_unenforced=False)
        if parent_fd is None:
            raise BundleError("POSIX parent descriptor unavailable")
        try:
            try:
                os.mkdir(bundle.name, 0o750, dir_fd=parent_fd)
            except FileExistsError as exc:
                raise BundleError(f"bundle already exists: {bundle}") from exc
            bundle_fd = os.open(bundle.name, _DIR_FLAGS, dir_fd=parent_fd)
            for relative, data in normalized_files.items():
                _write_at_posix(bundle_fd, relative, data)
            _assert_fd_path_same(bundle_fd, bundle)
        except BaseException:
            os.close(parent_fd)
            parent_fd = None
            raise

    try:
        if bundle_fd is not None:
            _assert_fd_path_same(bundle_fd, bundle)
        build_run_seal(bundle, canonical_path_root=bundle)
        if bundle_fd is not None:
            _assert_fd_path_same(bundle_fd, bundle)
        sealed = load_sealed_run(bundle, read_content=False)
        if bundle_fd is not None:
            _assert_fd_path_same(bundle_fd, bundle)
        seal_bytes = sealed.seal_evidence.data
        trust_payload = {
            "schema_version": TRUST_SCHEMA_VERSION,
            "bundle_root": _normalized(bundle),
            "identity": normalized_identity,
            "seal_sha256": _sha256(seal_bytes),
            "files": {relative: {"sha256": evidence.sha256, "size": evidence.size} for relative, evidence in sorted(sealed.files.items())},
        }
        trust_bytes = _canonical_json(trust_payload)
        if os.name == "nt":
            _write_exclusive(trust, trust_bytes, test_only_allow_unenforced=True)
        else:
            trust_parent_fd = _open_parent(trust.parent, test_only_allow_unenforced=False)
            if trust_parent_fd is None:
                raise BundleError("POSIX trust parent descriptor unavailable")
            try:
                _write_at_posix(trust_parent_fd, Path(trust.name), trust_bytes)
            finally:
                os.close(trust_parent_fd)
        return {
            "status": "PASS",
            "bundle_root": _normalized(bundle),
            "trust_manifest": _normalized(trust),
            "seal_sha256": trust_payload["seal_sha256"],
            "trust_manifest_sha256": _sha256(trust_bytes),
            "files": sorted(sealed.files),
            "identity": normalized_identity,
        }
    finally:
        if bundle_fd is not None:
            os.close(bundle_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def verify_content_bundle(
    bundle_root: str | Path,
    trust_manifest: str | Path,
    *,
    expected_identity: Mapping[str, str],
    expected_trust_sha256: str,
    test_only_allow_unenforced: bool = False,
) -> dict[str, Any]:
    """Verify the sealed bundle against an externally pinned trust hash."""
    _require_mode(test_only_allow_unenforced)
    bundle = Path(bundle_root)
    trust = Path(trust_manifest)
    if not bundle.is_dir():
        raise BundleError("bundle root is absent")
    if _inside(trust, bundle):
        raise BundleError("trust manifest must be external")
    trust_data, trust_hash = _read_external_trust(trust, expected_sha256=expected_trust_sha256)
    if trust_data.get("bundle_root") != _normalized(bundle):
        raise BundleError("trust bundle root mismatch")
    identity = _identity_copy(expected_identity)
    if trust_data.get("identity") != identity:
        raise BundleError("trust identity mismatch")
    try:
        sealed = load_sealed_run(bundle, read_content=not test_only_allow_unenforced)
    except Exception as exc:
        raise BundleError("sealed bundle verification failed") from exc
    if not test_only_allow_unenforced:
        identity_bindings = {
            "probe_data_sha256": "probe-data.json", "probe_code_sha256": "probe_content_sources10.py",
            "verifier_code_sha256": "verify_content_probe10.py", "bundle_helper_sha256": "content_probe_bundle.py",
            "integrity_sha256": "integrity.py",
        }
        for field, relative in identity_bindings.items():
            evidence = sealed.files.get(relative)
            if evidence is None or evidence.sha256 != identity[field]:
                raise BundleError(f"sealed identity hash mismatch: {field}")
        probe_evidence = sealed.files.get("probe-data.json")
        if probe_evidence is None or not probe_evidence.data:
            raise BundleError("sealed probe-data content missing")
        probe_data = json.loads(probe_evidence.data.decode("utf-8"))
        if probe_data.get("source_seal_sha256") != identity["source_seal_sha256"]:
            raise BundleError("sealed source seal identity mismatch")
    seal_sha256 = sealed.seal_evidence.sha256
    if seal_sha256 != trust_data.get("seal_sha256"):
        raise BundleError("trust seal hash mismatch")
    trusted_files = trust_data.get("files")
    if not isinstance(trusted_files, dict) or set(trusted_files) != set(sealed.files):
        raise BundleError("trust file set mismatch")
    for relative, evidence in sealed.files.items():
        record = trusted_files.get(relative)
        if not isinstance(record, dict) or record.get("sha256") != evidence.sha256 or record.get("size") != evidence.size:
            raise BundleError(f"trust file hash/size mismatch: {relative}")
    # load_sealed_run performs the descriptor-rooted final read-back; repeat the
    # trust read to bind the external attestation through the return boundary.
    _read_external_trust(trust, expected_sha256=expected_trust_sha256)
    return {
        "status": "PASS",
        "bundle_root": _normalized(bundle),
        "trust_manifest": _normalized(trust),
        "trust_manifest_sha256": trust_hash,
        "seal_sha256": seal_sha256,
        "files": sorted(sealed.files),
        "identity": identity,
    }
