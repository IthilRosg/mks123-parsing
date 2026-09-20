"""Build a direct Netlab transfer preview or staging SQL candidate."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil  # noqa: F401 - retained for test-only compatibility
import stat
import sys
import tempfile
import uuid
from collections import Counter
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import replace
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.integrity import build_run_seal
from mks123_pipeline.netlab_transfer import (
    TransferConfig,
    TransferError,
    TransferPlan,
    _deterministic_transferred_at,
    build_transfer_plan,
    plan_summary,
    render_sql,
    select_supplier_item_ids,
    validate_attribute_mapping_payload,
    validate_source_freshness,
)
from mks123_pipeline.trusted_run import TrustedRunError, load_trusted_run_manifest
from mks123_pipeline.two_category_selector import (
    CategorySelection,
    CategorySelectorError,
    select_two_category_items,
)


def _load_json(path: Path) -> dict[str, Any]:
    return _read_stable_json(Path(path))[0]


def _load_canary_ids(path: Path) -> frozenset[str]:
    payload, _ = _read_stable_json(Path(path), object_pairs_hook=_reject_duplicate_json_keys)
    values = payload.get("supplier_item_ids") if isinstance(payload, dict) else None
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(value, str) or not value.strip() for value in values)
        or len(set(values)) != len(values)
    ):
        raise TransferError("canary supplier_item_ids file is invalid")
    return frozenset(values)

def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TransferError(f"JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def _load_attribute_mapping(path: Path, *, expected_language_id: int = 1) -> tuple[dict[str, int], str, str, dict[str, Any]]:
    path = Path(path)
    payload, digest = _read_stable_json(path, object_pairs_hook=_reject_duplicate_json_keys)
    mapping, metadata = validate_attribute_mapping_payload(
        payload,
        expected_language_id=expected_language_id,
    )
    return mapping, digest, str(path.resolve(strict=True)), metadata


def _manifest_policy(
    manifest_path: Path,
    *,
    expected_seal_sha256: str | None,
) -> tuple[str, str, str, str, str, dict[str, Any]]:
    manifest_path = Path(manifest_path)
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise TransferError("run manifest is not a regular file")
    manifest_path = manifest_path.resolve(strict=True)
    try:
        manifest, manifest_identity, _ = load_trusted_run_manifest(
            manifest_path,
            expected_seal_sha256=expected_seal_sha256 or "",
        )
    except TrustedRunError as exc:
        raise TransferError(str(exc)) from exc
    manifest_sha256 = manifest_identity["sha256"]
    run_id = manifest.get("run_id")
    inputs = manifest.get("inputs")
    policy = manifest.get("policy")
    rates = policy.get("rates") if isinstance(policy, dict) else None
    usd = rates.get("USD") if isinstance(rates, dict) else None
    source = inputs.get("source") if isinstance(inputs, dict) else None
    source_hash = source.get("sha256") if isinstance(source, dict) else None
    source_bundle = source.get("bundle_path") if isinstance(source, dict) else None
    rate = usd.get("rub_per_unit") if isinstance(usd, dict) else None
    if not all(isinstance(value, str) and value for value in (run_id, source_hash, source_bundle, rate)):
        raise TransferError("run manifest lacks source hash, path, run id or USD rate")
    bundle = Path(source_bundle)
    if bundle.is_absolute() or ".." in bundle.parts:
        raise TransferError("run manifest source bundle path is unsafe")
    bundle_path = manifest_path.parent / bundle
    if bundle_path.is_symlink() or not bundle_path.is_file():
        raise TransferError("run manifest source bundle is not a regular file")
    source_artifact_path = bundle_path.resolve(strict=True)
    if manifest.get("supplier") != "netlab":
        raise TransferError("transfer requires a Netlab run manifest")
    run_manifest_provenance = {
        "run_id": run_id,
        "fetched_at": manifest.get("fetched_at"),
        "source_catalog_date": manifest.get("source_catalog_date"),
        "code_identity": manifest.get("code_identity"),
        "policy": manifest.get("policy"),
        "selection_inputs": manifest.get("selection_inputs"),
    }
    return run_id, source_hash, rate, str(source_artifact_path), manifest_sha256, run_manifest_provenance


def _validate_selection_seal(provenance: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sealed = provenance.get("selection_inputs")
    roles = (
        "normalized_source",
        "matches",
        "category_mapping_proposals",
        "product_category_proposals",
        "category_snapshot",
    )
    if not isinstance(sealed, dict):
        raise TransferError("scoped mode requires sealed selection inputs in the run manifest")
    validated: dict[str, dict[str, Any]] = {}
    for role in roles:
        entry = sealed.get(role)
        if not isinstance(entry, dict):
            raise TransferError(f"trusted selection seal is missing: {role}")
        paths = entry.get("paths")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(paths, list)
            or not paths
            or not all(isinstance(path, str) and Path(path).is_absolute() for path in paths)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in digest)
        ):
            raise TransferError(f"trusted selection seal is invalid: {role}")
        validated[role] = {"paths": paths, "size": size, "sha256": digest.lower()}
    return validated


def _select_sealed_selection_path(
    selection_seal: dict[str, dict[str, Any]],
    role: str,
) -> Path:
    entry = selection_seal[role]
    for raw_path in entry["paths"]:
        path = Path(raw_path)
        try:
            path_stat = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            continue
        identity = _file_identity(path)
        if identity["size"] != entry["size"] or identity["sha256"] != entry["sha256"]:
            raise TransferError(f"trusted selection input changed: {role}")
        return path.resolve(strict=True)
    raise TransferError(f"trusted selection input is unavailable: {role}")


def _record_json(record: Any, *, run_id: str, transferred_at: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "transferred_at": transferred_at,
        "action": record.action,
        "supplier_item_id": record.source.supplier_item_id,
        "source_sku": record.source.catalog_sku,
        "target_product_id": record.target_product_id,
        "target_sku": record.target_sku,
        "source_kind": "netlab",
        "verification_status": record.verification_status,
        "manufacturer_verified": False,
        "source_row_sha256": record.source.payload_sha256,
        "source_raw_hash": record.target_payload["raw_hash"],
        "source_url": record.target_payload["source_url"],
        "source_fetched_at": record.target_payload["fetched_at"],
        "source_snapshot_json": record.source.source_snapshot_json,
        "target_payload": record.target_payload,
        "properties_json": record.source_properties_json,
        "image_urls_json": record.source_images_json,
        "category_json": record.source_category_json,
        "attribute_rows": [
            {"attribute_id": attribute_id, "text": text}
            for attribute_id, text in record.attribute_rows
        ],
        "unmapped_attribute_names": list(record.unmapped_attribute_names),
    }


def _write_exclusive(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _capture_input(path: Path, destination: Path, *, label: str, maximum: int) -> tuple[Path, str]:
    original = Path(path)
    if original.is_symlink() or not original.is_file():
        raise TransferError(f"{label} is not a regular file")
    before_path_stat = os.lstat(original)
    digest = hashlib.sha256()
    size = 0
    try:
        with original.open("rb") as source, destination.open("xb") as target:
            before_handle_stat = os.fstat(source.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise TransferError(f"{label} changed before capture")
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise TransferError(f"{label} exceeds byte limit")
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
            after_handle_stat = os.fstat(source.fileno())
        after_path_stat = os.lstat(original)
    except OSError as exc:
        raise TransferError(f"cannot capture {label}") from exc
    if (
        not stat.S_ISREG(after_path_stat.st_mode)
        or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size)
        != (after_handle_stat.st_dev, after_handle_stat.st_ino, after_handle_stat.st_size)
        or (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size)
        != (after_path_stat.st_dev, after_path_stat.st_ino, after_path_stat.st_size)
        or size != after_handle_stat.st_size
    ):
        raise TransferError(f"{label} changed during capture")
    return destination, digest.hexdigest()


def _file_identity(path: Path) -> dict[str, Any]:
    before_path_stat = os.lstat(path)
    if not stat.S_ISREG(before_path_stat.st_mode):
        raise TransferError(f"input is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        before_handle_stat = os.fstat(handle.fileno())
        if (before_handle_stat.st_dev, before_handle_stat.st_ino) != (
            before_path_stat.st_dev,
            before_path_stat.st_ino,
        ):
            raise TransferError(f"input changed before hashing: {path}")
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after_handle_stat = os.fstat(handle.fileno())
    after_path_stat = os.lstat(path)
    if not stat.S_ISREG(after_path_stat.st_mode):
        raise TransferError(f"input type changed during hashing: {path}")
    if (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size) != (
        after_handle_stat.st_dev,
        after_handle_stat.st_ino,
        after_handle_stat.st_size,
    ) or (before_path_stat.st_dev, before_path_stat.st_ino) != (
        after_path_stat.st_dev,
        after_path_stat.st_ino,
    ):
        raise TransferError(f"input changed during hashing: {path}")
    if size != after_handle_stat.st_size:
        raise TransferError(f"input size changed during hashing: {path}")
    return {"path": path.name, "size": size, "sha256": digest.hexdigest()}


def _read_stable_json(
    path: Path,
    *,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], str]:
    before_path_stat = os.lstat(path)
    if not stat.S_ISREG(before_path_stat.st_mode):
        raise TransferError(f"run manifest is not a regular file: {path}")
    try:
        with path.open("rb") as handle:
            before_handle_stat = os.fstat(handle.fileno())
            if (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size) != (
                before_handle_stat.st_dev,
                before_handle_stat.st_ino,
                before_handle_stat.st_size,
            ):
                raise TransferError("run manifest changed before parsing")
            data = handle.read(8 * 1024 * 1024 + 1)
            after_handle_stat = os.fstat(handle.fileno())
        after_path_stat = os.lstat(path)
    except OSError as exc:
        raise TransferError(f"cannot read run manifest: {path}") from exc
    if (
        len(data) > 8 * 1024 * 1024
        or len(data) != after_handle_stat.st_size
        or (before_handle_stat.st_dev, before_handle_stat.st_ino, before_handle_stat.st_size)
        != (after_handle_stat.st_dev, after_handle_stat.st_ino, after_handle_stat.st_size)
        or (before_path_stat.st_dev, before_path_stat.st_ino, before_path_stat.st_size)
        != (after_path_stat.st_dev, after_path_stat.st_ino, after_path_stat.st_size)
    ):
        raise TransferError("run manifest changed during parsing")
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs_hook)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"invalid JSON manifest: {path}") from exc
    if not isinstance(payload, dict):
        raise TransferError("run manifest must be an object")
    return payload, hashlib.sha256(data).hexdigest()


def _path_variants_from_resolved(resolved: str) -> list[str]:
    variants = [resolved]
    if len(resolved) >= 3 and resolved[1:3] == ":\\":
        rest = resolved[3:].replace("\\", "/")
        variants.append(f"/mnt/{resolved[0].lower()}/{rest}")
    elif len(resolved) >= 7 and resolved.casefold().startswith("/mnt/") and resolved[5].isalpha() and resolved[6] == "/":
        drive = resolved[5].upper()
        rest = resolved[7:].replace("/", chr(92))
        variants.append(f"{drive}:{chr(92)}{rest}")
    return variants


def _path_variants(path: Path) -> list[str]:
    return _path_variants_from_resolved(str(path.resolve(strict=True)))


def _input_identity(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    original_path = Path(path)
    if original_path.is_symlink() or not original_path.is_file():
        raise TransferError(f"transfer input is not a regular file: {original_path}")
    path = original_path.resolve(strict=True)
    identity = _file_identity(path)
    if identity["sha256"] != expected_sha256:
        raise TransferError(f"transfer input hash changed: {path}")
    return {
        "paths": _path_variants(path),
        "size": identity["size"],
        "sha256": identity["sha256"],
    }


def _candidate_identity(manifest: dict[str, Any]) -> str:
    material = {
        "schema_version": manifest["schema_version"],
        "candidate_mode": manifest["candidate_mode"],
        "run_id": manifest["run_id"],
        "source_artifact_sha256": manifest["source_artifact_sha256"],
        "matches_artifact_sha256": manifest["matches_artifact_sha256"],
        "run_manifest_sha256": manifest.get("run_manifest_sha256"),
        "run_manifest_provenance": manifest.get("run_manifest_provenance"),
        "inputs": manifest["inputs"],
        "attribute_mapping": manifest.get("attribute_mapping"),
        "files": sorted(manifest["files"], key=lambda entry: entry["path"]),
    }
    if "selector" in manifest:
        material["selector"] = manifest["selector"]
    canonical = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _directory_identity(path: Path) -> tuple[int, int]:
    directory_stat = os.lstat(path)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise TransferError(f"candidate output parent is not a regular directory: {path}")
    return directory_stat.st_dev, directory_stat.st_ino


def _directory_identity_from_fd(fd: int) -> tuple[int, int]:
    directory_stat = os.fstat(fd)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise TransferError("candidate directory handle is not a directory")
    return directory_stat.st_dev, directory_stat.st_ino


def _open_directory_fd(path: Path) -> int | None:
    if os.name == "nt":
        return None
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags)


def _open_directory_entry_fd(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=parent_fd)


def _directory_entry_identity(parent_fd: int, name: str) -> tuple[int, int]:
    entry_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(entry_stat.st_mode):
        raise TransferError(f"candidate stage entry is not a directory: {name}")
    return entry_stat.st_dev, entry_stat.st_ino


def _create_stage_directory(parent: Path, final_name: str, parent_fd: int | None) -> Path:
    if parent_fd is None:
        return Path(tempfile.mkdtemp(prefix=f".{final_name}.building-", dir=str(parent)))
    for _ in range(32):
        name = f".{final_name}.building-{uuid.uuid4().hex}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        return parent / name
    raise TransferError("could not reserve a unique candidate stage")


def _stage_io_path(stage: Path, stage_fd: int | None) -> Path:
    if stage_fd is not None and os.name != "nt":
        return Path(f"/proc/self/fd/{stage_fd}")
    return stage


def _flush_directory(path: Path, *, directory_fd: int | None = None) -> None:
    if os.name != "nt":
        fd = directory_fd
        close_fd = False
        if fd is None:
            fd = os.open(path, os.O_RDONLY)
            close_fd = True
        try:
            os.fsync(fd)
        finally:
            if close_fd:
                os.close(fd)
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    handle = kernel32.CreateFileW(
        str(path),
        0xC0000000,
        0x00000007,
        None,
        3,
        0x02000000,
        None,
    )
    invalid = wintypes.HANDLE(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), f"cannot open output parent: {path}")
    try:
        if not kernel32.FlushFileBuffers(handle):
            raise OSError(ctypes.get_last_error(), f"cannot flush output parent: {path}")
    finally:
        kernel32.CloseHandle(handle)


def _rename_noreplace(
    source: Path,
    destination: Path,
    *,
    directory_fd: int | None = None,
    source_identity: tuple[int, int] | None = None,
) -> None:
    """Atomically publish a directory without replacing an existing path."""
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move_file_ex.restype = wintypes.BOOL
        if move_file_ex(str(source), str(destination), 0x00000008):
            return
        error = ctypes.get_last_error()
        if error in {80, 183}:
            raise FileExistsError(destination)
        raise OSError(error, f"cannot publish candidate: {source} -> {destination}")

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError(errno.ENOSYS, "atomic no-replace rename is unavailable") from exc
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    owned_fd = False
    if directory_fd is None:
        if source.parent != destination.parent:
            raise TransferError("no-replace publication requires one parent directory")
        directory_fd = _open_directory_fd(source.parent)
        if directory_fd is None:
            raise OSError(errno.ENOSYS, "descriptor-relative rename is unavailable")
        owned_fd = True
    try:
        if source_identity is not None and _directory_entry_identity(directory_fd, source.name) != source_identity:
            raise TransferError("candidate stage source entry changed before publication")
        result = renameat2(
            directory_fd,
            os.fsencode(source.name),
            directory_fd,
            os.fsencode(destination.name),
            1,
        )
    finally:
        if owned_fd:
            os.close(directory_fd)
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(destination)
    raise OSError(error, os.strerror(error))


def _write_candidate(
    root: Path,
    plan: TransferPlan,
    *,
    render_staging_sql: bool,
    run_manifest_path: Path,
    category_selection: CategorySelection | None = None,
    selector_input_paths: dict[str, Path] | None = None,
    provenance_input_paths: dict[str, Path] | None = None,
) -> None:
    final_root = Path(root)
    if final_root.is_symlink() or final_root.exists():
        raise TransferError(f"candidate output already exists: {final_root}")
    if category_selection is None and plan.policy.selection_manifest_sha256 is not None:
        raise TransferError("selection hash requires a category selection manifest")
    if category_selection is not None:
        expected_keys = {
            "category_mapping_proposals",
            "product_category_proposals",
            "category_snapshot",
        }
        if not selector_input_paths or set(selector_input_paths) != expected_keys:
            raise TransferError("scoped candidate is missing selector input paths")
        if plan.policy.selected_supplier_item_ids != category_selection.selected_supplier_item_ids:
            raise TransferError("plan selection IDs do not match category selection manifest")
        if plan.policy.selection_manifest_sha256 != category_selection.selection_manifest_sha256:
            raise TransferError("plan selection hash does not match category selection manifest")

    provenance = provenance_input_paths or {}
    source_artifact_path = Path(provenance.get("source_artifact", plan.policy.source_artifact_path or plan.source_path))
    normalized_source_path = provenance.get("normalized_source", plan.source_path)
    matches_path = provenance.get("matches", plan.matches_path)
    manifest_path = provenance.get("run_manifest", run_manifest_path)
    _input_identity(source_artifact_path, expected_sha256=plan.source_artifact_sha256)
    _input_identity(
        normalized_source_path,
        expected_sha256=(
            category_selection.source_sha256
            if category_selection is not None
            else _file_identity(plan.source_path)["sha256"]
        ),
    )
    _input_identity(
        matches_path,
        expected_sha256=(
            category_selection.matches_sha256
            if category_selection is not None
            else plan.matches_artifact_sha256
        ),
    )
    _input_identity(
        manifest_path,
        expected_sha256=(plan.policy.run_manifest_sha256 or _file_identity(manifest_path)["sha256"]),
    )
    if category_selection is not None:
        _input_identity(
            selector_input_paths["category_mapping_proposals"],
            expected_sha256=category_selection.category_mapping_sha256,
        )
        _input_identity(
            selector_input_paths["product_category_proposals"],
            expected_sha256=category_selection.product_proposals_sha256,
        )
        _input_identity(
            selector_input_paths["category_snapshot"],
            expected_sha256=category_selection.category_snapshot.snapshot_sha256,
        )

    final_root.parent.mkdir(parents=True, exist_ok=True)
    expected_parent_identity = _directory_identity(final_root.parent)
    parent_fd = _open_directory_fd(final_root.parent)
    parent_identity = (
        _directory_identity_from_fd(parent_fd)
        if parent_fd is not None
        else expected_parent_identity
    )
    if parent_identity != expected_parent_identity:
        if parent_fd is not None:
            os.close(parent_fd)
        raise TransferError("candidate output parent changed while opening descriptor")
    stage: Path | None = None
    stage_io: Path | None = None
    stage_fd: int | None = None
    stage_identity: tuple[int, int] | None = None
    published = False
    try:
        stage = _create_stage_directory(final_root.parent, final_root.name, parent_fd)
        stage_fd = (
            _open_directory_entry_fd(parent_fd, stage.name)
            if parent_fd is not None
            else _open_directory_fd(stage)
        )
        stage_io = _stage_io_path(stage, stage_fd)
        if stage_fd is not None:
            stage_identity = _directory_identity_from_fd(stage_fd)
            if parent_fd is not None and _directory_entry_identity(parent_fd, stage.name) != stage_identity:
                raise TransferError("candidate stage source entry changed while opening")
        _write_candidate_contents(
            stage_io,
            plan,
            render_staging_sql=render_staging_sql,
            run_manifest_path=run_manifest_path,
            category_selection=category_selection,
            selector_input_paths=selector_input_paths,
            provenance_input_paths=provenance,
        )
        if (
            parent_fd is not None
            and _directory_identity_from_fd(parent_fd) != parent_identity
        ) or (
            stage_fd is not None
            and (
                _directory_identity_from_fd(stage_fd) != stage_identity
                or (
                    parent_fd is not None
                    and _directory_entry_identity(parent_fd, stage.name) != stage_identity
                )
            )
        ):
            raise TransferError("candidate staging directory changed before sealing")
        build_run_seal(
            stage_io,
            canonical_path_root=final_root,
            run_dir_fd=stage_fd,
        )
        if stage_fd is not None and (
            _directory_identity_from_fd(stage_fd) != stage_identity
            or (
                parent_fd is not None
                and _directory_entry_identity(parent_fd, stage.name) != stage_identity
            )
        ):
            raise TransferError("candidate staging directory changed during sealing")
        _flush_directory(stage_io, directory_fd=stage_fd)
        if parent_fd is not None and _directory_identity_from_fd(parent_fd) != parent_identity:
            raise TransferError("candidate output parent changed before publication")
        _rename_noreplace(
            stage,
            final_root,
            directory_fd=parent_fd,
            source_identity=stage_identity,
        )
        published = True
        if parent_fd is not None and _directory_identity_from_fd(parent_fd) != parent_identity:
            raise TransferError("candidate output parent changed during publication")
        _flush_directory(final_root.parent, directory_fd=parent_fd)
    except BaseException as error:
        if published:
            error.add_note(
                f"candidate was atomically published but parent durability is ambiguous: {final_root}"
            )
        elif stage is not None:
            error.add_note(
                f"private candidate stage preserved after failed pre-publication: {stage}"
            )
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _write_candidate_contents(
    root: Path,
    plan: TransferPlan,
    *,
    render_staging_sql: bool,
    run_manifest_path: Path,
    category_selection: CategorySelection | None = None,
    selector_input_paths: dict[str, Path] | None = None,
    provenance_input_paths: dict[str, Path] | None = None,
) -> None:
    records_path = root / "RECORDS.jsonl"
    provenance = provenance_input_paths or {}
    source_artifact_path = Path(provenance.get("source_artifact", plan.policy.source_artifact_path or plan.source_path))
    normalized_source_path = provenance.get("normalized_source", plan.source_path)
    matches_path = provenance.get("matches", plan.matches_path)
    manifest_path = provenance.get("run_manifest", run_manifest_path)
    selector_code_identity = (
        _file_identity(Path(select_two_category_items.__code__.co_filename))
        if category_selection is not None
        else None
    )
    transferred_at = _deterministic_transferred_at(plan.policy)
    if plan.policy.attribute_mapping_path:
        _, captured_mapping_sha256 = _capture_input(
            Path(plan.policy.attribute_mapping_path),
            root / "ATTRIBUTE_MAPPING.json",
            label="attribute mapping",
            maximum=8 * 1024 * 1024,
        )
        if captured_mapping_sha256 != plan.policy.attribute_mapping_sha256:
            raise TransferError("attribute mapping changed while copying into candidate")
    with records_path.open("xb") as handle:
        for record in (*plan.updates, *plan.creates):
            record_data = _record_json(record, run_id=plan.run_id, transferred_at=transferred_at)
            record_data.update(
                {
                    "source_artifact_path": plan.policy.source_artifact_path or str(plan.source_path),
                    "source_artifact_sha256": plan.source_artifact_sha256,
                    "matches_artifact_sha256": plan.matches_artifact_sha256,
                    "run_manifest_sha256": plan.policy.run_manifest_sha256,
                }
            )
            if plan.policy.selection_manifest_sha256 is not None:
                record_data["selection_manifest_sha256"] = plan.policy.selection_manifest_sha256
                binding = (plan.policy.selection_record_bindings or {}).get(record.source.supplier_item_id)
                if binding is None:
                    raise TransferError(
                        f"missing selection binding for record {record.source.supplier_item_id}"
                    )
                record_data["selection_binding"] = {
                    field: binding[field]
                    for field in (
                        "catalog_sku",
                        "source_category_path",
                        "source_row_sha256",
                        "matches_row_sha256",
                        "category_mapping_row_sha256",
                        "product_proposal_row_sha256",
                        "target_category_id",
                        "root_category_id",
                    )
                }
            data = (json.dumps(record_data, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    exceptions = [
        {
            "supplier_item_id": item.supplier_item_id,
            "source_sku": item.catalog_sku,
            "reason": item.reason,
            "detail": item.detail,
        }
        for item in plan.exceptions
    ]
    summary_data = plan_summary(plan)
    summary_data["source_path"] = str(normalized_source_path)
    summary_data["matches_path"] = str(matches_path)
    summary_data["transferred_at"] = transferred_at
    if category_selection is not None:
        summary_data["category_selection"] = category_selection.as_manifest()
        summary_data["category_selection"]["selector_implementation_sha256"] = selector_code_identity["sha256"]
        summary_data["category_selection"]["transfer_counts"] = {
            "selected_rows": category_selection.selected_count,
            "written_records": plan.update_count + plan.create_count,
            "transfer_exceptions": len(plan.exceptions),
        }
    _write_exclusive(
        root / "SUMMARY.json",
        (json.dumps(summary_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _write_exclusive(
        root / "EXCEPTIONS.json",
        (json.dumps(exceptions, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    report = (
        "# Netlab snapshot transfer candidate\n\n"
        f"- Run: `{plan.run_id}`\n"
        f"- Source records scanned: `{plan.source_record_count}`\n"
        f"- Match records: `{plan.match_record_count}`\n"
        f"- Exact updates: `{plan.update_count}`\n"
        f"- Unmatched creates: `{plan.create_count}`\n"
        f"- Exceptions: `{len(plan.exceptions)}`\n"
        f"- Feed override: `{plan.feed_override or 'none'}`\n"
        "- Source kind: `netlab`\n"
        "- Verification status: `transferred_unverified`\n"
        "- Manufacturer verified: `false`\n"
        "- Compatibility relations: `0`\n"
        f"- Category relation writes: `{plan.relations_created}`\n"
        "- Media assignments: `0`\n"
        "- Publication enabled: `false`\n"
        "- Production writes: `0`\n"
    )
    if category_selection is not None:
        report += (
            f"- Two-category selected rows: `{category_selection.selected_count}`\n"
            f"- Two-category root counts: `{json.dumps(category_selection.selected_root_counts, sort_keys=True)}`\n"
            f"- Two-category selection manifest: `{category_selection.selection_manifest_sha256}`\n"
        )
    attribute_note = (
        "Mapped source-backed attributes are assigned through the explicit attribute mapping artifact; "
        "unmapped properties remain in provenance.\n"
        if plan.policy.attribute_mapping_sha256
        else "Remote image URLs and raw properties remain recorded but are not assigned as media/attribute relations in this candidate.\n"
    )
    report += (
        "\nDescriptions are sanitized for target HTML; the raw source row remains in the provenance snapshot. "
        "Scoped records assign only the allowlisted target category relation. "
        + attribute_note
    )
    _write_exclusive(root / "PREVIEW.md", report.encode("utf-8"))
    if render_staging_sql:
        _write_exclusive(
            root / "APPLY_STAGING.sql",
            render_sql(plan, mode="apply_staging", transferred_at=transferred_at).encode("utf-8"),
        )

    if category_selection is not None:
        if not selector_input_paths or set(selector_input_paths) != {
            "category_mapping_proposals",
            "product_category_proposals",
            "category_snapshot",
        }:
            raise TransferError("scoped candidate is missing selector input paths")
        selection_lines = b"".join(
            (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            for row in category_selection.selection_manifest
        )
        _write_exclusive(root / "SELECTION_MANIFEST.jsonl", selection_lines)
        selection_summary = category_selection.as_manifest()
        selection_summary["selector_implementation_sha256"] = selector_code_identity["sha256"]
        selection_summary["selection_manifest_file"] = "SELECTION_MANIFEST.jsonl"
        selection_summary["transfer_counts"] = {
            "selected_rows": category_selection.selected_count,
            "written_records": plan.update_count + plan.create_count,
            "transfer_exceptions": len(plan.exceptions),
        }
        _write_exclusive(
            root / "CATEGORY_SELECTION.json",
            (json.dumps(selection_summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    inputs = {
        "source_artifact": _input_identity(
            source_artifact_path,
            expected_sha256=plan.source_artifact_sha256,
        ),
        "normalized_source": _input_identity(
            normalized_source_path,
            expected_sha256=(category_selection.source_sha256 if category_selection else _file_identity(normalized_source_path)["sha256"]),
        ),
        "matches": _input_identity(
            matches_path,
            expected_sha256=(category_selection.matches_sha256 if category_selection else plan.matches_artifact_sha256),
        ),
        "run_manifest": _input_identity(
            manifest_path,
            expected_sha256=(plan.policy.run_manifest_sha256 or _file_identity(manifest_path)["sha256"]),
        ),
    }
    if plan.policy.attribute_mapping_path:
        inputs["attribute_mapping"] = _input_identity(
            Path(plan.policy.attribute_mapping_path),
            expected_sha256=plan.policy.attribute_mapping_sha256,
        )
    manifest: dict[str, Any] = {
        "schema_version": 2 if category_selection is not None else 1,
        "candidate_mode": "apply_staging" if render_staging_sql else "preview",
        "run_id": plan.run_id,
        "source_artifact_sha256": plan.source_artifact_sha256,
        "matches_artifact_sha256": plan.matches_artifact_sha256,
        "run_manifest_sha256": plan.policy.run_manifest_sha256,
        "run_manifest_provenance": plan.policy.run_manifest_provenance,
        "attribute_mapping": (
            {
                "file_sha256": plan.policy.attribute_mapping_sha256,
                "artifact_sha256": plan.policy.attribute_mapping_artifact_sha256,
                "database": plan.policy.attribute_mapping_database,
                "language_id": plan.policy.attribute_mapping_language_id,
                "scope_skus": sorted(plan.policy.attribute_mapping_scope_skus or ()),
            }
            if plan.policy.attribute_mapping_sha256
            else None
        ),
        "inputs": inputs,
        "files": [_file_identity(path) for path in sorted(root.iterdir()) if path.is_file()],
    }
    if category_selection is not None:
        inputs.update(
            {
                "category_mapping_proposals": _input_identity(
                    selector_input_paths["category_mapping_proposals"],
                    expected_sha256=category_selection.category_mapping_sha256,
                ),
                "product_category_proposals": _input_identity(
                    selector_input_paths["product_category_proposals"],
                    expected_sha256=category_selection.product_proposals_sha256,
                ),
                "category_snapshot": _input_identity(
                    selector_input_paths["category_snapshot"],
                    expected_sha256=category_selection.category_snapshot.snapshot_sha256,
                ),
            }
        )
        selector_manifest = category_selection.as_manifest()
        if plan.policy.bounded_canary_supplier_item_ids is not None:
            selector_manifest["bounded_canary"] = {
                "supplier_item_ids": sorted(plan.policy.bounded_canary_supplier_item_ids),
                "excluded_from_trusted_selection": category_selection.exclusion_counts.get("bounded_canary_excluded", 0),
            }
        selector_manifest["selector_implementation_sha256"] = selector_code_identity["sha256"]
        selector_manifest["selection_manifest_file"] = "SELECTION_MANIFEST.jsonl"
        selector_manifest["transfer_counts"] = {
            "selected_rows": category_selection.selected_count,
            "written_records": plan.update_count + plan.create_count,
            "transfer_exceptions": len(plan.exceptions),
        }
        manifest["selector"] = selector_manifest
    manifest["candidate_id"] = _candidate_identity(manifest)
    _write_exclusive(
        root / "CANDIDATE_MANIFEST.json",
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--matches", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path, required=True)
    parser.add_argument("--expected-run-seal-sha256")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--updates-limit", type=int)
    parser.add_argument("--creates-limit", type=int)
    parser.add_argument("--allow-incomplete-feed-staging", action="store_true")
    parser.add_argument("--render-staging-sql", action="store_true")
    parser.add_argument("--category-mapping-proposals", type=Path)
    parser.add_argument("--product-category-proposals", type=Path)
    parser.add_argument("--category-snapshot", type=Path)
    parser.add_argument("--attribute-mapping", type=Path)
    parser.add_argument("--require-complete-attributes", action="store_true")
    parser.add_argument("--selected-supplier-item-ids", type=Path)
    parser.add_argument("--run-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    capture_root: Path | None = None
    capture_root_io: Path | None = None
    capture_parent_fd: int | None = None
    capture_root_fd: int | None = None
    capture_root_identity: tuple[int, int] | None = None
    result = 2
    try:
        _, source_artifact_hash, rate, source_artifact_path, run_manifest_sha256, run_manifest_provenance = _manifest_policy(
            args.run_manifest,
            expected_seal_sha256=args.expected_run_seal_sha256,
        )
        selector_args = (
            args.category_mapping_proposals,
            args.product_category_proposals,
            args.category_snapshot,
        )
        category_selection: CategorySelection | None = None
        selection_manifest_sha256: str | None = None
        selector_input_paths: dict[str, Path] | None = None
        selection_seal: dict[str, dict[str, Any]] | None = None
        bounded_canary_ids: frozenset[str] | None = None
        source_for_plan = args.source
        matches_for_plan = args.matches
        if any(value is not None for value in selector_args):
            if not all(value is not None for value in selector_args):
                raise TransferError(
                    "two-category mode requires category mapping, product proposals and category snapshot"
                )
            if args.updates_limit is not None or args.creates_limit is not None:
                raise TransferError("updates/creates limits cannot be combined with two-category mode")
            if (
                not isinstance(run_manifest_provenance.get("fetched_at"), str)
                or not run_manifest_provenance.get("fetched_at")
                or not isinstance(run_manifest_provenance.get("code_identity"), dict)
                or not isinstance(run_manifest_provenance.get("policy"), dict)
            ):
                raise TransferError("scoped mode requires complete run-manifest provenance")
            validate_source_freshness(
                run_manifest_provenance["fetched_at"],
                label="run manifest fetched_at",
            )
            selection_seal = _validate_selection_seal(run_manifest_provenance)
            sealed_selection_paths = {
                role: _select_sealed_selection_path(selection_seal, role)
                for role in (
                    "normalized_source",
                    "matches",
                    "category_mapping_proposals",
                    "product_category_proposals",
                    "category_snapshot",
                )
            }
            capture_root = Path(tempfile.mkdtemp(prefix=".netlab-inputs-"))
            capture_parent_fd = _open_directory_fd(capture_root.parent)
            if capture_parent_fd is not None:
                capture_root_fd = _open_directory_entry_fd(capture_parent_fd, capture_root.name)
                capture_root_identity = _directory_identity_from_fd(capture_root_fd)
                if _directory_entry_identity(capture_parent_fd, capture_root.name) != capture_root_identity:
                    raise TransferError("capture directory identity changed while opening")
                capture_root_io = _stage_io_path(capture_root, capture_root_fd)
            else:
                capture_root_io = capture_root
            source_for_plan, source_capture_hash = _capture_input(
                sealed_selection_paths["normalized_source"],
                capture_root_io / "normalized-items.csv",
                label="normalized source",
                maximum=1024 * 1024 * 1024,
            )
            matches_for_plan, matches_capture_hash = _capture_input(
                sealed_selection_paths["matches"],
                capture_root_io / "matches.csv",
                label="matches",
                maximum=1024 * 1024 * 1024,
            )
            captured_category_mapping, category_mapping_capture_hash = _capture_input(
                sealed_selection_paths["category_mapping_proposals"],
                capture_root_io / "category-mapping-proposals.csv",
                label="category mapping proposals",
                maximum=1024 * 1024 * 1024,
            )
            captured_product_proposals, product_proposals_capture_hash = _capture_input(
                sealed_selection_paths["product_category_proposals"],
                capture_root_io / "product-category-proposals.csv",
                label="product category proposals",
                maximum=1024 * 1024 * 1024,
            )
            captured_snapshot, snapshot_capture_hash = _capture_input(
                sealed_selection_paths["category_snapshot"],
                capture_root_io / "category-snapshot.sql",
                label="category snapshot",
                maximum=256 * 1024 * 1024,
            )
            category_selection = select_two_category_items(
                source_for_plan,
                matches_for_plan,
                captured_category_mapping,
                captured_product_proposals,
                captured_snapshot,
            )
            if (
                category_selection.source_sha256 != source_capture_hash
                or category_selection.matches_sha256 != matches_capture_hash
                or category_selection.category_mapping_sha256 != category_mapping_capture_hash
                or category_selection.product_proposals_sha256 != product_proposals_capture_hash
                or category_selection.category_snapshot.snapshot_sha256 != snapshot_capture_hash
            ):
                raise TransferError("captured selector bytes do not match selector hashes")
            captured_hashes = {
                "normalized_source": source_capture_hash,
                "matches": matches_capture_hash,
                "category_mapping_proposals": category_mapping_capture_hash,
                "product_category_proposals": product_proposals_capture_hash,
                "category_snapshot": snapshot_capture_hash,
            }
            if any(selection_seal[role]["sha256"] != digest for role, digest in captured_hashes.items()):
                raise TransferError("captured selector bytes do not match the trusted run seal")
            selection_manifest_sha256 = category_selection.selection_manifest_sha256
            selector_input_paths = {
                "category_mapping_proposals": sealed_selection_paths["category_mapping_proposals"],
                "product_category_proposals": sealed_selection_paths["product_category_proposals"],
                "category_snapshot": sealed_selection_paths["category_snapshot"],
            }
            selected = category_selection.selected_supplier_item_ids
            if args.selected_supplier_item_ids is not None:
                bounded_canary_ids = _load_canary_ids(args.selected_supplier_item_ids)
                if not bounded_canary_ids.issubset(category_selection.selected_supplier_item_ids):
                    raise TransferError("bounded canary contains an item outside trusted selector")
                filtered_rows = tuple(
                    row
                    for row in category_selection.selection_manifest
                    if row["supplier_item_id"] in bounded_canary_ids
                )
                if len(filtered_rows) != len(bounded_canary_ids):
                    raise TransferError("bounded canary item is missing from trusted selection manifest")
                dropped = category_selection.selected_count - len(filtered_rows)
                exclusions = dict(category_selection.exclusion_counts)
                exclusions["bounded_canary_excluded"] = dropped
                selection_digest = hashlib.sha256()
                for row in filtered_rows:
                    selection_digest.update((json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
                category_selection = replace(
                    category_selection,
                    selected_supplier_item_ids=bounded_canary_ids,
                    selection_manifest=filtered_rows,
                    selected_root_counts=dict(sorted(Counter(str(row["root_category_id"]) for row in filtered_rows).items())),
                    exclusion_counts=dict(sorted(exclusions.items())),
                    mapping_status_counts=dict(sorted(Counter(str(row["mapping_status"]) for row in filtered_rows).items())),
                    selection_manifest_sha256=selection_digest.hexdigest(),
                )
                selection_manifest_sha256 = category_selection.selection_manifest_sha256
                selected = bounded_canary_ids
        else:
            selected = None
            if args.updates_limit is not None or args.creates_limit is not None:
                selected = select_supplier_item_ids(
                    args.matches,
                    max_updates=args.updates_limit or 0,
                    max_creates=args.creates_limit or 0,
                )
        attribute_mapping: dict[str, int] | None = None
        attribute_mapping_sha256: str | None = None
        attribute_mapping_path: str | None = None
        attribute_mapping_artifact_sha256: str | None = None
        attribute_mapping_database: str | None = None
        attribute_mapping_language_id: int | None = None
        attribute_mapping_scope_skus: frozenset[str] | None = None
        if args.attribute_mapping is not None:
            (
                attribute_mapping,
                attribute_mapping_sha256,
                attribute_mapping_path,
                mapping_metadata,
            ) = _load_attribute_mapping(args.attribute_mapping)
            attribute_mapping_artifact_sha256 = mapping_metadata["artifact_sha256"]
            attribute_mapping_database = mapping_metadata["database"]
            attribute_mapping_language_id = mapping_metadata["language_id"]
            attribute_mapping_scope_skus = mapping_metadata["scope_skus"]
        config = TransferConfig(
            usd_rub_rate=rate,
            feed_complete=False,
            allow_staging_apply=args.render_staging_sql,
            allow_incomplete_feed_for_staging=args.allow_incomplete_feed_staging,
            enforce_source_freshness=category_selection is not None,
            run_id=args.run_id,
            source_artifact_sha256=source_artifact_hash,
            source_artifact_path=source_artifact_path,
            run_manifest_sha256=run_manifest_sha256,
            run_manifest_provenance=run_manifest_provenance,
            attribute_mapping=attribute_mapping,
            attribute_mapping_sha256=attribute_mapping_sha256,
            attribute_mapping_path=attribute_mapping_path,
            attribute_mapping_artifact_sha256=attribute_mapping_artifact_sha256,
            attribute_mapping_database=attribute_mapping_database,
            attribute_mapping_language_id=attribute_mapping_language_id,
            attribute_mapping_scope_skus=attribute_mapping_scope_skus,
            bounded_canary_supplier_item_ids=bounded_canary_ids,
            require_complete_attribute_mapping=args.require_complete_attributes,
            selected_supplier_item_ids=selected,
            selection_manifest_sha256=selection_manifest_sha256,
            selection_manifest_supplier_item_ids=(
                frozenset(category_selection.selected_supplier_item_ids)
                if category_selection is not None
                else None
            ),
            selection_record_bindings=(
                {row["supplier_item_id"]: row for row in category_selection.selection_manifest}
                if category_selection is not None
                else None
            ),
        )
        plan = build_transfer_plan(source_for_plan, matches_for_plan, config=config)
        provenance_input_paths = {
            "source_artifact": Path(source_artifact_path),
            "normalized_source": (
                sealed_selection_paths["normalized_source"]
                if category_selection is not None
                else args.source
            ),
            "matches": (
                sealed_selection_paths["matches"]
                if category_selection is not None
                else args.matches
            ),
            "run_manifest": args.run_manifest,
        }
        if attribute_mapping_path:
            provenance_input_paths["attribute_mapping"] = Path(attribute_mapping_path)
        _write_candidate(
            args.output_root,
            plan,
            render_staging_sql=args.render_staging_sql,
            run_manifest_path=args.run_manifest,
            category_selection=category_selection,
            selector_input_paths=selector_input_paths,
            provenance_input_paths=provenance_input_paths,
        )
        summary = plan_summary(plan)
        if category_selection is not None:
            summary["category_selection"] = category_selection.as_manifest()
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        result = 0
    except (OSError, TransferError, CategorySelectorError) as exc:
        print(f"transfer candidate failed: {exc}", file=sys.stderr)
    finally:
        # The private capture tree is intentionally preserved.  Deleting a directory
        # by pathname cannot bind the final unlink/rmdir syscall to the verified inode.
        if capture_root_fd is not None:
            os.close(capture_root_fd)
        if capture_parent_fd is not None:
            os.close(capture_parent_fd)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
