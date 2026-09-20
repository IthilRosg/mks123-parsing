from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from PIL import Image, features
from PIL import __version__ as PILLOW_VERSION

from .integrity import SealedRunEvidence, load_sealed_run, read_evidence

STORAGE_ROOT = Path("/var/lib/mks123-netlab-media")
MAX_COMPRESSED_BYTES = 5 * 1024 * 1024
MAX_WIDTH = 6000
MAX_HEIGHT = 6000
MAX_PIXELS = 16_000_000
PLAN_SCHEMA = "netlab-media-plan-v2"
STAGE_SCHEMA = "netlab-media-stage-v2"
FINAL_SCHEMA = "netlab-media-final-v2"
POLICY_SCHEMA = "netlab-media-selection-policy-v1"
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x10
FS_APPEND_FL = 0x20
AT_EMPTY_PATH = 0x1000
RENAME_NOREPLACE = 1
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _image_extension(image_format: str) -> str:
    extensions = {"jpeg": "jpg", "png": "png", "webp": "webp"}
    try:
        return extensions[image_format]
    except KeyError as exc:
        raise ValueError("unsupported image format") from exc


def _require_sha(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"invalid {label}")


def _require_id(value: str, label: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")


def encoder_runtime_identity() -> dict[str, str]:
    webp = features.version("webp")
    if not isinstance(webp, str) or not webp:
        raise RuntimeError("Pillow WebP runtime is unavailable")
    return {"pillow_version": PILLOW_VERSION, "libwebp_version": webp}


def canonical_selection_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise TypeError("selection policy must be an object")
    allowed = {"schema", "eligible_catalog_skus", "eligible_supplier_item_ids", "max_images_per_item", "transform"}
    if set(policy) - allowed:
        raise ValueError("selection policy has unknown fields")
    skus = policy.get("eligible_catalog_skus", [])
    item_ids = policy.get("eligible_supplier_item_ids", [])
    if not isinstance(skus, list) or not isinstance(item_ids, list) or not (skus or item_ids):
        raise ValueError("invalid empty selection policy")
    for values in (skus, item_ids):
        if any(not isinstance(v, str) or not v for v in values) or len(values) != len(set(values)):
            raise ValueError("invalid selection allowlist")
    count = policy.get("max_images_per_item")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 3:
        raise ValueError("invalid maximum image count")
    transform = policy.get("transform")
    expected = {"format": "webp", "quality": 84, "hero_max_edge": 1600,
                "gallery_max_edge": 1200, "no_upscale": True, "strip_metadata": True}
    original = {"format": "source", "preserve_original": True}
    if transform not in (expected, original):
        raise ValueError("unsupported transform policy")
    selected = original if transform == original else expected
    return {"schema": POLICY_SCHEMA, "eligible_catalog_skus": sorted(skus),
            "eligible_supplier_item_ids": sorted(item_ids), "max_images_per_item": count,
            "transform": selected}


def _validate_plan(plan: dict[str, Any], expected_sha: str) -> bytes:
    _require_sha(expected_sha, "plan SHA-256")
    payload = _canonical(plan)
    keys = {"schema", "source_run_id", "source_seal_sha256", "selection_policy",
            "selection_policy_sha256", "transform_policy", "transform_policy_sha256",
            "encoder_runtime", "encoder_runtime_sha256", "fetches", "counts",
            "publication_enabled", "production_writes"}
    if _digest(payload) != expected_sha or not isinstance(plan, dict) or set(plan) != keys or plan["schema"] != PLAN_SCHEMA:
        raise ValueError("plan digest/schema mismatch")
    policy = canonical_selection_policy(plan["selection_policy"])
    runtime = encoder_runtime_identity()
    if policy != plan["selection_policy"] or plan["selection_policy_sha256"] != _digest(_canonical(policy)):
        raise ValueError("selection policy binding mismatch")
    if plan["transform_policy"] != policy["transform"] or plan["transform_policy_sha256"] != _digest(_canonical(policy["transform"])):
        raise ValueError("transform policy binding mismatch")
    if plan["encoder_runtime"] != runtime or plan["encoder_runtime_sha256"] != _digest(_canonical(runtime)):
        raise ValueError("encoder runtime binding mismatch")
    if plan["publication_enabled"] is not False or plan["production_writes"] != 0 or not isinstance(plan["fetches"], list) or not plan["fetches"]:
        raise ValueError("unsafe or empty plan")
    urls = []
    for item in plan["fetches"]:
        if not isinstance(item, dict) or set(item) != {"url", "supplier_item_id", "catalog_sku", "slot", "role"}:
            raise ValueError("invalid planned operation schema")
        if (not isinstance(item["url"], str) or not item["url"].startswith("https://nlimg.netlab.ru/") or
                any(not isinstance(item[k], str) or not item[k] for k in ("supplier_item_id", "catalog_sku")) or
                isinstance(item["slot"], bool) or not isinstance(item["slot"], int) or item["slot"] < 0 or
                item["role"] != ("hero" if item["slot"] == 0 else "gallery")):
            raise ValueError("planned role mismatch")
        urls.append(item["url"])
    if len(urls) != len(set(urls)) or plan["counts"] != {"selected_images": len(urls)}:
        raise ValueError("duplicate operation or count mismatch")
    return payload


def _sealed_source(run_dir: Path) -> tuple[SealedRunEvidence, dict[str, Any], bytes]:
    sealed = load_sealed_run(run_dir, read_content=False)
    manifest_ev = read_evidence(run_dir / "run-manifest.json", max_bytes=8 * 1024 * 1024)
    normalized_ev = read_evidence(run_dir / "normalized/items.jsonl", max_bytes=256 * 1024 * 1024)
    for name, evidence in (("run-manifest.json", manifest_ev), ("normalized/items.jsonl", normalized_ev)):
        expected = sealed.files.get(name)
        if expected is None or evidence.sha256 != expected.sha256 or evidence.file_identity != expected.file_identity:
            raise ValueError(f"sealed source changed: {name}")
    manifest = json.loads(manifest_ev.data)
    if manifest.get("supplier") != "netlab" or manifest.get("production_writes") != 0 or manifest.get("publication_enabled") is not False:
        raise ValueError("source must be a sealed unpublished Netlab run")
    return sealed, manifest, normalized_ev.data


def _open_dir(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    if os.name == "nt":
        return os.open(absolute, os.O_RDONLY)
    fd = os.open(os.sep, _DIR_FLAGS)
    try:
        for part in absolute.parts[1:]:
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _flags(fd: int, new: int | None = None) -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Linux inode flags are required")
    value = ctypes.c_uint(0 if new is None else new)
    request = FS_IOC_GETFLAGS if new is None else FS_IOC_SETFLAGS
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.ioctl(fd, request, ctypes.byref(value)):
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return value.value


def _set_flag(fd: int, flag: int) -> None:
    current = _flags(fd)
    if not current & flag:
        _flags(fd, current | flag)
    if not _flags(fd) & flag:
        raise RuntimeError("filesystem refused required inode flag")


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short write")
        view = view[count:]
    os.fsync(fd)


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, mode)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        _write_fd(fd, data)
    finally:
        os.close(fd)
    os.chmod(path, mode)


def _read_fd(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    out = bytearray()
    while len(out) <= limit:
        chunk = os.read(fd, min(1024 * 1024, limit + 1 - len(out)))
        if not chunk:
            return bytes(out)
        out.extend(chunk)
    raise ValueError("file exceeds bound")


def _storage_metadata(root: Path) -> dict[str, Any]:
    if os.name == "nt":
        value = json.loads((root / "storage.json").read_text("utf-8"))
    else:
        root_fd = _open_dir(root)
        try:
            fd = os.open("storage.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            try:
                identity, data = _snapshot_file(fd, 4096)
                value = json.loads(data)
                if (not isinstance(value, dict) or identity[3] != 0 or
                        stat.S_IMODE(identity[2]) != 0o440 or identity[4] != value.get("writer_gid")):
                    raise ValueError("invalid storage metadata owner/mode")
            finally:
                os.close(fd)
        finally:
            os.close(root_fd)
    if set(value) != {"schema", "writer_uid", "writer_gid"} or value["schema"] != "netlab-media-storage-v1":
        raise ValueError("invalid storage metadata")
    if any(isinstance(value[k], bool) or not isinstance(value[k], int) or value[k] < 1 for k in ("writer_uid", "writer_gid")):
        raise ValueError("invalid storage writer identity")
    return value


def init_storage(root: str | Path = STORAGE_ROOT, *, writer_uid: int, writer_gid: int,
                 test_only_allow_unenforced: bool = False) -> dict[str, Any]:
    path = Path(root)
    if not test_only_allow_unenforced and (not sys.platform.startswith("linux") or path != STORAGE_ROOT or os.geteuid() != 0):
        raise PermissionError("storage initialization requires Linux root and fixed production root")
    if isinstance(writer_uid, bool) or isinstance(writer_gid, bool) or writer_uid < 1 or writer_gid < 1:
        raise ValueError("writer uid/gid must be non-root")
    metadata = {"schema": "netlab-media-storage-v1", "writer_uid": writer_uid, "writer_gid": writer_gid}
    if test_only_allow_unenforced and os.name == "nt":
        path.mkdir(parents=True, exist_ok=True)
        specs = [(path, 0o711), (path / "cas", 0o710), (path / "runs", 0o710),
                 (path / "staging", 0o700), (path / "finalizing", 0o700), (path / "locks", 0o700)]
        for directory, mode in specs:
            if directory.is_symlink():
                raise ValueError("storage symlink is forbidden")
            directory.mkdir(exist_ok=True)
            os.chmod(directory, mode)
        for number in range(256):
            bucket = path / "cas" / f"{number:02x}"
            bucket.mkdir(exist_ok=True)
            os.chmod(bucket, 0o730)
        meta_path = path / "storage.json"
        if meta_path.exists():
            if json.loads(meta_path.read_text("utf-8")) != metadata:
                raise ValueError("storage already initialized for another writer")
        else:
            _write_exclusive(meta_path, _canonical(metadata), 0o400)
        return {"root": str(path), "writer_uid": writer_uid, "writer_gid": writer_gid,
                "publication_enabled": False, "production_writes": 0}

    parent_fd = _open_dir(path.parent)
    try:
        try:
            os.mkdir(path.name, 0o711, dir_fd=parent_fd)
        except FileExistsError:
            pass
        root_fd = os.open(path.name, _DIR_FLAGS, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        os.fchmod(root_fd, 0o750)
        os.fchown(root_fd, 0, writer_gid)
        child_specs = {"cas": (0o750, 0, writer_gid), "runs": (0o750, 0, writer_gid),
                       "staging": (0o700, writer_uid, writer_gid), "finalizing": (0o700, 0, 0),
                       "locks": (0o700, 0, 0)}
        children: dict[str, int] = {}
        try:
            for name, (mode, uid, gid) in child_specs.items():
                created = False
                try:
                    os.mkdir(name, mode, dir_fd=root_fd)
                    created = True
                except FileExistsError:
                    pass
                fd = os.open(name, _DIR_FLAGS, dir_fd=root_fd)
                children[name] = fd
                info = os.fstat(fd)
                actual = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                expected = (uid, gid, mode)
                if not stat.S_ISDIR(info.st_mode) or (not created and actual != expected):
                    raise ValueError(f"existing storage directory owner/mode mismatch: {name}")
                if created:
                    os.fchmod(fd, mode)
                    os.fchown(fd, uid, gid)
            cas_fd = children["cas"]
            for name in (f"{number:02x}" for number in range(256)):
                created = False
                try:
                    os.mkdir(name, 0o730, dir_fd=cas_fd)
                    created = True
                except FileExistsError:
                    pass
                bucket_fd = os.open(name, _DIR_FLAGS, dir_fd=cas_fd)
                try:
                    info = os.fstat(bucket_fd)
                    actual = (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    if not stat.S_ISDIR(info.st_mode) or (not created and actual != (0, writer_gid, 0o730)):
                        raise ValueError(f"existing storage bucket owner/mode mismatch: {name}")
                    if created:
                        os.fchmod(bucket_fd, 0o730)
                        os.fchown(bucket_fd, 0, writer_gid)
                    if not test_only_allow_unenforced:
                        _set_flag(bucket_fd, FS_APPEND_FL)
                    os.fsync(bucket_fd)
                finally:
                    os.close(bucket_fd)
            if not test_only_allow_unenforced:
                _set_flag(children["runs"], FS_APPEND_FL)
            try:
                meta_fd = os.open("storage.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            except FileNotFoundError:
                meta_fd = os.open("storage.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440, dir_fd=root_fd)
                _write_fd(meta_fd, _canonical(metadata))
                os.close(meta_fd)
                meta_fd = os.open("storage.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            try:
                os.fchmod(meta_fd, 0o440)
                os.fchown(meta_fd, 0, writer_gid)
                if json.loads(_read_fd(meta_fd, 4096)) != metadata:
                    raise ValueError("storage already initialized for another writer")
            finally:
                os.close(meta_fd)
            for fd in children.values():
                os.fsync(fd)
            os.fsync(root_fd)
        finally:
            for fd in children.values():
                os.close(fd)
    finally:
        os.close(root_fd)
    return {"root": str(path), "writer_uid": writer_uid, "writer_gid": writer_gid,
            "publication_enabled": False, "production_writes": 0}


@contextmanager
def _kernel_lock(path: Path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if sys.platform.startswith("linux"):
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _snapshot_file(fd: int, limit: int) -> tuple[tuple[int, ...], bytes]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("evidence is not an unaliased regular file")
    data = _read_fd(fd, limit)
    after = os.fstat(fd)
    identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid,
                before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    other = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid,
             after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if identity != other or before.st_size != len(data):
        raise ValueError("evidence mutated while read")
    return identity, data


def _walk_fd(fd: int, prefix: str = "") -> tuple[dict[str, tuple[tuple[int, ...], bytes]], list[str]]:
    files: dict[str, tuple[tuple[int, ...], bytes]] = {}
    directories = ["." if not prefix else prefix]
    for name in sorted(os.listdir(fd)):
        if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\\" in name:
            raise ValueError("noncanonical stage entry")
        rel = f"{prefix}/{name}" if prefix else name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("stage symlink is forbidden")
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _DIR_FLAGS, dir_fd=fd)
            try:
                if (os.fstat(child).st_dev, os.fstat(child).st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError("stage directory substituted")
                nested, nested_dirs = _walk_fd(child, rel)
                files.update(nested)
                directories.extend(nested_dirs)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | _BINARY, dir_fd=fd)
            try:
                files[rel] = _snapshot_file(child, 256 * 1024 * 1024)
            finally:
                os.close(child)
        else:
            raise ValueError("unsupported stage entry type")
    return files, directories


def _capture_stage(stage: Path, expected_seal: str, *, test_only_allow_unenforced: bool = False) -> tuple[dict[str, Any], dict[str, bytes]]:
    _require_sha(expected_seal, "stage seal SHA-256")
    if os.name == "nt":
        # Test-only compatibility; production is rejected before this path.
        files = {}
        dirs = ["."]
        for base, names, filenames in os.walk(stage, followlinks=False):
            relative = Path(base).relative_to(stage).as_posix()
            if relative != ".":
                dirs.append(relative)
            for name in names:
                if (Path(base) / name).is_symlink():
                    raise ValueError("stage symlink is forbidden")
            for name in filenames:
                path = Path(base) / name
                if path.is_symlink():
                    raise ValueError("stage symlink is forbidden")
                fd = os.open(path, os.O_RDONLY | _BINARY)
                try:
                    files[(Path(relative) / name).as_posix().removeprefix("./")] = _snapshot_file(fd, 256 * 1024 * 1024)
                finally:
                    os.close(fd)
        first = (files, sorted(dirs))
        second = first
    else:
        staging_fd = _open_dir(stage.parent)
        try:
            stage_fd = os.open(stage.name, _DIR_FLAGS, dir_fd=staging_fd)
            try:
                stable = os.fstat(stage_fd)
                first = _walk_fd(stage_fd)
                second = _walk_fd(stage_fd)
                now = os.fstat(stage_fd)
                if (stable.st_dev, stable.st_ino) != (now.st_dev, now.st_ino):
                    raise ValueError("stage directory identity changed")
            finally:
                os.close(stage_fd)
        finally:
            os.close(staging_fd)
    if first != second:
        raise ValueError("stage mutated during capture")
    records, dirs = first
    if "stage-seal.json" not in records:
        raise ValueError("stage seal missing")
    seal_identity, seal_bytes = records["stage-seal.json"]
    if _digest(seal_bytes) != expected_seal:
        raise ValueError("stage seal digest mismatch")
    seal = json.loads(seal_bytes)
    seal_keys = {"schema", "stage_id", "plan_sha256", "selection_policy_sha256", "transform_policy",
                 "transform_policy_sha256", "encoder_runtime", "encoder_runtime_sha256",
                 "files", "directories", "publication_enabled", "production_writes"}
    if not isinstance(seal, dict) or set(seal) != seal_keys or seal["schema"] != STAGE_SCHEMA:
        raise ValueError("invalid stage seal schema")
    if seal["publication_enabled"] is not False or seal["production_writes"] != 0:
        raise ValueError("unsafe stage seal")
    expected = set(seal["files"]) | {"stage-seal.json"}
    if set(records) != expected or sorted(dirs) != sorted(seal["directories"]):
        raise ValueError("stage file/directory set changed")
    if not test_only_allow_unenforced and (stat.S_IMODE(seal_identity[2]) != 0o600):
        raise ValueError("stage seal mode changed")
    captured = {"stage-seal.json": seal_bytes}
    for name, record in seal["files"].items():
        if not isinstance(name, str) or name.startswith("/") or "\\" in name or Path(name).as_posix() != name or ".." in Path(name).parts:
            raise ValueError("noncanonical stage path")
        identity, data = records[name]
        expected_record = {"size": len(data), "sha256": _digest(data), "mode": "0600",
                           "uid": identity[3], "gid": identity[4]}
        if set(record) != set(expected_record) or record != expected_record:
            raise ValueError("stage size/hash/owner changed")
        if not test_only_allow_unenforced and stat.S_IMODE(identity[2]) != 0o600:
            raise ValueError("stage type/mode changed")
        captured[name] = data
    return seal, captured


def _validate_stage_documents(seal: dict[str, Any], captured: dict[str, bytes], stage_id: str,
                              expected_plan_sha256: str) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = json.loads(captured["media-plan.json"])
    _validate_plan(plan, expected_plan_sha256)
    manifest = json.loads(captured["stage-manifest.json"])
    manifest_keys = {"schema", "stage_id", "plan_sha256", "source_run_id", "source_seal_sha256",
                     "selection_policy_sha256", "transform_policy", "transform_policy_sha256",
                     "encoder_runtime", "encoder_runtime_sha256", "objects", "failures",
                     "publication_enabled", "production_writes"}
    if not isinstance(manifest, dict) or set(manifest) != manifest_keys or manifest["schema"] != STAGE_SCHEMA:
        raise ValueError("invalid stage manifest schema")
    if manifest["stage_id"] != stage_id or seal["stage_id"] != stage_id:
        raise ValueError("stage id binding mismatch")
    common = ("plan_sha256", "selection_policy_sha256", "transform_policy", "transform_policy_sha256",
              "encoder_runtime", "encoder_runtime_sha256")
    if any(manifest[k] != (expected_plan_sha256 if k == "plan_sha256" else plan[k]) or
           seal[k] != (expected_plan_sha256 if k == "plan_sha256" else plan[k]) for k in common):
        raise ValueError("stage policy/runtime binding mismatch")
    if manifest["source_run_id"] != plan["source_run_id"] or manifest["source_seal_sha256"] != plan["source_seal_sha256"]:
        raise ValueError("stage source binding mismatch")
    if manifest["publication_enabled"] is not False or manifest["production_writes"] != 0:
        raise ValueError("unsafe stage manifest")
    _validate_outcomes(plan, manifest["objects"], manifest["failures"], captured=captured, final=False)
    return plan, manifest


def _positive_int(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value > 0


def _phash_bytes(data: bytes) -> str:
    with Image.open(io.BytesIO(data)) as image:
        gray = image.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
        pixels = list(gray.get_flattened_data())
    average = sum(pixels) / len(pixels)
    return f"{sum((pixel >= average) << i for i, pixel in enumerate(pixels)):016x}"


def _validate_outcomes(plan: dict[str, Any], objects: Any, failures: Any, *,
                       captured: dict[str, bytes] | None, final: bool) -> None:
    if not isinstance(objects, list) or not isinstance(failures, list):
        raise TypeError("invalid outcome collections")
    if len(objects) + len(failures) != len(plan["fetches"]):
        raise ValueError("stage outcome cardinality mismatch")
    seen_indexes: set[int] = set()
    seen_paths: set[str] = set()
    prior_hashes: list[str] = []
    object_keys = {"fetch_index", "source_url", "binding", "source", "transform", "output", "stage_path",
                   "perceptual_hash", "similarity_evidence"} | ({"cas_path", "cas_created"} if final else set())
    for obj in objects:
        if not isinstance(obj, dict) or set(obj) != object_keys:
            raise ValueError("invalid object schema")
        index = obj["fetch_index"]
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(plan["fetches"]) or index in seen_indexes:
            raise ValueError("invalid or duplicate fetch index")
        planned = plan["fetches"][index]
        binding = {k: planned[k] for k in ("supplier_item_id", "catalog_sku", "slot", "role")}
        if obj["source_url"] != planned["url"] or obj["binding"] != binding or set(obj["binding"]) != set(binding):
            raise ValueError("object plan binding mismatch")
        source = obj["source"]
        if not isinstance(source, dict) or set(source) != {"format", "content_type", "width", "height", "size_bytes", "sha256"}:
            raise ValueError("invalid source schema")
        if source["format"] not in {"jpeg", "png", "webp"} or source["content_type"] != f"image/{source['format']}" or not all(_positive_int(source[k]) for k in ("width", "height", "size_bytes")):
            raise ValueError("invalid source evidence")
        _require_sha(source["sha256"], "source digest")
        output = obj["output"]
        original = plan["transform_policy"]["format"] == "source"
        expected_output_format = source["format"] if original else "webp"
        if not isinstance(output, dict) or set(output) != {"format", "width", "height", "size_bytes", "sha256"} or output["format"] != expected_output_format or not all(_positive_int(output[k]) for k in ("width", "height", "size_bytes")):
            raise ValueError("invalid output schema")
        _require_sha(output["sha256"], "output digest")
        role = planned["role"]
        expected_transform = dict(plan["transform_policy"])
        maximum = None
        if not original:
            maximum = plan["transform_policy"]["hero_max_edge" if role == "hero" else "gallery_max_edge"]
            expected_transform["max_edge"] = maximum
        if obj["transform"] != expected_transform or set(obj["transform"]) != set(expected_transform):
            raise ValueError("object transform binding mismatch")
        if (maximum is not None and max(output["width"], output["height"]) > maximum) or max(output["width"], output["height"]) > max(source["width"], source["height"]):
            raise ValueError("output dimension policy mismatch")
        expected_path = f"objects/{index:06d}-{output['sha256']}.{_image_extension(output['format'])}"
        if obj["stage_path"] != expected_path or expected_path in seen_paths:
            raise ValueError("stage path binding mismatch")
        seen_paths.add(expected_path)
        phash = obj["perceptual_hash"]
        if not isinstance(phash, str) or re.fullmatch(r"[0-9a-f]{16}", phash) is None:
            raise ValueError("invalid perceptual hash")
        if captured is not None:
            if expected_path not in captured:
                raise ValueError("staged object missing")
            data = captured[expected_path]
            if len(data) != output["size_bytes"] or _digest(data) != output["sha256"] or _phash_bytes(data) != phash:
                raise ValueError("output bytes/evidence mismatch")
            if original and (output != {key: source[key] for key in ("format", "width", "height", "size_bytes", "sha256")}):
                raise ValueError("original output/source binding mismatch")
            with Image.open(io.BytesIO(data)) as image:
                expected_pillow_format = {"jpeg": "JPEG", "png": "PNG", "webp": "WEBP"}[output["format"]]
                if image.format != expected_pillow_format or image.size != (output["width"], output["height"]):
                    raise ValueError("output image/dimension binding mismatch")
        evidence = obj["similarity_evidence"]
        expected_similarity = [{"object_index": i, "hamming_distance": (int(phash, 16) ^ int(old, 16)).bit_count()}
                               for i, old in enumerate(prior_hashes)]
        if evidence != expected_similarity or any(not isinstance(x, dict) or set(x) != {"object_index", "hamming_distance"} for x in evidence):
            raise ValueError("invalid similarity evidence")
        if final:
            _canonical_cas_parts(obj["cas_path"], output["sha256"], output["format"])
            if not isinstance(obj["cas_created"], bool):
                raise ValueError("cas_created must be bool")
        prior_hashes.append(phash)
        seen_indexes.add(index)
    failure_keys = {"fetch_index", "source_url", "binding", "error_type", "error"}
    for failure in failures:
        if not isinstance(failure, dict) or set(failure) != failure_keys:
            raise ValueError("invalid failure schema")
        index = failure["fetch_index"]
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(plan["fetches"]) or index in seen_indexes:
            raise ValueError("invalid or duplicate failure index")
        planned = plan["fetches"][index]
        if failure["source_url"] != planned["url"] or failure["binding"] != planned or not all(isinstance(failure[k], str) and failure[k] for k in ("error_type", "error")):
            raise ValueError("failure plan/evidence binding mismatch")
        seen_indexes.add(index)
    if seen_indexes != set(range(len(plan["fetches"]))):
        raise ValueError("outcome index set incomplete")


def _linkat_empty(fd: int, bucket_fd: int, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, "linkat", None)
    if fn is None or fn(fd, b"", bucket_fd, os.fsencode(target), AT_EMPTY_PATH):
        err = ctypes.get_errno()
        if err == 17:
            raise FileExistsError(target)
        raise OSError(err, os.strerror(err))


def _verify_cas_fd(bucket_fd: int, name: str, data: bytes, digest: str, *, test_only_allow_unenforced: bool) -> tuple[tuple[int, ...], bytes]:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY, dir_fd=bucket_fd)
    try:
        identity, existing = _snapshot_file(fd, len(data))
        if stat.S_IMODE(identity[2]) != 0o400 or identity[3] != (os.geteuid() if test_only_allow_unenforced else 0):
            raise ValueError("CAS owner/mode mismatch")
        if existing != data or _digest(existing) != digest:
            raise ValueError("CAS collision")
        if not test_only_allow_unenforced and not _flags(fd) & FS_IMMUTABLE_FL:
            raise ValueError("CAS immutable flag missing")
        return identity, existing
    finally:
        os.close(fd)


def _install_cas(root: Path, data: bytes, digest: str, *, extension: str, test_only_allow_unenforced: bool) -> tuple[Path, bool]:
    _require_sha(digest, "CAS digest")
    target = root / "cas" / digest[:2] / f"{digest}.{_image_extension(extension)}"
    if test_only_allow_unenforced and os.name == "nt":
        try:
            _write_exclusive(target, data, 0o400)
            return target, True
        except FileExistsError:
            fd = os.open(target, os.O_RDONLY | _BINARY)
            try:
                _, existing = _snapshot_file(fd, len(data))
                if existing != data or _digest(existing) != digest:
                    raise ValueError("CAS collision")
            finally:
                os.close(fd)
            return target, False
    bucket_fd = _open_dir(target.parent)
    try:
        try:
            _verify_cas_fd(bucket_fd, target.name, data, digest, test_only_allow_unenforced=test_only_allow_unenforced)
            return target, False
        except FileNotFoundError:
            pass
        if test_only_allow_unenforced:
            try:
                fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o400, dir_fd=bucket_fd)
                try:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, 0o400)
                    _write_fd(fd, data)
                finally:
                    os.close(fd)
                created = True
            except FileExistsError:
                created = False
            _verify_cas_fd(bucket_fd, target.name, data, digest, test_only_allow_unenforced=True)
            os.fsync(bucket_fd)
            return target, created
        if not sys.platform.startswith("linux") or not hasattr(os, "O_TMPFILE"):
            raise RuntimeError("O_TMPFILE CAS publication is required")
        fd = os.open(".", os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=bucket_fd)
        try:
            _write_fd(fd, data)
            os.fchmod(fd, 0o400)
            os.fchown(fd, 0, 0)
            try:
                _linkat_empty(fd, bucket_fd, target.name)
                created = True
            except FileExistsError:
                created = False
            published = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bucket_fd)
            try:
                if created:
                    _set_flag(published, FS_IMMUTABLE_FL)
            finally:
                os.close(published)
            _verify_cas_fd(bucket_fd, target.name, data, digest, test_only_allow_unenforced=False)
            os.fsync(bucket_fd)
            return target, created
        finally:
            os.close(fd)
    finally:
        os.close(bucket_fd)


def _rename_noreplace(source: Path, destination: Path, *, test_only_allow_unenforced: bool) -> None:
    if test_only_allow_unenforced:
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination.name)
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, "renameat2", None)
    if fn is None or fn(-100, os.fsencode(source), -100, os.fsencode(destination), RENAME_NOREPLACE):
        err = ctypes.get_errno()
        if err == 17:
            raise FileExistsError(destination.name)
        raise OSError(err, os.strerror(err))


def finalize_media_stage(*, media_root: str | Path, stage_id: str, media_run_id: str,
                         expected_stage_seal_sha256: str, expected_plan_sha256: str,
                         writer_uid: int | None = None, writer_gid: int | None = None,
                         test_only_allow_unenforced: bool = False) -> dict[str, Any]:
    _require_id(stage_id, "stage id")
    _require_id(media_run_id, "media run id")
    _require_sha(expected_plan_sha256, "plan SHA-256")
    root = Path(media_root)
    storage = _storage_metadata(root)
    if writer_uid is not None and writer_uid != storage["writer_uid"] or writer_gid is not None and writer_gid != storage["writer_gid"]:
        raise ValueError("writer identity policy mismatch")
    if not test_only_allow_unenforced and (not sys.platform.startswith("linux") or os.geteuid() != 0):
        raise PermissionError("finalize requires Linux root")
    stage = root / "staging" / stage_id
    operation = root / "finalizing" / f".{media_run_id}.{uuid4().hex}"
    run = root / "runs" / media_run_id
    with _kernel_lock(root / "locks" / f"{media_run_id}.lock"):
        if run.exists() or run.is_symlink():
            raise FileExistsError(media_run_id)
        seal, captured = _capture_stage(
            stage, expected_stage_seal_sha256,
            test_only_allow_unenforced=test_only_allow_unenforced,
        )
        plan, manifest = _validate_stage_documents(seal, captured, stage_id, expected_plan_sha256)
        operation.mkdir(mode=0o700)
        try:
            final_objects = []
            for obj in manifest["objects"]:
                data = captured[obj["stage_path"]]
                digest = obj["output"]["sha256"]
                if _digest(data) != digest or len(data) != obj["output"]["size_bytes"]:
                    raise ValueError("transformed object binding mismatch")
                cas_path, created = _install_cas(root, data, digest, extension=obj["output"]["format"], test_only_allow_unenforced=test_only_allow_unenforced)
                final_objects.append(obj | {"cas_path": cas_path.relative_to(root).as_posix(), "cas_created": created})
            final_manifest = {"schema": FINAL_SCHEMA, "media_run_id": media_run_id, "stage_id": stage_id,
                              "stage_seal_sha256": expected_stage_seal_sha256, "plan_sha256": expected_plan_sha256,
                              "source_run_id": plan["source_run_id"], "source_seal_sha256": plan["source_seal_sha256"],
                              "selection_policy_sha256": plan["selection_policy_sha256"], "transform_policy": plan["transform_policy"],
                              "transform_policy_sha256": plan["transform_policy_sha256"], "encoder_runtime": plan["encoder_runtime"],
                              "encoder_runtime_sha256": plan["encoder_runtime_sha256"],
                              "objects": final_objects, "failures": manifest["failures"], "publication_enabled": False, "production_writes": 0}
            payloads = {"media-plan.json": captured["media-plan.json"], "media-manifest.json": _canonical(final_manifest)}
            records = {}
            for name, data in payloads.items():
                _write_exclusive(operation / name, data, 0o400)
                records[name] = {"size": len(data), "sha256": _digest(data), "mode": "0400",
                                 "owner_uid": 0, "owner_gid": 0, "immutable": True}
            final_seal = {"schema": FINAL_SCHEMA, "media_run_id": media_run_id, "stage_seal_sha256": expected_stage_seal_sha256,
                          "stage_id": stage_id, "source_run_id": plan["source_run_id"],
                          "source_seal_sha256": plan["source_seal_sha256"],
                          "plan_sha256": expected_plan_sha256, "selection_policy_sha256": plan["selection_policy_sha256"],
                          "transform_policy": plan["transform_policy"], "files": records,
                          "transform_policy_sha256": plan["transform_policy_sha256"], "encoder_runtime": plan["encoder_runtime"],
                          "encoder_runtime_sha256": plan["encoder_runtime_sha256"],
                          "publication_enabled": False, "production_writes": 0}
            seal_bytes = _canonical(final_seal)
            _write_exclusive(operation / "media-seal.json", seal_bytes, 0o400)
            if not test_only_allow_unenforced:
                for path in operation.iterdir():
                    fd = os.open(path, os.O_RDONLY | _BINARY)
                    try:
                        os.fchown(fd, 0, 0)
                        _set_flag(fd, FS_IMMUTABLE_FL)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.chmod(operation, 0o500)
                opfd = _open_dir(operation)
                try:
                    os.fchown(opfd, 0, 0)
                    _set_flag(opfd, FS_IMMUTABLE_FL)
                    os.fsync(opfd)
                finally:
                    os.close(opfd)
            _rename_noreplace(operation, run, test_only_allow_unenforced=test_only_allow_unenforced)
            if not (test_only_allow_unenforced and os.name == "nt"):
                runsfd = _open_dir(root / "runs")
                try:
                    os.fsync(runsfd)
                finally:
                    os.close(runsfd)

            return {"run_dir": str(run), "media_run_id": media_run_id, "media_seal_sha256": _digest(seal_bytes),
                    "publication_enabled": False, "production_writes": 0}
        except BaseException:
            if operation.exists():
                shutil.rmtree(operation, ignore_errors=True)
            raise


def _capture_final_fd(run_fd: int, expected_seal: str, *, test_only_allow_unenforced: bool) -> tuple[dict[str, Any], dict[str, bytes]]:
    expected_names = {"media-plan.json", "media-manifest.json", "media-seal.json"}
    if set(os.listdir(run_fd)) != expected_names:
        raise ValueError("final run set changed")
    captured: dict[str, bytes] = {}
    for name in sorted(expected_names):
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | _BINARY, dir_fd=run_fd)
        try:
            identity, captured[name] = _snapshot_file(fd, 256 * 1024 * 1024)
            if stat.S_IMODE(identity[2]) != 0o400:
                raise ValueError("final evidence mode changed")
            if not test_only_allow_unenforced and (identity[3] != 0 or not _flags(fd) & FS_IMMUTABLE_FL):
                raise ValueError("final evidence owner/flag changed")
        finally:
            os.close(fd)
    if _digest(captured["media-seal.json"]) != expected_seal:
        raise ValueError("final seal digest mismatch")
    seal = json.loads(captured["media-seal.json"])
    seal_keys = {"schema", "media_run_id", "stage_id", "stage_seal_sha256", "source_run_id", "source_seal_sha256", "plan_sha256",
                 "selection_policy_sha256", "transform_policy", "transform_policy_sha256",
                 "encoder_runtime", "encoder_runtime_sha256", "files", "publication_enabled", "production_writes"}
    if not isinstance(seal, dict) or set(seal) != seal_keys or seal["schema"] != FINAL_SCHEMA:
        raise ValueError("invalid final seal schema")
    if set(seal["files"]) != {"media-plan.json", "media-manifest.json"}:
        raise ValueError("invalid final seal file set")
    for name, record in seal["files"].items():
        expected = {"size": len(captured[name]), "sha256": _digest(captured[name]), "mode": "0400",
                    "owner_uid": 0, "owner_gid": 0, "immutable": True}
        if set(record) != set(expected) or record != expected:
            raise ValueError("final evidence hash/size changed")
    return seal, captured


def _canonical_cas_parts(value: Any, digest: str, image_format: str) -> tuple[str, str]:
    expected = f"cas/{digest[:2]}/{digest}.{_image_extension(image_format)}"
    if not isinstance(value, str) or value != expected or value.startswith("/") or "\\" in value or ".." in value.split("/"):
        raise ValueError("noncanonical CAS path")
    return digest[:2], f"{digest}.{_image_extension(image_format)}"


def _capture_cas(root: Path, manifest: dict[str, Any], *, test_only_allow_unenforced: bool) -> dict[str, tuple[tuple[int, ...], bytes]]:
    result = {}
    for obj in manifest["objects"]:
        digest = obj["output"]["sha256"]
        _require_sha(digest, "object digest")
        bucket, name = _canonical_cas_parts(obj.get("cas_path"), digest, obj["output"]["format"])
        if test_only_allow_unenforced and os.name == "nt":
            fd = os.open(root / "cas" / bucket / name, os.O_RDONLY | _BINARY)
            try:
                identity, data = _snapshot_file(fd, obj["output"]["size_bytes"])
            finally:
                os.close(fd)
        else:
            cas_fd = _open_dir(root / "cas")
            try:
                bucket_fd = os.open(bucket, _DIR_FLAGS, dir_fd=cas_fd)
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | _BINARY, dir_fd=bucket_fd)
                    try:
                        identity, data = _snapshot_file(fd, obj["output"]["size_bytes"])
                        if not test_only_allow_unenforced and not _flags(fd) & FS_IMMUTABLE_FL:
                            raise ValueError("CAS immutable flag missing")
                    finally:
                        os.close(fd)
                finally:
                    os.close(bucket_fd)
            finally:
                os.close(cas_fd)
        if not (test_only_allow_unenforced and os.name == "nt") and (
            stat.S_IMODE(identity[2]) != 0o400 or (not test_only_allow_unenforced and identity[3] != 0)
        ):
            raise ValueError("CAS owner/mode changed")
        if len(data) != obj["output"]["size_bytes"] or _digest(data) != digest:
            raise ValueError("CAS bytes changed")
        result[obj["cas_path"]] = (identity, data)
    return result


def verify_media_run(media_root: str | Path, media_run_id: str, expected_final_seal_sha256: str, *,
                     source_run_dir: str | Path, expected_source_seal_sha256: str | None = None,
                     test_only_allow_unenforced: bool = False,
                     between_reads: Any | None = None) -> dict[str, Any]:
    _require_id(media_run_id, "media run id")
    _require_sha(expected_final_seal_sha256, "final seal SHA-256")
    root = Path(media_root)
    run_path = root / "runs" / media_run_id
    if test_only_allow_unenforced and os.name == "nt":
        def capture() -> tuple[dict[str, Any], dict[str, bytes]]:
            names = {p.name for p in run_path.iterdir()}
            if names != {"media-plan.json", "media-manifest.json", "media-seal.json"}:
                raise ValueError("final run set changed")
            values = {}
            for name in names:
                fd = os.open(run_path / name, os.O_RDONLY | _BINARY)
                try:
                    _, values[name] = _snapshot_file(fd, 256 * 1024 * 1024)
                finally:
                    os.close(fd)
            seal = json.loads(values["media-seal.json"])
            if _digest(values["media-seal.json"]) != expected_final_seal_sha256:
                raise ValueError("final seal digest mismatch")
            return seal, values
        first_seal, first = capture()
        manifest = json.loads(first["media-manifest.json"])
        first_cas = _capture_cas(root, manifest, test_only_allow_unenforced=True)
        if between_reads is not None:
            between_reads()
        second_seal, second = capture()
    else:
        runs_fd = _open_dir(root / "runs")
        try:
            run_fd = os.open(media_run_id, _DIR_FLAGS, dir_fd=runs_fd)
            try:
                stable = os.fstat(run_fd)
                if not test_only_allow_unenforced and (stable.st_uid != 0 or stat.S_IMODE(stable.st_mode) != 0o500 or not _flags(run_fd) & FS_IMMUTABLE_FL):
                    raise ValueError("run directory owner/mode/flag changed")
                first_seal, first = _capture_final_fd(run_fd, expected_final_seal_sha256, test_only_allow_unenforced=test_only_allow_unenforced)
                manifest = json.loads(first["media-manifest.json"])
                first_cas = _capture_cas(root, manifest, test_only_allow_unenforced=test_only_allow_unenforced)
                if between_reads is not None:
                    between_reads()
                second_seal, second = _capture_final_fd(run_fd, expected_final_seal_sha256, test_only_allow_unenforced=test_only_allow_unenforced)
                now = os.fstat(run_fd)
                if (stable.st_dev, stable.st_ino) != (now.st_dev, now.st_ino):
                    raise ValueError("run directory identity changed")
            finally:
                os.close(run_fd)
        finally:
            os.close(runs_fd)
    if first != second or first_seal != second_seal:
        raise ValueError("final run mutated between reads")
    second_manifest = json.loads(second["media-manifest.json"])
    second_cas = _capture_cas(root, second_manifest, test_only_allow_unenforced=test_only_allow_unenforced)
    if first_cas != second_cas:
        raise ValueError("CAS mutated between reads")
    plan = json.loads(first["media-plan.json"])
    manifest = json.loads(first["media-manifest.json"])
    plan_sha = _digest(first["media-plan.json"])
    _validate_plan(plan, plan_sha)
    manifest_keys = {"schema", "media_run_id", "stage_id", "stage_seal_sha256", "plan_sha256",
                     "source_run_id", "source_seal_sha256", "selection_policy_sha256", "transform_policy",
                     "transform_policy_sha256", "encoder_runtime", "encoder_runtime_sha256", "objects",
                     "failures", "publication_enabled", "production_writes"}
    if not isinstance(manifest, dict) or set(manifest) != manifest_keys or manifest["schema"] != FINAL_SCHEMA:
        raise ValueError("invalid final manifest schema")
    final_captured = {obj["stage_path"]: first_cas[obj["cas_path"]][1] for obj in manifest["objects"]}
    _validate_outcomes(plan, manifest["objects"], manifest["failures"], captured=final_captured, final=True)
    if manifest["media_run_id"] != media_run_id or first_seal["media_run_id"] != media_run_id:
        raise ValueError("final run id binding mismatch")
    if first_seal["stage_id"] != manifest["stage_id"] or first_seal["stage_seal_sha256"] != manifest["stage_seal_sha256"]:
        raise ValueError("final stage binding mismatch")
    sealed, source_manifest, _ = _sealed_source(Path(source_run_dir))
    pinned_source = expected_source_seal_sha256 or plan["source_seal_sha256"]
    if sealed.seal_evidence.sha256 != pinned_source or plan["source_seal_sha256"] != pinned_source or manifest["source_seal_sha256"] != pinned_source or manifest["source_run_id"] != source_manifest["run_id"]:
        raise ValueError("source binding mismatch")
    policy = canonical_selection_policy(plan["selection_policy"])
    bindings = ("selection_policy_sha256", "transform_policy", "transform_policy_sha256", "encoder_runtime", "encoder_runtime_sha256")
    if plan_sha != first_seal["plan_sha256"] or plan_sha != manifest["plan_sha256"] or any(first_seal[k] != plan[k] or manifest[k] != plan[k] for k in bindings):
        raise ValueError("plan/policy/runtime binding mismatch")
    if _digest(_canonical(policy)) != plan["selection_policy_sha256"] or _digest(_canonical(policy["transform"])) != plan["transform_policy_sha256"]:
        raise ValueError("policy digest mismatch")
    runtime = encoder_runtime_identity()
    if runtime != plan["encoder_runtime"] or _digest(_canonical(runtime)) != plan["encoder_runtime_sha256"]:
        raise ValueError("encoder runtime changed")
    if any(v.get("publication_enabled") is not False or v.get("production_writes") != 0 for v in (plan, manifest, first_seal)):
        raise ValueError("publication safety binding changed")
    return {"verified": True, "media_run_id": media_run_id, "media_seal_sha256": expected_final_seal_sha256,
            "publication_enabled": False, "production_writes": 0}
