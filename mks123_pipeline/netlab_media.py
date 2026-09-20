from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from PIL import Image, ImageOps, UnidentifiedImageError, features
from PIL import __version__ as PILLOW_VERSION

from .integrity import (
    Evidence,
    SealedRunEvidence,
    _canonical_path_from_fd,
    _close_parent_handles,
    _file_identity,
    _open_non_following,
    load_sealed_run,
    read_evidence,
)
from .netlab_content import _safe_image_url

STORAGE_ROOT = Path("/var/lib/mks123-netlab-media")
MAX_COMPRESSED_BYTES = 5 * 1024 * 1024
MAX_WIDTH = 6000
MAX_HEIGHT = 6000
MAX_PIXELS = 16_000_000
PLAN_SCHEMA = "netlab-media-plan-v2"
STAGE_SCHEMA = "netlab-media-stage-v2"
FINAL_SCHEMA = "netlab-media-final-v2"
POLICY_SCHEMA = "netlab-media-selection-policy-v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAX_NORMALIZED_BYTES = 2 * 1024 * 1024 * 1024
MAX_NORMALIZED_LINE_BYTES = 16 * 1024 * 1024


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


def encoder_runtime_identity() -> dict[str, str]:
    webp = features.version("webp")
    if not isinstance(webp, str) or not webp:
        raise RuntimeError("Pillow WebP runtime is unavailable")
    return {"pillow_version": PILLOW_VERSION, "libwebp_version": webp}


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), mode)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, mode)


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def _open_dir(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    fd = os.open(os.sep, _DIR_FLAGS)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_at(dir_fd: int | None, directory: Path, name: str, data: bytes, mode: int) -> tuple[int, ...]:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ValueError("noncanonical stage filename")
    fd = os.open(directory / name, _FILE_FLAGS, mode) if dir_fd is None else os.open(name, _FILE_FLAGS, mode, dir_fd=dir_fd)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(data) or
                (os.name != "nt" and stat.S_IMODE(info.st_mode) != mode)):
            raise ValueError("invalid staged file identity/type/mode/link/size")
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size)
    finally:
        os.close(fd)


def _read_at(dir_fd: int | None, directory: Path, name: str) -> tuple[tuple[int, ...], bytes]:
    fd = os.open(directory / name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)) if dir_fd is None else os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("invalid staged file")
        data = bytearray()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size)
        if identity != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_nlink, after.st_size) or len(data) != info.st_size:
            raise ValueError("staged file mutated")
        return identity, bytes(data)
    finally:
        os.close(fd)


def _require_sha(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"invalid {label}")


def _require_id(value: str, label: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")


def _storage_metadata(root: Path) -> dict[str, Any]:
    value = json.loads((root / "storage.json").read_text("utf-8"))
    if set(value) != {"schema", "writer_uid", "writer_gid"} or value["schema"] != "netlab-media-storage-v1":
        raise ValueError("invalid storage metadata")
    if any(isinstance(value[k], bool) or not isinstance(value[k], int) or value[k] < 1 for k in ("writer_uid", "writer_gid")):
        raise ValueError("invalid storage writer identity")
    return value


def _safe_media_url(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("https://nlimg.netlab.ru/"):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.netloc == "nlimg.netlab.ru" and _safe_image_url(value)


def canonical_selection_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise TypeError("selection policy must be an object")
    allowed = {"schema", "eligible_catalog_skus", "eligible_supplier_item_ids", "max_images_per_item", "transform"}
    if set(policy) - allowed:
        raise ValueError("selection policy has unknown fields")
    skus = policy.get("eligible_catalog_skus", [])
    item_ids = policy.get("eligible_supplier_item_ids", [])
    if not isinstance(skus, list) or not isinstance(item_ids, list):
        raise TypeError("eligibility lists are required")
    if not skus and not item_ids:
        raise ValueError("selection policy must explicitly select at least one item")
    for values, label in ((skus, "catalog SKU"), (item_ids, "supplier item id")):
        if any(not isinstance(v, str) or not v for v in values) or len(values) != len(set(values)):
            raise ValueError(f"invalid or duplicate {label}")
    count = policy.get("max_images_per_item")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 3:
        raise ValueError("max_images_per_item must be from 1 through 3")
    transform = policy.get("transform")
    if not isinstance(transform, dict):
        raise TypeError("explicit transform policy is required")
    expected_transform = {
        "format": "webp", "quality": 84, "hero_max_edge": 1600,
        "gallery_max_edge": 1200, "no_upscale": True, "strip_metadata": True,
    }
    original_transform = {"format": "source", "preserve_original": True}
    if transform not in (expected_transform, original_transform):
        raise ValueError("unsupported transform policy")
    selected_transform = original_transform if transform == original_transform else expected_transform
    return {"schema": POLICY_SCHEMA, "eligible_catalog_skus": sorted(skus),
            "eligible_supplier_item_ids": sorted(item_ids), "max_images_per_item": count,
            "transform": selected_transform}


def _sealed_source(run_dir: Path) -> tuple[SealedRunEvidence, dict[str, Any], Path]:
    sealed = load_sealed_run(run_dir, read_content=False)
    manifest_ev = read_evidence(run_dir / "run-manifest.json", max_bytes=8 * 1024 * 1024)
    normalized_path = run_dir / "normalized/items.jsonl"
    normalized_record = sealed.files.get("normalized/items.jsonl")
    if normalized_record is None:
        raise ValueError("sealed source has no normalized items")
    if normalized_record.size is None or normalized_record.size > MAX_NORMALIZED_BYTES:
        raise ValueError("normalized items exceed byte limit")
    expected_manifest = sealed.files.get("run-manifest.json")
    if expected_manifest is None or manifest_ev.sha256 != expected_manifest.sha256 or manifest_ev.file_identity != expected_manifest.file_identity:
        raise ValueError("sealed source changed: run-manifest.json")
    manifest = json.loads(manifest_ev.data)
    if manifest.get("supplier") != "netlab":
        raise ValueError("source must be a sealed unpublished Netlab run")
    summary = manifest.get("summary") if isinstance(manifest.get("summary"), dict) else {}
    production_writes = summary.get("production_writes", manifest.get("production_writes"))
    publication_enabled = summary.get("publication_enabled", manifest.get("publication_enabled"))
    mode = summary.get("mode", manifest.get("mode"))
    if production_writes != 0 or (publication_enabled is not None and publication_enabled is not False) or mode not in (None, "read_only"):
        raise ValueError("source must be a sealed unpublished Netlab run")
    if production_writes is None and publication_enabled is None and mode is None:
        raise ValueError("source must declare read-only state")
    return sealed, manifest, normalized_path


def _iter_normalized_rows(path: Path, expected: Evidence):
    opened = _open_non_following(path)
    if isinstance(opened, tuple):
        fd, parent_handles = opened
    else:
        fd, parent_handles = opened, []
    try:
        opened_canonical_path = _canonical_path_from_fd(fd)
        if opened_canonical_path != expected.canonical_path:
            raise ValueError("normalized items canonical path changed")
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _file_identity(before) != expected.file_identity:
            raise ValueError("normalized items identity changed before read")
        if before.st_size > MAX_NORMALIZED_BYTES:
            raise ValueError("normalized items exceed byte limit")
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            for line_no, line in enumerate(handle, 1):
                total += len(line)
                if total > MAX_NORMALIZED_BYTES:
                    raise ValueError("normalized items exceed byte limit")
                if len(line) > MAX_NORMALIZED_LINE_BYTES:
                    raise ValueError(f"normalized row exceeds byte limit: {line_no}")
                digest.update(line)
                try:
                    row = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"invalid normalized JSONL row: {line_no}") from exc
                if not isinstance(row, dict):
                    raise TypeError(f"normalized row is not an object: {line_no}")
                yield line_no, row
            after = os.fstat(handle.fileno())
        if (_file_identity(after) != expected.file_identity or total != before.st_size or
                digest.hexdigest() != expected.sha256):
            raise ValueError("normalized items changed while reading")
    finally:
        if fd is not None:
            os.close(fd)
        _close_parent_handles(parent_handles)


def build_media_plan(run_dir: str | Path, selection_policy: dict[str, Any], *,
                     expected_source_seal_sha256: str | None = None,
                     max_items: int = 1_000_000, max_urls: int = 3_000_000) -> dict[str, Any]:
    canonical_policy = canonical_selection_policy(selection_policy)
    policy_sha = _digest(_canonical(canonical_policy))
    transform_sha = _digest(_canonical(canonical_policy["transform"]))
    runtime = encoder_runtime_identity()
    sealed, manifest, normalized_path = _sealed_source(Path(run_dir))
    if expected_source_seal_sha256 is not None and sealed.seal_evidence.sha256 != expected_source_seal_sha256:
        raise ValueError("source seal digest mismatch")
    selected: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    sku_set = set(canonical_policy["eligible_catalog_skus"])
    id_set = set(canonical_policy["eligible_supplier_item_ids"])
    normalized_record = sealed.files["normalized/items.jsonl"]
    for line_no, row in _iter_normalized_rows(normalized_path, normalized_record):
        if line_no > max_items:
            raise ValueError("source item limit exceeded")
        if row.get("supplier") != "netlab":
            raise ValueError(f"invalid normalized row {line_no}")
        sku, item_id, urls = row.get("catalog_sku"), row.get("supplier_item_id"), row.get("image_urls")
        if not isinstance(sku, str) or not isinstance(item_id, str) or not isinstance(urls, list):
            raise TypeError(f"invalid media row {line_no}")
        if sku not in sku_set and item_id not in id_set:
            continue
        for slot, url in enumerate(urls[: canonical_policy["max_images_per_item"]]):
            if not _safe_media_url(url):
                raise ValueError(f"unsafe media URL in row {line_no}")
            if url in seen_urls:
                raise ValueError("selected image URL is duplicated across bindings")
            seen_urls.add(url)
            selected.append({"url": url, "supplier_item_id": item_id, "catalog_sku": sku,
                             "slot": slot, "role": "hero" if slot == 0 else "gallery"})
    if not selected:
        raise ValueError("selection policy selected no images")
    if len(selected) > max_urls:
        raise ValueError("selected URL limit exceeded")
    selected.sort(key=lambda x: (x["catalog_sku"], x["supplier_item_id"], x["slot"], x["url"]))
    return {"schema": PLAN_SCHEMA, "source_run_id": manifest["run_id"],
            "source_seal_sha256": sealed.seal_evidence.sha256, "selection_policy": canonical_policy,
            "selection_policy_sha256": policy_sha, "transform_policy": canonical_policy["transform"],
            "transform_policy_sha256": transform_sha, "encoder_runtime": runtime,
            "encoder_runtime_sha256": _digest(_canonical(runtime)),
            "fetches": selected, "counts": {"selected_images": len(selected)},
            "publication_enabled": False, "production_writes": 0}


def validate_image(data: bytes, *, content_type: str, max_bytes: int = MAX_COMPRESSED_BYTES,
                   max_width: int = MAX_WIDTH, max_height: int = MAX_HEIGHT,
                   max_pixels: int = MAX_PIXELS) -> dict[str, Any]:
    if max_bytes > MAX_COMPRESSED_BYTES or not data or len(data) > max_bytes:
        raise ValueError("image compressed size exceeds limit")
    expected = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}.get(content_type)
    if expected is None:
        raise ValueError("image content type is not allowed")
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format != expected:
                raise ValueError("image format does not match content type")
            if getattr(image, "n_frames", 1) != 1:
                raise ValueError("animated images are forbidden")
            width, height = image.size
            if width < 1 or height < 1 or width > min(max_width, MAX_WIDTH) or height > min(max_height, MAX_HEIGHT) or width * height > min(max_pixels, MAX_PIXELS):
                raise ValueError("image dimensions exceed pre-decode limits")
            image.verify()
        with Image.open(io.BytesIO(data)) as image:
            image.load()
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise ValueError("invalid image") from exc
    return {"format": expected.lower(), "content_type": content_type, "width": width, "height": height,
            "size_bytes": len(data), "sha256": _digest(data)}


def _transform(data: bytes, role: str, policy: dict[str, Any], source: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if policy["format"] == "source":
        return data, {key: source[key] for key in ("format", "width", "height", "size_bytes", "sha256")}
    with Image.open(io.BytesIO(data)) as image:
        image.load()
        clean = ImageOps.exif_transpose(image).convert("RGB")
        max_edge = policy["hero_max_edge"] if role == "hero" else policy["gallery_max_edge"]
        if max(clean.size) > max_edge:
            clean.thumbnail((max_edge, max_edge), Image.Resampling.LANCZOS, reducing_gap=3.0)
        output = io.BytesIO()
        clean.save(output, "WEBP", quality=policy["quality"], method=6, exact=True, exif=b"", xmp=b"")
        payload = output.getvalue()
        return payload, {"format": "webp", "width": clean.width, "height": clean.height,
                         "size_bytes": len(payload), "sha256": _digest(payload)}


def _phash(data: bytes) -> str:
    with Image.open(io.BytesIO(data)) as image:
        gray = image.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
        pixels = list(gray.get_flattened_data())
    average = sum(pixels) / len(pixels)
    value = sum((pixel >= average) << index for index, pixel in enumerate(pixels))
    return f"{value:016x}"


def _hamming(a: str, b: str) -> int:
    return (int(a, 16) ^ int(b, 16)).bit_count()


def fetch_image(url: str, *, opener: Any | None = None, timeout_seconds: int = 15,
                max_bytes: int = MAX_COMPRESSED_BYTES, **_: Any) -> dict[str, Any]:
    if not _safe_media_url(url) or max_bytes != MAX_COMPRESSED_BYTES:
        raise ValueError("unsafe URL or noncanonical compressed limit")
    if opener is None:
        from urllib.request import (
            HTTPRedirectHandler,
            ProxyHandler,
            Request,
            build_opener,
        )
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
                return None
        opener = build_opener(ProxyHandler({}), NoRedirect())
        request = Request(url, method="GET", headers={"Accept": "image/jpeg,image/png,image/webp", "User-Agent": "mks123-netlab-media/2"})
    else:
        from urllib.request import Request
        request = Request(url, method="GET", headers={"Accept": "image/jpeg,image/png,image/webp", "User-Agent": "mks123-netlab-media/2"})
    with opener.open(request, timeout=timeout_seconds) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("non-200 response or redirect")
        content_type = response.headers.get("Content-Type")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdecimal() or not 0 < int(length) <= MAX_COMPRESSED_BYTES):
            raise ValueError("invalid image content length")
        data = response.read(MAX_COMPRESSED_BYTES + 1)
    metadata = validate_image(data, content_type=content_type)
    return {"data": data, "metadata": metadata}


def _validate_plan(plan: dict[str, Any], expected_sha: str) -> bytes:
    _require_sha(expected_sha, "plan SHA-256")
    payload = _canonical(plan)
    if _digest(payload) != expected_sha or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("plan digest/schema mismatch")
    keys = {"schema", "source_run_id", "source_seal_sha256", "selection_policy",
            "selection_policy_sha256", "transform_policy", "transform_policy_sha256",
            "encoder_runtime", "encoder_runtime_sha256", "fetches", "counts",
            "publication_enabled", "production_writes"}
    if set(plan) != keys or not isinstance(plan["fetches"], list):
        raise ValueError("invalid plan schema")
    policy = canonical_selection_policy(plan.get("selection_policy"))
    if policy != plan["selection_policy"] or _digest(_canonical(policy)) != plan.get("selection_policy_sha256") or plan.get("transform_policy") != policy["transform"]:
        raise ValueError("selection/transform policy binding mismatch")
    if plan.get("transform_policy_sha256") != _digest(_canonical(policy["transform"])):
        raise ValueError("transform policy digest mismatch")
    runtime = encoder_runtime_identity()
    if plan.get("encoder_runtime") != runtime or plan.get("encoder_runtime_sha256") != _digest(_canonical(runtime)):
        raise ValueError("encoder runtime binding mismatch")
    if plan.get("production_writes") != 0 or plan.get("publication_enabled") is not False or not plan.get("fetches"):
        raise ValueError("unsafe or empty plan")
    seen = set()
    for item in plan["fetches"]:
        if not isinstance(item, dict) or set(item) != {"url", "supplier_item_id", "catalog_sku", "slot", "role"}:
            raise ValueError("invalid planned fetch schema")
        if not _safe_media_url(item["url"]) or item["url"] in seen or item["role"] not in {"hero", "gallery"}:
            raise ValueError("invalid or duplicate planned fetch")
        if item["role"] != ("hero" if item["slot"] == 0 else "gallery"):
            raise ValueError("planned role binding mismatch")
        seen.add(item["url"])
    if plan["counts"] != {"selected_images": len(plan["fetches"])}:
        raise ValueError("plan count mismatch")
    return payload


def stage_media_plan(plan: dict[str, Any], *, media_root: str | Path, stage_id: str,
                     expected_plan_sha256: str, fetcher: Callable[..., dict[str, Any]] | None = None,
                     timeout_seconds: int = 15, test_only_allow_unenforced: bool = False) -> dict[str, Any]:
    _require_id(stage_id, "stage id")
    root = Path(media_root)
    metadata = _storage_metadata(root)
    if not test_only_allow_unenforced:
        if not sys.platform.startswith("linux") or os.geteuid() == 0:
            raise PermissionError("stage must run as the configured non-root writer")
        if os.geteuid() != metadata["writer_uid"] or os.getegid() != metadata["writer_gid"]:
            raise PermissionError("stage writer identity mismatch")
    plan_bytes = _validate_plan(plan, expected_plan_sha256)
    stage = root / "staging" / stage_id
    staging_fd: int | None = None
    root_fd: int | None = None
    stage_fd: int | None = None
    objects_fd: int | None = None
    if os.name == "nt":
        if not test_only_allow_unenforced:
            raise PermissionError("descriptor-rooted staging is unavailable on Windows")
        stage.mkdir(mode=0o700)
        os.chmod(stage, 0o700)
        (stage / "objects").mkdir(mode=0o700)
        stage_identity = (stage.stat(follow_symlinks=False).st_dev, stage.stat(follow_symlinks=False).st_ino)
    else:
        root_fd = _open_dir(root)
        staging_fd = os.open("staging", _DIR_FLAGS, dir_fd=root_fd)
        protected = []
        for name in ("cas", "runs"):
            fd = os.open(name, _DIR_FLAGS, dir_fd=root_fd)
            try:
                info = os.fstat(fd)
                protected.append((info.st_dev, info.st_ino))
            finally:
                os.close(fd)
        staging_info = os.fstat(staging_fd)
        if (staging_info.st_dev, staging_info.st_ino) in protected:
            raise ValueError("staging aliases protected storage")
        os.mkdir(stage_id, 0o700, dir_fd=staging_fd)
        stage_fd = os.open(stage_id, _DIR_FLAGS, dir_fd=staging_fd)
        os.fchmod(stage_fd, 0o700)
        stable = os.fstat(stage_fd)
        stage_identity = (stable.st_dev, stable.st_ino)
        os.mkdir("objects", 0o700, dir_fd=stage_fd)
        objects_fd = os.open("objects", _DIR_FLAGS, dir_fd=stage_fd)
        os.fchmod(objects_fd, 0o700)
    client = fetch_image if fetcher is None else fetcher
    objects: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    hashes: list[str] = []
    def assert_stage_path() -> None:
        try:
            info = os.stat(stage_id, dir_fd=staging_fd, follow_symlinks=False) if staging_fd is not None else stage.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ValueError("stage directory substituted") from exc
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != stage_identity:
            raise ValueError("stage directory substituted")
    try:
        for index, binding in enumerate(plan["fetches"]):
            try:
                fetched = client(binding["url"], timeout_seconds=timeout_seconds, max_bytes=MAX_COMPRESSED_BYTES,
                                 max_width=MAX_WIDTH, max_height=MAX_HEIGHT, max_pixels=MAX_PIXELS)
                original = fetched["data"]
                source = validate_image(original, content_type=fetched["metadata"]["content_type"])
                transformed, output = _transform(original, binding["role"], plan["transform_policy"], source)
                original = b""
                phash = _phash(transformed)
                name = f"objects/{index:06d}-{output['sha256']}.{_image_extension(output['format'])}"
                assert_stage_path()
                _write_at(objects_fd, stage / "objects", name.removeprefix("objects/"), transformed, 0o600)
                similarity = [{"object_index": i, "hamming_distance": _hamming(phash, previous)} for i, previous in enumerate(hashes)]
                hashes.append(phash)
                transform = dict(plan["transform_policy"])
                if transform["format"] == "webp":
                    transform["max_edge"] = transform["hero_max_edge"] if binding["role"] == "hero" else transform["gallery_max_edge"]
                objects.append({"fetch_index": index, "source_url": binding["url"], "binding": {k: binding[k] for k in ("supplier_item_id", "catalog_sku", "slot", "role")},
                                "source": source, "transform": transform,
                                "output": output, "stage_path": name, "perceptual_hash": phash, "similarity_evidence": similarity})
            except (ValueError, OSError, TimeoutError) as exc:
                failures.append({"fetch_index": index, "source_url": binding["url"], "binding": binding, "error_type": type(exc).__name__, "error": str(exc)})
        manifest = {"schema": STAGE_SCHEMA, "stage_id": stage_id, "plan_sha256": expected_plan_sha256,
                    "source_run_id": plan["source_run_id"], "source_seal_sha256": plan["source_seal_sha256"],
                    "selection_policy_sha256": plan["selection_policy_sha256"], "transform_policy": plan["transform_policy"],
                    "transform_policy_sha256": plan["transform_policy_sha256"], "encoder_runtime": plan["encoder_runtime"],
                    "encoder_runtime_sha256": plan["encoder_runtime_sha256"],
                    "objects": objects, "failures": failures, "publication_enabled": False, "production_writes": 0}
        payloads = {"media-plan.json": plan_bytes, "stage-manifest.json": _canonical(manifest)}
        for name, data in payloads.items():
            assert_stage_path()
            _write_at(stage_fd, stage, name, data, 0o600)
        file_records = {}
        for name in sorted(payloads):
            info, data = _read_at(stage_fd, stage, name)
            file_records[name] = {
                "size": len(data), "sha256": _digest(data), "mode": "0600",
                "uid": info[3], "gid": info[4],
            }
        object_names = sorted(os.listdir(objects_fd) if objects_fd is not None else os.listdir(stage / "objects"))
        for leaf in object_names:
            info, data = _read_at(objects_fd, stage / "objects", leaf)
            file_records[f"objects/{leaf}"] = {"size": len(data), "sha256": _digest(data), "mode": "0600",
                                                     "uid": info[3], "gid": info[4]}
        seal = {"schema": STAGE_SCHEMA, "stage_id": stage_id, "plan_sha256": expected_plan_sha256,
                "selection_policy_sha256": plan["selection_policy_sha256"], "transform_policy": plan["transform_policy"],
                "transform_policy_sha256": plan["transform_policy_sha256"], "encoder_runtime": plan["encoder_runtime"],
                "encoder_runtime_sha256": plan["encoder_runtime_sha256"],
                "files": file_records, "directories": [".", "objects"],
                "publication_enabled": False, "production_writes": 0}
        seal_bytes = _canonical(seal)
        assert_stage_path()
        _write_at(stage_fd, stage, "stage-seal.json", seal_bytes, 0o600)
        identity, readback = _read_at(stage_fd, stage, "stage-seal.json")
        if readback != seal_bytes or identity[5] != 1:
            raise ValueError("stage seal read-back mismatch")
        if objects_fd is not None:
            os.fsync(objects_fd)
        if stage_fd is not None:
            os.fsync(stage_fd)
        if staging_fd is not None:
            os.fsync(staging_fd)
        assert_stage_path()
        return {"stage_dir": str(stage), "stage_id": stage_id, "stage_seal_sha256": _digest(seal_bytes),
                "counts": {"staged": len(objects), "failed": len(failures)}, "publication_enabled": False, "production_writes": 0}
    except BaseException:
        # Only remove the directory inode created by this operation.  A replacement
        # at the public pathname is never followed or removed.
        if os.name == "nt":
            # Do not search other children by inode after pathname substitution:
            # the displaced inode is retained for forensic cleanup/read-back.
            try:
                info = stage.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == stage_identity:
                    shutil.rmtree(stage, ignore_errors=True)
            except OSError:
                pass
        else:
            # Delete only through the retained inode descriptors. Directory-name
            # removal is deliberately omitted because unlinkat cannot assert inode.
            if objects_fd is not None:
                for name in os.listdir(objects_fd):
                    try:
                        os.unlink(name, dir_fd=objects_fd)
                    except OSError:
                        pass
            if stage_fd is not None:
                for name in os.listdir(stage_fd):
                    if name != "objects":
                        try:
                            os.unlink(name, dir_fd=stage_fd)
                        except OSError:
                            pass
        raise
    finally:
        for fd in (objects_fd, stage_fd, staging_fd, root_fd):
            if fd is not None:
                os.close(fd)
