from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.electrozone import FeedValidationError, parse_yml
from mks123_pipeline.snapshot_store import install_snapshot

DEFAULT_RAW_ROOT = PROJECT_ROOT / "raw"
DEFAULT_MAX_SOURCE_BYTES = 64 * 1024 * 1024


def _identity(file_stat: os.stat_result) -> tuple[int, int]:
    return (file_stat.st_dev, file_stat.st_ino)


def _signature(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    return (*_identity(file_stat), file_stat.st_size, file_stat.st_mtime_ns)


def _is_link_or_reparse(file_stat: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(file_stat, "st_file_attributes", 0)
    return stat.S_ISLNK(file_stat.st_mode) or bool(reparse_flag and attributes & reparse_flag)


def _copy_bounded(source: Path, part: Path, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    path_before = source.lstat()
    if _is_link_or_reparse(path_before):
        raise RuntimeError("symbolic links and reparse points are not accepted")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        descriptor_before = os.fstat(descriptor)
        path_after_open = source.lstat()
        if not stat.S_ISREG(descriptor_before.st_mode):
            raise RuntimeError("source is not a regular file")
        if _is_link_or_reparse(path_after_open) or _identity(path_after_open) != _identity(descriptor_before):
            raise RuntimeError("opened source does not match requested path")
        with os.fdopen(descriptor, "rb", closefd=False) as src, part.open("xb") as dst:
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise RuntimeError(f"source size exceeds {max_bytes} bytes")
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        descriptor_after = os.fstat(descriptor)
        path_after_copy = source.lstat()
        if _signature(descriptor_after) != _signature(descriptor_before):
            raise RuntimeError("source changed while it was being copied")
        if _is_link_or_reparse(path_after_copy) or _identity(path_after_copy) != _identity(descriptor_after):
            raise RuntimeError("source path changed while it was being copied")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install a read-only Electrozone manual-drop snapshot")
    parser.add_argument("--source", required=True, type=Path, help="Supplier-provided YML/XML file")
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--min-offers", type=int, default=1500)
    parser.add_argument("--max-offers", type=int, default=100000)
    parser.add_argument("--max-source-bytes", type=int, default=DEFAULT_MAX_SOURCE_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    source_input = args.source
    try:
        source = source_input.absolute()
        raw_root = args.raw_root.resolve()
        if source == raw_root or raw_root in source.parents:
            raise ValueError("source must be outside the immutable raw snapshot root")
        if args.max_source_bytes <= 0:
            raise ValueError("max-source-bytes must be positive")
        if args.min_offers <= 0 or args.max_offers < args.min_offers:
            raise ValueError("invalid offer-count limits")

        raw_root.mkdir(parents=True, exist_ok=True)
        part = raw_root / f".electrozone-manual-{uuid.uuid4().hex}.part"
        received_at = datetime.now(UTC).isoformat()
        try:
            content_hash, source_size = _copy_bounded(source, part, args.max_source_bytes)
            snapshot = parse_yml(
                part,
                received_at,
                min_items=args.min_offers,
                max_items=args.max_offers,
                max_bytes=args.max_source_bytes,
            )
            if snapshot.source_sha256 != content_hash:
                raise RuntimeError("source changed during validation")
            if not snapshot.catalog_date:
                raise FeedValidationError("yml_catalog date is required for immutable snapshot identity")
            metadata = {
                "supplier": "electrozone",
                "source": "manual_drop",
                "source_filename": source.name,
                "received_at_utc": received_at,
                "catalog_date": snapshot.catalog_date,
                "offer_count": len(snapshot.items),
                "currency_ids": sorted(snapshot.currencies),
                "size_bytes": source_size,
                "credentials_persisted": False,
                "publication_enabled": False,
                "production_writes": 0,
            }
            metadata_contract = {
                key: metadata[key]
                for key in (
                    "supplier",
                    "source",
                    "catalog_date",
                    "offer_count",
                    "currency_ids",
                    "size_bytes",
                    "credentials_persisted",
                    "publication_enabled",
                    "production_writes",
                )
            }
            installed = install_snapshot(
                part,
                raw_root,
                feed_date=snapshot.catalog_date,
                content_hash=content_hash,
                metadata=metadata,
                required_existing_metadata=metadata_contract,
            )
            if any(installed.metadata.get(key) != expected for key, expected in metadata_contract.items()):
                raise RuntimeError("snapshot metadata changed after contract validation")
            print(
                json.dumps(
                    {
                        **installed.metadata,
                        "created": installed.created,
                        "metadata_created": installed.metadata_created,
                        "snapshot": str(installed.target),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0
        finally:
            part.unlink(missing_ok=True)
    except (FeedValidationError, OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"MANUAL_DROP_FAILED {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
