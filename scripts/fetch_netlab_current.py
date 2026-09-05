from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.electrozone import FeedValidationError
from mks123_pipeline.integrity import read_evidence
from mks123_pipeline.netlab_properties import scan_netlab_properties
from mks123_pipeline.snapshot_store import install_snapshot

DEFAULT_PRICE_URL = "https://www.netlab.ru/products/pricexml4.zip"
DEFAULT_PROPERTIES_URL = "https://www.netlab.ru/products/GoodsProperties.zip"
ALLOWED_HOST = "www.netlab.ru"
ALLOWED_PATHS = {
    "price": "/products/pricexml4.zip",
    "properties": "/products/GoodsProperties.zip",
}
MAX_SOURCE_BYTES = 128 * 1024 * 1024
READ_TIMEOUT_SECONDS = 180
DEFAULT_MIN_ITEMS = {"price": 60_000, "properties": 50_000}
DEFAULT_MAX_ITEMS = 100_000
NETLAB_TIMEZONE = timezone(timedelta(hours=3), name="Europe/Moscow")


def _validate_feed_freshness(
    catalog_date: str,
    *,
    fetched_at_utc: str,
    max_age_hours: int,
) -> float:
    if max_age_hours <= 0:
        raise ValueError("max feed age must be positive")
    source_time = datetime.strptime(catalog_date, "%Y-%m-%d %H:%M").replace(tzinfo=NETLAB_TIMEZONE)
    fetched_time = datetime.fromisoformat(fetched_at_utc)
    if fetched_time.tzinfo is None:
        raise ValueError("fetch timestamp must include a timezone")
    age = fetched_time.astimezone(UTC) - source_time.astimezone(UTC)
    if age < -timedelta(minutes=15):
        raise ValueError("Netlab feed timestamp is implausibly in the future")
    if age > timedelta(hours=max_age_hours):
        raise ValueError("Netlab feed timestamp is stale")
    return age.total_seconds()


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class DownloadResult:
    status: int
    sha256: str | None
    size: int
    content_type: str
    etag: str | None
    last_modified: str | None


def _validate_source_url(kind: str, value: str) -> str:
    expected_path = ALLOWED_PATHS.get(kind)
    parts = urlsplit(value)
    if (
        expected_path is None
        or parts.scheme.lower() != "https"
        or parts.hostname != ALLOWED_HOST
        or parts.port not in (None, 443)
        or parts.path != expected_path
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("source URL is not allowlisted")
    return value


def _conditional_fetch_to_part(
    url: str,
    part: Path,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> DownloadResult:
    headers = {
        "Accept": "application/zip,application/x-zip-compressed,application/octet-stream;q=0.9,*/*;q=0.1",
        "User-Agent": "mks123-readonly-pipeline/1.0",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = Request(
        url,
        headers=headers,
        method="GET",
    )
    opener = build_opener(_RejectRedirects())
    digest = hashlib.sha256()
    size = 0
    try:
        response_context = opener.open(request, timeout=READ_TIMEOUT_SECONDS)
    except HTTPError as exc:
        if exc.code != 304:
            raise
        response_headers = exc.headers or {}
        return DownloadResult(
            status=304,
            sha256=None,
            size=0,
            content_type="",
            etag=response_headers.get("ETag"),
            last_modified=response_headers.get("Last-Modified"),
        )
    with response_context as response:
        status = getattr(response, "status", None)
        content_type = (response.headers.get_content_type() or "").lower()
        content_length = response.headers.get("Content-Length")
        if status is None or status < 200 or status >= 300:
            raise RuntimeError(f"unexpected HTTP status: {status}")
        if content_type in {"text/html", "application/xhtml+xml"}:
            raise RuntimeError(f"unexpected content type: {content_type}")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError as exc:
                raise RuntimeError("invalid Content-Length") from exc
            if declared_size < 0 or declared_size > MAX_SOURCE_BYTES:
                raise RuntimeError(f"source size exceeds byte limit: {MAX_SOURCE_BYTES}")
        with part.open("xb") as handle:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > MAX_SOURCE_BYTES:
                    raise RuntimeError(f"source size exceeds byte limit: {MAX_SOURCE_BYTES}")
                handle.write(block)
                digest.update(block)
            handle.flush()
            os.fsync(handle.fileno())
        return DownloadResult(
            status=status,
            sha256=digest.hexdigest(),
            size=size,
            content_type=content_type,
            etag=response.headers.get("ETag"),
            last_modified=response.headers.get("Last-Modified"),
        )


def _fetch_to_part(url: str, part: Path) -> tuple[str, int, str]:
    result = _conditional_fetch_to_part(url, part)
    if result.status != 200 or result.sha256 is None:
        raise RuntimeError(f"unexpected HTTP status: {result.status}")
    return result.sha256, result.size, result.content_type


def _snapshot_contract(raw_root: Path, metadata: dict[str, object]) -> tuple[Path, str, int]:
    local_file = metadata.get("local_file")
    expected_hash = metadata.get("sha256")
    expected_size = metadata.get("size_bytes")
    if (
        not isinstance(local_file, str)
        or not local_file
        or Path(local_file).name != local_file
        or "/" in local_file
        or "\\" in local_file
    ):
        raise ValueError("invalid accepted snapshot filename")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("invalid accepted snapshot hash")
    if not isinstance(expected_size, int) or expected_size < 1:
        raise ValueError("invalid accepted snapshot size")
    snapshot = raw_root / local_file
    if snapshot.parent != raw_root or snapshot.suffix.casefold() != ".zip":
        raise ValueError("accepted snapshot escapes raw root")
    return snapshot, expected_hash, expected_size


def _capture_validated_price_snapshot(
    raw_root: Path,
    metadata: dict[str, object],
    captured_path: Path,
    *,
    fetched_at: str,
    min_items: int,
    max_items: int,
) -> object:
    snapshot_path, expected_hash, expected_size = _snapshot_contract(raw_root, metadata)
    if expected_size > MAX_SOURCE_BYTES:
        raise ValueError("accepted snapshot exceeds byte limit")
    evidence = read_evidence(snapshot_path, max_bytes=MAX_SOURCE_BYTES)
    data = evidence.data
    if len(data) != expected_size or evidence.sha256 != expected_hash:
        raise ValueError("accepted snapshot failed size/hash validation")
    with captured_path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    parsed = NetlabAdapter().parse(
        captured_path,
        fetched_at=fetched_at,
        min_items=min_items,
        max_items=max_items,
        max_bytes=MAX_SOURCE_BYTES,
    )
    actual_contract = {
        "feed_catalog_date": parsed.catalog_date or "",
        "item_count": len(parsed.items),
        "currency_rates": {key: str(value) for key, value in sorted(parsed.currencies.items())},
    }
    expected_contract = {key: metadata.get(key) for key in actual_contract}
    if actual_contract != expected_contract or parsed.source_sha256 != expected_hash:
        raise ValueError("accepted snapshot metadata does not match captured ZIP")
    return parsed


def _validated_snapshot_path(raw_root: Path, metadata: dict[str, object]) -> Path:
    snapshot, expected_hash, expected_size = _snapshot_contract(raw_root, metadata)
    if expected_size > MAX_SOURCE_BYTES:
        raise ValueError("accepted snapshot exceeds byte limit")
    evidence = read_evidence(snapshot, max_bytes=MAX_SOURCE_BYTES)
    if len(evidence.data) != expected_size or evidence.sha256 != expected_hash:
        raise ValueError("accepted snapshot failed size/hash validation")
    return snapshot


def _latest_price_metadata(raw_root: Path) -> dict[str, object] | None:
    accepted: list[dict[str, object]] = []
    for path in raw_root.glob("netlab-live-*.metadata.json"):
        try:
            payload = json.loads(
                read_evidence(path, max_bytes=4 * 1024 * 1024).data.decode("utf-8")
            )
            if not isinstance(payload, dict):
                continue
            if (
                payload.get("supplier") != "netlab"
                or payload.get("feed_kind") != "price"
                or payload.get("source_url") != DEFAULT_PRICE_URL
            ):
                continue
            _validated_snapshot_path(raw_root, payload)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        accepted.append(payload)
    if not accepted:
        return None
    return max(accepted, key=lambda item: str(item.get("fetched_at_utc") or ""))


def _write_304_receipt(raw_root: Path, metadata: dict[str, object], checked_at: str) -> str:
    receipt_dir = raw_root / "acquisition-receipts"
    receipt_dir.mkdir(parents=True, exist_ok=True)
    token = datetime.fromisoformat(checked_at).strftime("%Y%m%dT%H%M%S%fZ")
    receipt_path = receipt_dir / f"netlab-price-{token}-{uuid4().hex}.json"
    payload = {
        "supplier": "netlab",
        "feed_kind": "price",
        "source_url": DEFAULT_PRICE_URL,
        "http_status": 304,
        "checked_at_utc": checked_at,
        "local_file": metadata["local_file"],
        "sha256": metadata["sha256"],
        "etag": metadata.get("etag"),
        "last_modified": metadata.get("last_modified"),
        "production_writes": 0,
    }
    with receipt_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return receipt_path.relative_to(raw_root).as_posix()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch and validate an immutable Netlab supplier ZIP")
    parser.add_argument("--kind", choices=("price", "properties"), required=True)
    parser.add_argument("--raw-root", type=Path, default=PROJECT_ROOT / "raw")
    parser.add_argument("--min-items", type=int, default=None)
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--max-feed-age-hours", type=int, default=24)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    raw_root = args.raw_root.resolve()
    raw_root.mkdir(parents=True, exist_ok=True)
    part = raw_root / f".netlab-{args.kind}-{os.getpid()}-{uuid4().hex}.part.zip"
    fetched_at = datetime.now(UTC).isoformat()
    url = DEFAULT_PRICE_URL if args.kind == "price" else DEFAULT_PROPERTIES_URL
    min_items = args.min_items if args.min_items is not None else DEFAULT_MIN_ITEMS[args.kind]
    hard_min_items = DEFAULT_MIN_ITEMS[args.kind]
    if (
        min_items < hard_min_items
        or args.max_items > DEFAULT_MAX_ITEMS
        or args.max_items < min_items
        or args.max_feed_age_hours < 1
        or args.max_feed_age_hours > 24
    ):
        raise SystemExit("FETCH_FAILED unsafe acquisition bounds")
    try:
        source_url = _validate_source_url(args.kind, url)
        previous = _latest_price_metadata(raw_root) if args.kind == "price" else None
        download = _conditional_fetch_to_part(
            source_url,
            part,
            etag=str(previous.get("etag")) if previous and previous.get("etag") else None,
            last_modified=(
                str(previous.get("last_modified")) if previous and previous.get("last_modified") else None
            ),
        )
        if download.status == 304:
            try:
                if previous is None:
                    raise ValueError("304 response has no accepted local snapshot")
                snapshot = _capture_validated_price_snapshot(
                    raw_root,
                    previous,
                    part,
                    fetched_at=fetched_at,
                    min_items=min_items,
                    max_items=args.max_items,
                )
                feed_date = snapshot.catalog_date or ""
                feed_age_seconds = _validate_feed_freshness(
                    feed_date,
                    fetched_at_utc=fetched_at,
                    max_age_hours=args.max_feed_age_hours,
                )
            except (OSError, TypeError, ValueError):
                part.unlink(missing_ok=True)
                download = _conditional_fetch_to_part(source_url, part)
            else:
                receipt = _write_304_receipt(raw_root, previous, fetched_at)
                output = {
                    **previous,
                    "deduplicated": True,
                    "http_status": 304,
                    "checked_at_utc": fetched_at,
                    "feed_age_seconds": feed_age_seconds,
                    "max_feed_age_hours": args.max_feed_age_hours,
                    "acquisition_receipt": receipt,
                    "production_writes": 0,
                }
                print(json.dumps(output, ensure_ascii=False, sort_keys=True))
                return 0
        if download.status != 200 or download.sha256 is None:
            raise RuntimeError(f"unexpected HTTP status: {download.status}")
        content_hash = download.sha256
        size = download.size
        content_type = download.content_type
        if args.kind == "price":
            snapshot = NetlabAdapter().parse(
                part,
                fetched_at=fetched_at,
                min_items=min_items,
                max_items=args.max_items,
                max_bytes=MAX_SOURCE_BYTES,
            )
            if snapshot.source_sha256 != content_hash:
                raise RuntimeError("source hash mismatch after download")
            feed_date = snapshot.catalog_date or ""
            feed_age_seconds = _validate_feed_freshness(
                feed_date,
                fetched_at_utc=fetched_at,
                max_age_hours=args.max_feed_age_hours,
            )
            content_fields = {
                "feed_catalog_date": feed_date,
                "item_count": len(snapshot.items),
                "currency_rates": {key: str(value) for key, value in sorted(snapshot.currencies.items())},
            }
        else:
            stats = scan_netlab_properties(
                part,
                max_bytes=MAX_SOURCE_BYTES,
                allow_unknown_property_ids=True,
            )
            if stats.source_sha256 != content_hash:
                raise RuntimeError("source hash mismatch after download")
            if stats.item_count < min_items or stats.item_count > args.max_items:
                raise FeedValidationError(
                    f"properties item count outside configured bounds: {stats.item_count}"
                )
            feed_date = stats.catalog_date
            content_fields = {
                "feed_catalog_date": feed_date,
                "item_count": stats.item_count,
                "property_count": stats.property_count,
                "observation_count": stats.observation_count,
                "missing_observation_count": stats.missing_observation_count,
                "unknown_property_id_count": stats.unknown_property_id_count,
                "unknown_observation_count": stats.unknown_observation_count,
            }
        metadata = {
            "supplier": "netlab",
            "feed_kind": args.kind,
            "source": "direct_https",
            "source_url": source_url,
            "fetched_at_utc": fetched_at,
            "size_bytes": size,
            "content_type": content_type,
            "http_status": 200,
            "etag": download.etag,
            "last_modified": download.last_modified,
            **content_fields,
            "credentials_persisted": False,
            "publication_enabled": False,
            "production_writes": 0,
            "max_feed_age_hours": args.max_feed_age_hours if args.kind == "price" else None,
            "feed_age_seconds": feed_age_seconds if args.kind == "price" else None,
        }
        required_existing = {
            key: metadata[key]
            for key in (
                "supplier",
                "feed_kind",
                "source",
                "source_url",
                "size_bytes",
                "feed_catalog_date",
                "item_count",
                "credentials_persisted",
                "publication_enabled",
                "production_writes",
                "max_feed_age_hours",
            )
        }
        for key in (
            "currency_rates",
            "property_count",
            "observation_count",
            "missing_observation_count",
            "unknown_property_id_count",
            "unknown_observation_count",
        ):
            if key in metadata:
                required_existing[key] = metadata[key]
        installed = install_snapshot(
            part,
            raw_root,
            feed_date=feed_date,
            content_hash=content_hash,
            metadata=metadata,
            required_existing_metadata=required_existing,
            source_suffix=".zip",
        )
        output = dict(installed.metadata)
        output["deduplicated"] = not installed.created
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
        return 0
    except HTTPError as exc:
        raise SystemExit(f"FETCH_FAILED http_status={exc.code}") from exc
    except URLError as exc:
        raise SystemExit(f"FETCH_FAILED network_error={exc.reason}") from exc
    except (FeedValidationError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise SystemExit(f"FETCH_FAILED {exc}") from exc
    finally:
        part.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
