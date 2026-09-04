from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from defusedxml import ElementTree as ET

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.electrozone import FeedValidationError, parse_yml
from mks123_pipeline.snapshot_store import install_snapshot

DEFAULT_FEED_URL = "https://electrozon.ru/files/market_whs.yml"
ALLOWED_FEED_HOST = "electrozon.ru"
ALLOWED_FEED_PATH = "/files/market_whs.yml"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MIN_SOURCE_OFFERS = 1_500
READ_TIMEOUT_SECONDS = 180


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _validate_feed_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme.lower() != "https"
        or parts.hostname != ALLOWED_FEED_HOST
        or parts.port not in (None, 443)
        or parts.path != ALLOWED_FEED_PATH
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise ValueError("source URL is not allowlisted")
    return value


def _basic_authorization(user: str, password: str) -> str:
    if not user or not password:
        raise ValueError("feed credentials are not configured")
    if ":" in user:
        raise ValueError("feed username must not contain ':'")
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    return f"Basic {encoded}"


def _fetch_to_part(url: str, authorization: str, part: Path) -> tuple[str, int, str]:
    request = Request(
        url,
        headers={
            "Authorization": authorization,
            "Accept": "application/xml,text/xml,application/octet-stream;q=0.9,*/*;q=0.1",
            "User-Agent": "mks123-readonly-pipeline/1.0",
        },
        method="GET",
    )
    opener = build_opener(_RejectRedirects())
    digest = hashlib.sha256()
    size = 0
    with opener.open(request, timeout=READ_TIMEOUT_SECONDS) as response:
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
    return digest.hexdigest(), size, content_type


def main() -> int:
    raw_root = PROJECT_ROOT / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    part = raw_root / f".electrozone-current-{os.getpid()}-{uuid4().hex}.yml.part"
    fetched_at = datetime.now(UTC).isoformat()
    try:
        feed_url = _validate_feed_url(os.environ.get("FIN_ELECTROZONE_FEED_URL", DEFAULT_FEED_URL))
        authorization = _basic_authorization(
            os.environ.get("FIN_ELECTROZONE_FEED_USER", ""),
            os.environ.get("FIN_ELECTROZONE_FEED_PASS", ""),
        )
        content_hash, size, content_type = _fetch_to_part(feed_url, authorization, part)
        snapshot = parse_yml(
            part,
            fetched_at=fetched_at,
            min_items=MIN_SOURCE_OFFERS,
            max_items=100_000,
            max_bytes=MAX_SOURCE_BYTES,
        )
        if snapshot.source_sha256 != content_hash:
            raise RuntimeError("source hash mismatch after download")
        metadata = {
            "supplier": "electrozone",
            "source": "direct_https_basic_auth",
            "source_url": feed_url,
            "fetched_at_utc": fetched_at,
            "feed_catalog_date": snapshot.catalog_date or "",
            "local_size": size,
            "offer_count": len(snapshot.items),
            "content_type": content_type,
            "credentials_persisted": False,
        }
        installed = install_snapshot(
            part,
            raw_root,
            feed_date=snapshot.catalog_date or "",
            content_hash=content_hash,
            metadata=metadata,
        )
        output = dict(installed.metadata)
        output["deduplicated"] = not installed.created
        output["metadata_repaired"] = installed.metadata_created and not installed.created
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except HTTPError as exc:
        raise SystemExit(f"FETCH_FAILED http_status={exc.code}") from exc
    except URLError as exc:
        raise SystemExit(f"FETCH_FAILED network_error={exc.reason}") from exc
    except (FeedValidationError, ET.ParseError, OSError, RuntimeError, ValueError) as exc:
        raise SystemExit(f"FETCH_FAILED {exc}") from exc
    finally:
        part.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
