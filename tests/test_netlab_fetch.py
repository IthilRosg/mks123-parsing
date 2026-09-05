from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Self
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.netlab_properties import scan_netlab_properties
from scripts import fetch_netlab_current as fetch


def test_netlab_feed_freshness_uses_supplier_moscow_timestamp() -> None:
    fetch._validate_feed_freshness(
        "2026-09-04 13:04",
        fetched_at_utc="2026-09-04T10:13:00Z",
        max_age_hours=24,
    )


def test_netlab_feed_freshness_rejects_stale_rate() -> None:
    with pytest.raises(ValueError, match="stale"):
        fetch._validate_feed_freshness(
            "2026-09-02 13:04",
            fetched_at_utc="2026-09-04T10:13:00Z",
            max_age_hours=24,
        )


def test_netlab_feed_freshness_rejects_implausible_future_timestamp() -> None:
    with pytest.raises(ValueError, match="future"):
        fetch._validate_feed_freshness(
            "2026-09-04 14:04",
            fetched_at_utc="2026-09-04T10:13:00Z",
            max_age_hours=24,
        )


PRICE_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<xml_catalog date="2026-09-04 09:04"><shop>
<currencies><currency id="USD" rate="86.89"/></currencies>
<categories><category id="1">Network</category></categories><offers>
<offer id="1000463" available="true"><priceE>270</priceE><currencyId>USD</currencyId>
<categoryId>1</categoryId><count>4</count><name>Cable</name></offer>
</offers></shop></xml_catalog>'''

PROPERTIES_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<xml_catalog date="2026-09-04 08:46"><properties><property id="p1">Vendor</property></properties>
<items><item id="1000463"><p1>Rexant</p1></item></items></xml_catalog>'''


class _Headers:
    def __init__(self, content_type: str, content_length: str | None = None) -> None:
        self._content_type = content_type
        self._content_length = content_length

    def get_content_type(self) -> str:
        return self._content_type

    def get(self, name: str) -> str | None:
        return self._content_length if name == "Content-Length" else None


class _Response(BytesIO):
    status = 200

    def __init__(self, body: bytes, content_type: str = "application/x-zip-compressed") -> None:
        super().__init__(body)
        self.headers = _Headers(content_type, str(len(body)))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _Opener:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def open(self, request: object, timeout: int) -> _Response:
        return _Response(self.body)


def _archive(member: str, body: bytes) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(member, body)
    return buffer.getvalue()


def test_netlab_fetch_allowlists_only_exact_supplier_urls() -> None:
    assert fetch._validate_source_url("price", fetch.DEFAULT_PRICE_URL) == fetch.DEFAULT_PRICE_URL
    assert fetch._validate_source_url("properties", fetch.DEFAULT_PROPERTIES_URL) == fetch.DEFAULT_PROPERTIES_URL

    for value in (
        "http://www.netlab.ru/products/pricexml4.zip",
        "https://example.com/products/pricexml4.zip",
        "https://www.netlab.ru/products/other.zip",
        "https://user:pass@www.netlab.ru/products/pricexml4.zip",
        "https://www.netlab.ru/products/pricexml4.zip?x=1",
    ):
        with pytest.raises(ValueError, match="not allowlisted"):
            fetch._validate_source_url("price", value)


def test_netlab_fetch_streams_exact_archive_with_hash_and_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _archive("Price.xml", PRICE_XML)
    monkeypatch.setattr(fetch, "build_opener", lambda *args: _Opener(body))
    part = tmp_path / "price.zip.part"

    digest, size, content_type = fetch._fetch_to_part(fetch.DEFAULT_PRICE_URL, part)

    assert part.read_bytes() == body
    assert digest == hashlib.sha256(body).hexdigest()
    assert size == len(body)
    assert content_type == "application/x-zip-compressed"


def test_conditional_fetch_sends_validators_and_accepts_304_without_part(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_headers: dict[str, str] = {}

    class NotModifiedOpener:
        def open(self, request, timeout):
            observed_headers.update({key.casefold(): value for key, value in request.header_items()})
            from email.message import Message
            from urllib.error import HTTPError

            headers = Message()
            headers["ETag"] = '"current"'
            headers["Last-Modified"] = "Fri, 04 Sep 2026 10:00:00 GMT"
            raise HTTPError(request.full_url, 304, "Not Modified", headers, None)

    monkeypatch.setattr(fetch, "build_opener", lambda *handlers: NotModifiedOpener())
    part = tmp_path / "part.zip"

    result = fetch._conditional_fetch_to_part(
        fetch.DEFAULT_PRICE_URL,
        part,
        etag='"current"',
        last_modified="Fri, 04 Sep 2026 10:00:00 GMT",
    )

    assert result.status == 304
    assert result.etag == '"current"'
    assert result.last_modified == "Fri, 04 Sep 2026 10:00:00 GMT"
    assert observed_headers["if-none-match"] == '"current"'
    assert observed_headers["if-modified-since"] == "Fri, 04 Sep 2026 10:00:00 GMT"
    assert not part.exists()


def test_conditional_fetch_accepts_304_without_response_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from urllib.error import HTTPError

    class NotModifiedWithoutHeaders:
        def open(self, request, *, timeout: int):
            raise HTTPError(request.full_url, 304, "Not Modified", None, None)

    monkeypatch.setattr(fetch, "build_opener", lambda *handlers: NotModifiedWithoutHeaders())

    result = fetch._conditional_fetch_to_part(
        fetch.DEFAULT_PRICE_URL,
        tmp_path / "response.part.zip",
        etag='"snapshot-v1"',
    )

    assert result.status == 304
    assert result.etag is None
    assert result.last_modified is None


def test_netlab_price_fetch_installs_parseable_immutable_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = _archive("Price.xml", PRICE_XML)

    def write_price(url: str, part: Path, **validators) -> fetch.DownloadResult:
        part.write_bytes(body)
        return fetch.DownloadResult(
            status=200,
            sha256=hashlib.sha256(body).hexdigest(),
            size=len(body),
            content_type="application/x-zip-compressed",
            etag='"price-v1"',
            last_modified="Fri, 04 Sep 2026 06:04:00 GMT",
        )

    monkeypatch.setattr(fetch, "_conditional_fetch_to_part", write_price)
    monkeypatch.setitem(fetch.DEFAULT_MIN_ITEMS, "price", 1)
    raw_root = tmp_path / "raw"

    assert fetch.main(["--kind", "price", "--raw-root", str(raw_root), "--min-items", "1"]) == 0
    result = json.loads(capsys.readouterr().out)
    target = raw_root / result["local_file"]

    assert target.suffix == ".zip"
    assert hashlib.sha256(target.read_bytes()).hexdigest() == result["sha256"]
    snapshot = NetlabAdapter().parse(
        target,
        fetched_at="2026-09-04T09:05:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )
    assert snapshot.currencies == {"USD": Decimal("86.89")}
    assert result["supplier"] == "netlab"
    assert result["feed_kind"] == "price"
    assert result["production_writes"] == 0


def test_netlab_properties_fetch_validates_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = _archive("GoodsProperties.xml", PROPERTIES_XML)

    def write_properties(url: str, part: Path, **validators) -> fetch.DownloadResult:
        part.write_bytes(body)
        return fetch.DownloadResult(
            status=200,
            sha256=hashlib.sha256(body).hexdigest(),
            size=len(body),
            content_type="application/x-zip-compressed",
            etag='"properties-v1"',
            last_modified="Fri, 04 Sep 2026 06:04:00 GMT",
        )

    monkeypatch.setattr(fetch, "_conditional_fetch_to_part", write_properties)
    monkeypatch.setitem(fetch.DEFAULT_MIN_ITEMS, "properties", 1)
    raw_root = tmp_path / "raw"

    assert fetch.main(
        ["--kind", "properties", "--raw-root", str(raw_root), "--min-items", "1"]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    target = raw_root / result["local_file"]
    stats = scan_netlab_properties(target, max_bytes=64 * 1024)

    assert stats.item_count == 1
    assert result["feed_kind"] == "properties"
    assert result["item_count"] == 1
    assert result["production_writes"] == 0


def test_price_fetch_reuses_verified_snapshot_on_conditional_304(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = _archive("Price.xml", PRICE_XML)
    digest = hashlib.sha256(body).hexdigest()
    responses = [
        fetch.DownloadResult(
            status=200,
            sha256=digest,
            size=len(body),
            content_type="application/x-zip-compressed",
            etag='"v1"',
            last_modified="Fri, 04 Sep 2026 06:04:00 GMT",
        ),
        fetch.DownloadResult(
            status=304,
            sha256=None,
            size=0,
            content_type="",
            etag='"v1"',
            last_modified="Fri, 04 Sep 2026 06:04:00 GMT",
        ),
    ]

    def conditional(url: str, part: Path, **validators) -> fetch.DownloadResult:
        result = responses.pop(0)
        if result.status == 200:
            part.write_bytes(body)
        else:
            assert validators == {
                "etag": '"v1"',
                "last_modified": "Fri, 04 Sep 2026 06:04:00 GMT",
            }
        return result

    monkeypatch.setattr(fetch, "_conditional_fetch_to_part", conditional)
    monkeypatch.setattr(fetch, "_fetch_to_part", lambda *args: (_ for _ in ()).throw(AssertionError("legacy path")))
    monkeypatch.setitem(fetch.DEFAULT_MIN_ITEMS, "price", 1)
    raw_root = tmp_path / "raw"
    args = [
        "--kind",
        "price",
        "--raw-root",
        str(raw_root),
        "--min-items",
        "1",
    ]

    assert fetch.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert fetch.main(args) == 0
    second = json.loads(capsys.readouterr().out)

    assert first["sha256"] == digest
    assert first["etag"] == '"v1"'
    assert second["sha256"] == digest
    assert second["deduplicated"] is True
    assert second["http_status"] == 304
    receipts = list((raw_root / "acquisition-receipts").glob("*.json"))
    assert len(receipts) == 1


def test_price_fetch_reparses_304_snapshot_and_retries_when_sidecar_semantics_disagree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    body = _archive("Price.xml", PRICE_XML)
    digest = hashlib.sha256(body).hexdigest()
    responses = [200, 304, 200]
    calls: list[dict[str, str | None]] = []

    def conditional(url: str, part: Path, **validators) -> fetch.DownloadResult:
        calls.append(validators)
        status = responses.pop(0)
        if status == 200:
            part.write_bytes(body)
        return fetch.DownloadResult(
            status=status,
            sha256=digest if status == 200 else None,
            size=len(body) if status == 200 else 0,
            content_type="application/x-zip-compressed" if status == 200 else "",
            etag='"v1"',
            last_modified="Fri, 04 Sep 2026 06:04:00 GMT",
        )

    monkeypatch.setattr(fetch, "_conditional_fetch_to_part", conditional)
    monkeypatch.setitem(fetch.DEFAULT_MIN_ITEMS, "price", 1)
    raw_root = tmp_path / "raw"
    args = ["--kind", "price", "--raw-root", str(raw_root), "--min-items", "1"]

    assert fetch.main(args) == 0
    first = json.loads(capsys.readouterr().out)
    metadata_path = raw_root / f"{Path(first['local_file']).stem}.metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["feed_catalog_date"] = "2026-09-04 09:03"
    metadata_path.chmod(0o600)
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(SystemExit, match="FETCH_FAILED.*metadata conflict"):
        fetch.main(args)

    assert len(calls) == 3
    assert calls[2] == {}


@pytest.mark.parametrize(
    "args",
    [
        ["--kind", "price", "--min-items", "59999"],
        ["--kind", "properties", "--min-items", "49999"],
        ["--kind", "price", "--max-items", "100001"],
        ["--kind", "price", "--max-feed-age-hours", "25"],
    ],
)
def test_fetch_cli_cannot_weaken_hard_safety_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
) -> None:
    monkeypatch.setattr(
        fetch,
        "_conditional_fetch_to_part",
        lambda *unused_args, **unused_kwargs: (_ for _ in ()).throw(
            AssertionError("network must not run for unsafe bounds")
        ),
    )

    with pytest.raises(SystemExit, match="FETCH_FAILED unsafe acquisition bounds"):
        fetch.main([*args, "--raw-root", str(tmp_path / "raw")])
