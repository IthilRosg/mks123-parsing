from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from typing import Self

import pytest

from scripts import fetch_electrozone_current as fetch


class _Headers:
    def __init__(self, content_type: str, content_length: str | None = None) -> None:
        self._content_type = content_type
        self._content_length = content_length

    def get_content_type(self) -> str:
        return self._content_type

    def get(self, name: str) -> str | None:
        return self._content_length if name == "Content-Length" else None


class _Response(BytesIO):
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/xml",
        content_length: str | None = None,
    ) -> None:
        super().__init__(body)
        self.status = status
        self.headers = _Headers(content_type, content_length)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class _Opener:
    def __init__(self, response: _Response) -> None:
        self._response = response

    def open(self, request: object, timeout: int) -> _Response:
        return self._response


def test_feed_url_allowlist_accepts_only_exact_supplier_endpoint() -> None:
    assert fetch._validate_feed_url(fetch.DEFAULT_FEED_URL) == fetch.DEFAULT_FEED_URL

    rejected = [
        "http://electrozon.ru/files/market_whs.yml",
        "https://example.com/files/market_whs.yml",
        "https://electrozon.ru/files/other.yml",
        "https://user:pass@electrozon.ru/files/market_whs.yml",
        "https://electrozon.ru/files/market_whs.yml?download=1",
        "https://electrozon.ru/files/market_whs.yml#fragment",
    ]
    for value in rejected:
        with pytest.raises(ValueError, match="not allowlisted"):
            fetch._validate_feed_url(value)


def test_basic_authorization_requires_nonempty_credentials() -> None:
    assert fetch._basic_authorization("supplier", "password") == "Basic c3VwcGxpZXI6cGFzc3dvcmQ="

    for user, password in [("", "password"), ("supplier", ""), ("bad:user", "password")]:
        with pytest.raises(ValueError):
            fetch._basic_authorization(user, password)


def test_redirect_handler_rejects_redirects() -> None:
    handler = fetch._RejectRedirects()

    assert handler.redirect_request(None, None, 302, "Found", {}, fetch.DEFAULT_FEED_URL) is None


def test_fetch_streams_to_part_and_hashes_exact_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"<yml_catalog/>"
    response = _Response(body, content_length=str(len(body)))
    monkeypatch.setattr(fetch, "build_opener", lambda *args: _Opener(response))
    part = tmp_path / "source.part"

    digest, size, content_type = fetch._fetch_to_part(fetch.DEFAULT_FEED_URL, "Basic test", part)

    assert part.read_bytes() == body
    assert digest == hashlib.sha256(body).hexdigest()
    assert size == len(body)
    assert content_type == "application/xml"


def test_fetch_rejects_html_before_creating_part(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    response = _Response(b"<html>login</html>", content_type="text/html")
    monkeypatch.setattr(fetch, "build_opener", lambda *args: _Opener(response))
    part = tmp_path / "source.part"

    with pytest.raises(RuntimeError, match="unexpected content type"):
        fetch._fetch_to_part(fetch.DEFAULT_FEED_URL, "Basic test", part)

    assert not part.exists()


def test_fetch_rejects_declared_and_streamed_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fetch, "MAX_SOURCE_BYTES", 4)
    declared = _Response(b"", content_length="5")
    monkeypatch.setattr(fetch, "build_opener", lambda *args: _Opener(declared))
    declared_part = tmp_path / "declared.part"
    with pytest.raises(RuntimeError, match="source size exceeds"):
        fetch._fetch_to_part(fetch.DEFAULT_FEED_URL, "Basic test", declared_part)
    assert not declared_part.exists()

    streamed = _Response(b"12345")
    monkeypatch.setattr(fetch, "build_opener", lambda *args: _Opener(streamed))
    streamed_part = tmp_path / "streamed.part"
    with pytest.raises(RuntimeError, match="source size exceeds"):
        fetch._fetch_to_part(fetch.DEFAULT_FEED_URL, "Basic test", streamed_part)
    assert streamed_part.read_bytes() == b""


def test_main_removes_partial_file_after_malformed_xml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"<broken>"

    def write_malformed(url: str, authorization: str, part: Path) -> tuple[str, int, str]:
        part.write_bytes(body)
        return hashlib.sha256(body).hexdigest(), len(body), "application/xml"

    monkeypatch.setattr(fetch, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(fetch, "_fetch_to_part", write_malformed)
    monkeypatch.setenv("FIN_ELECTROZONE_FEED_USER", "supplier")
    monkeypatch.setenv("FIN_ELECTROZONE_FEED_PASS", "password")

    with pytest.raises(SystemExit, match="FETCH_FAILED"):
        fetch.main()

    assert list((tmp_path / "raw").glob("*.part")) == []
