from __future__ import annotations

from io import BytesIO
from time import monotonic, sleep
from typing import Self
from unittest.mock import patch

import pytest

from mks123_pipeline.manufacturer_evidence import ManufacturerIdentity
from mks123_pipeline.manufacturer_fetch import (
    FetchResult,
    FetchStatus,
    _resolve_public_host,
    fetch_bounded,
    read_bounded,
    validate_source_url,
)
from scripts.run_manufacturer_source_fetch import (
    _entry,
    _url_for_output,
    same_host_family,
)


class FakeHeaders(dict):
    def get_content_type(self) -> str:
        return self.get("Content-Type", "").split(";", 1)[0].strip().lower()


class FakeResponse:
    def __init__(self, body: bytes, *, status: int = 200, content_type: str = "text/html") -> None:
        self.body = body
        self.status = status
        self.headers = FakeHeaders({"Content-Type": content_type})
        self._stream = BytesIO(body)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requested = None

    def open(self, request: object, timeout: float) -> FakeResponse:
        self.requested = (request, timeout)
        return self.response


def test_validate_source_url_requires_http_and_allowlisted_host() -> None:
    with patch("mks123_pipeline.manufacturer_fetch._resolve_public_host"):
        assert validate_source_url("https://support.example.com/model", {"example.com"}) is None
        with pytest.raises(ValueError):
            validate_source_url("https://other.example/model", {"example.com"})
        with pytest.raises(ValueError):
            validate_source_url("file:///etc/passwd", {"example.com"})
        with pytest.raises(ValueError):
            validate_source_url("https://user:pass@example.com/model", {"example.com"})


def test_read_bounded_reports_oversize_without_unbounded_read() -> None:
    body, too_large = read_bounded(BytesIO(b"0123456789"), max_bytes=5)
    assert body == b"01234"
    assert too_large is True


def test_fetch_disables_proxy_and_accepts_only_bounded_200() -> None:
    opener = FakeOpener(FakeResponse(b"<title>TL-SF1005D</title>"))
    with patch("mks123_pipeline.manufacturer_fetch.build_opener", return_value=opener), patch("mks123_pipeline.manufacturer_fetch._resolve_public_host"):
        result = fetch_bounded("https://www.example.com/model", {"example.com"}, max_bytes=1024)
    assert result.status is FetchStatus.OK
    assert result.body == b"<title>TL-SF1005D</title>"
    assert result.redirect_location is None
    assert result.retrieved_at.endswith("+00:00")
    assert {key.lower() for key in opener.requested[0].headers} & {"cookie", "authorization"} == set()


def test_fetch_oversize_fails_closed() -> None:
    opener = FakeOpener(FakeResponse(b"0123456789"))
    with patch("mks123_pipeline.manufacturer_fetch.build_opener", return_value=opener):
        result = fetch_bounded("https://example.com/model", {"example.com"}, max_bytes=5)
    assert result.status is FetchStatus.TOO_LARGE
    assert result.body == b"01234"


def test_fetch_redirect_is_not_followed() -> None:
    opener = FakeOpener(FakeResponse(b"redirect", status=302))
    opener.response.headers["Location"] = "https://example.com/other"
    with patch("mks123_pipeline.manufacturer_fetch.build_opener", return_value=opener), patch("mks123_pipeline.manufacturer_fetch._resolve_public_host"):
        result = fetch_bounded("https://example.com/model", {"example.com"}, max_bytes=1024)
    assert result.status is FetchStatus.REDIRECT
    assert result.redirect_location == "https://example.com/other"


def test_redirect_followup_requires_same_host_family() -> None:
    assert same_host_family("www.tp-link.com", "tp-link.com") is True
    assert same_host_family("www.gembird.ru", "gembird.ru") is True
    assert same_host_family("kyocera.ru", "russia.kyocera.com") is False


def test_validate_source_url_rejects_private_ip_and_nonstandard_port() -> None:
    with pytest.raises(ValueError):
        validate_source_url("http://127.0.0.1/admin", {"127.0.0.1"})
    with pytest.raises(ValueError):
        validate_source_url("http://169.254.169.254/latest", {"169.254.169.254"})
    with pytest.raises(ValueError):
        validate_source_url("https://example.com:8443/model", {"example.com"})


def test_validate_source_url_rejects_scheme_mismatch_and_sensitive_query() -> None:
    with patch("mks123_pipeline.manufacturer_fetch._resolve_public_host", return_value="93.184.216.34"):
        for url in ("https://example.com:80/model", "http://example.com:443/model", "https://example.com/model?token=secret", "https://example.com/model#session"):
            with pytest.raises(ValueError):
                validate_source_url(url, {"example.com"})


def test_url_output_redacts_sensitive_components() -> None:
    for url in ("https://example.com/model?token=secret", "https://user:pass@example.com/model#session"):
        redacted = _url_for_output(url)
        assert "secret" not in redacted and "pass" not in redacted and "token=" not in redacted
        assert redacted == "https://example.com/model"


def test_fetch_rejects_premature_content_length_eof() -> None:
    opener = FakeOpener(FakeResponse(b"abc"))
    opener.response.headers["Content-Length"] = "5"
    with patch("mks123_pipeline.manufacturer_fetch.build_opener", return_value=opener), patch("mks123_pipeline.manufacturer_fetch._resolve_public_host", return_value="93.184.216.34"):
        result = fetch_bounded("https://example.com/model", {"example.com"}, max_bytes=1024)
    assert result.status is FetchStatus.TRANSPORT_ERROR
    assert result.error == "incomplete HTTP response"


def test_fetch_rejects_invalid_size_before_open() -> None:
    with patch("mks123_pipeline.manufacturer_fetch.build_opener") as build, pytest.raises(ValueError):
        fetch_bounded("https://example.com/model", {"example.com"}, max_bytes=0)
    build.assert_not_called()


def test_source_exact_requires_verified_domain() -> None:
    body = b"<title>TP-Link TL-SF1005D</title><main><table><tr><th>Model</th><td>TL-SF1005D</td></tr><tr><th>MPN</th><td>TL-SF1005D</td></tr></table></main>"
    result = FetchResult("https://www.tp-link.com/products/TL-SF1005D", FetchStatus.OK, 200, "text/html", body, "a" * 64, len(body), False, None, None, "2026-09-09T19:00:00+00:00")
    identity = ManufacturerIdentity("TP-Link", "TL-SF1005D", "TL-SF1005D")
    candidate = _entry(result, result.url, identity, set())
    assert candidate["match_status"] == "declared_source_model_mention"
    verified = _entry(result, result.url, identity, {"tp-link.com"})
    assert verified["match_status"] == "declared_source_exact"


def test_entry_does_not_persist_sensitive_body() -> None:
    body = b"<html><script>accessToken=super-secret-value</script></html>"
    result = FetchResult("https://www.example.com/products/TL-SF1005D", FetchStatus.OK, 200, "text/html", body, "a" * 64, len(body), False, None, None, "2026-09-09T19:00:00+00:00")
    entry = _entry(result, result.url, ManufacturerIdentity("TP-Link", "TL-SF1005D", "TL-SF1005D"), {"example.com"})
    assert entry["sensitive_content"] is True
    assert entry["body_persisted"] is False
    assert entry["body_b64"] == ""
    assert "super-secret-value" not in str(entry)


def test_dns_resolution_deadline_is_bounded() -> None:
    def slow_resolver(*_args, **_kwargs):
        sleep(0.2)
        return []

    started = monotonic()
    with patch("mks123_pipeline.manufacturer_fetch.socket.getaddrinfo", side_effect=slow_resolver), pytest.raises(TimeoutError):
        _resolve_public_host("example.com", timeout=0.01)
    assert monotonic() - started < 0.1


def test_dns_mixed_public_and_private_answers_fail_closed() -> None:
    answers = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("127.0.0.1", 0))]
    with patch("mks123_pipeline.manufacturer_fetch.socket.getaddrinfo", return_value=answers), pytest.raises(ValueError):
        _resolve_public_host("example.com", timeout=1)
