from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

_MAX_URL_LENGTH = 4096
MAX_BODY_BYTES = 500_000
_MAX_BODY_BYTES = MAX_BODY_BYTES
_DNS_RESOLUTION_SLOT = threading.BoundedSemaphore(1)


class FetchStatus(str, Enum):
    OK = "ok"
    HTTP_ERROR = "http_error"
    REDIRECT = "redirect"
    TOO_LARGE = "too_large"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: FetchStatus
    http_status: int | None
    content_type: str
    body: bytes
    body_sha256: str
    bytes_read: int
    too_large: bool
    redirect_location: str | None
    error: str | None
    retrieved_at: str


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, _request, _fp, _code, _msg, _headers, _newurl):
        return None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, resolved_ip: str, **kwargs) -> None:
        super().__init__(host, **kwargs)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._resolved_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, resolved_ip: str, **kwargs) -> None:
        super().__init__(host, **kwargs)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._resolved_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPHandler(HTTPHandler):
    def http_open(self, request):
        resolved_ip = getattr(request, "_mks123_resolved_ip", None)
        if not isinstance(resolved_ip, str):
            raise URLError("source URL has no pinned public address")
        return self.do_open(_PinnedHTTPConnection, request, resolved_ip=resolved_ip)


class _PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        resolved_ip = getattr(request, "_mks123_resolved_ip", None)
        if not isinstance(resolved_ip, str):
            raise URLError("source URL has no pinned public address")
        return self.do_open(_PinnedHTTPSConnection, request, resolved_ip=resolved_ip, context=self._context, check_hostname=self._check_hostname)


def _is_public_ip(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_global and not address.is_private and not address.is_loopback and not address.is_link_local and not address.is_reserved and not address.is_multicast and not address.is_unspecified


def _resolve_public_host(host: str, timeout: float = 10.0) -> str:
    if not _is_public_ip(host):
        raise ValueError("source URL IP is not public")
    if "." not in host and ":" not in host:
        raise ValueError("source URL host is not a public DNS name")
    if not _DNS_RESOLUTION_SLOT.acquire(timeout=max(timeout, 0.0)):
        raise TimeoutError("source URL DNS resolver is busy")
    resolved: list[str] = []
    errors: list[BaseException] = []

    def resolve() -> None:
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            resolved.extend(str(info[4][0]) for info in infos)
        except (OSError, ValueError) as exc:
            errors.append(exc)
        finally:
            _DNS_RESOLUTION_SLOT.release()

    try:
        worker = threading.Thread(target=resolve, name="mks123-dns-resolution", daemon=True)
        worker.start()
    except RuntimeError:
        _DNS_RESOLUTION_SLOT.release()
        raise
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError("source URL DNS resolution deadline exceeded")
    if errors:
        raise ValueError("source URL host did not resolve") from errors[0]
    addresses = list(dict.fromkeys(resolved))
    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise ValueError("source URL resolves to a non-public IP")
    return addresses[0]


def _validate_limits(max_bytes: int, timeout: float) -> None:
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 0 < max_bytes <= _MAX_BODY_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {_MAX_BODY_BYTES}")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 60:
        raise ValueError("timeout must be between 0 and 60 seconds")


def _validated_url(url: str, allowed_hosts: set[str], *, timeout: float = 10.0) -> tuple[str, str]:
    if not isinstance(url, str) or len(url) > _MAX_URL_LENGTH or any(ord(char) < 32 for char in url):
        raise ValueError("source URL must be a bounded string")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("source URL has malformed port or host") from exc
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("source URL must use https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source URL must not contain credentials")
    if (parsed.scheme == "http" and port not in {None, 80}) or (parsed.scheme == "https" and port not in {None, 443}):
        raise ValueError("source URL port does not match scheme")
    if parsed.fragment or parsed.query:
        raise ValueError("source URL must not contain query or fragment")
    hostname = parsed.hostname.lower().rstrip(".")
    if hostname in {"localhost", "ip6-localhost"} or hostname.endswith((".local", ".internal")):
        raise ValueError("source URL host is not public")
    normalized_hosts = {host_value.lower().removeprefix("www.").rstrip(".") for host_value in allowed_hosts}
    if not any(hostname == domain or hostname.endswith(f".{domain}") for domain in normalized_hosts):
        raise ValueError("source host is not allowlisted")
    return hostname, _resolve_public_host(hostname, timeout=timeout)


def validate_source_url(url: str, allowed_hosts: set[str]) -> None:
    _validated_url(url, allowed_hosts, timeout=10.0)


def _set_stream_timeout(stream: object, remaining: float) -> None:
    candidates = [stream, getattr(stream, "fp", None), getattr(stream, "raw", None)]
    for candidate in tuple(candidates):
        if candidate is not None:
            candidates.extend([getattr(candidate, "raw", None), getattr(candidate, "_sock", None)])
    for candidate in candidates:
        setter = getattr(candidate, "settimeout", None)
        if callable(setter):
            setter(max(remaining, 0.001))
            return


def read_bounded(stream, *, max_bytes: int, deadline: float | None = None) -> tuple[bytes, bool]:
    _validate_limits(max_bytes, 1.0)
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded read deadline exceeded")
            _set_stream_timeout(stream, remaining)
        chunk = stream.read(min(65536, max_bytes + 1 - total))
        if not isinstance(chunk, bytes):
            raise TypeError("source response returned non-bytes body")
        if not chunk:
            return b"".join(chunks), False
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            return b"".join(chunks)[:max_bytes], True
    return b"".join(chunks)[:max_bytes], True


def _content_type(headers) -> str:
    getter = getattr(headers, "get_content_type", None)
    if callable(getter):
        return str(getter() or "").lower()
    return str(headers.get("Content-Type", "")).split(";", 1)[0].strip().lower()


def _declared_content_length(headers) -> int | None:
    raw = headers.get("Content-Length") if hasattr(headers, "get") else None
    if raw is None:
        return None
    value = str(raw).strip()
    if not value.isascii() or not value.isdigit():
        raise ValueError("invalid Content-Length header")
    return int(value)


def _result(url: str, status: FetchStatus, http_status: int | None, content_type: str, body: bytes, *, too_large: bool = False, redirect_location: str | None = None, error: str | None = None) -> FetchResult:
    return FetchResult(
        url=url,
        status=status,
        http_status=http_status,
        content_type=content_type,
        body=body,
        body_sha256=hashlib.sha256(body).hexdigest(),
        bytes_read=len(body),
        too_large=too_large,
        redirect_location=redirect_location,
        error=error,
        retrieved_at=datetime.now(UTC).isoformat(),
    )


def _read_error_body(exc: HTTPError, max_bytes: int, deadline: float) -> tuple[bytes, bool, str | None]:
    try:
        declared_length = _declared_content_length(exc.headers or {})
        body, too_large = read_bounded(exc, max_bytes=max_bytes, deadline=deadline)
        if declared_length is not None and not too_large and len(body) != declared_length:
            return body, False, "incomplete HTTP error response"
        return body, too_large, None
    except (OSError, TypeError, TimeoutError, ValueError, http.client.HTTPException) as read_error:
        return b"", False, f"error body read failed: {read_error}"


def fetch_bounded(url: str, allowed_hosts: set[str], *, max_bytes: int = 2_000_000, timeout: float = 15.0, deadline: float | None = None) -> FetchResult:
    _validate_limits(max_bytes, timeout)
    operation_deadline = min(deadline, time.monotonic() + timeout) if deadline is not None else time.monotonic() + timeout
    remaining = operation_deadline - time.monotonic()
    if remaining <= 0:
        return _result(url, FetchStatus.TRANSPORT_ERROR, None, "", b"", error="fetch deadline exceeded before validation")
    try:
        _hostname, resolved_ip = _validated_url(url, allowed_hosts, timeout=remaining)
    except TimeoutError as exc:
        return _result(url, FetchStatus.TRANSPORT_ERROR, None, "", b"", error=str(exc))
    request = Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/pdf,application/zip,*/*;q=0.1",
            "User-Agent": "mks123-readonly-evidence/1",
        },
        method="GET",
    )
    request._mks123_resolved_ip = resolved_ip
    opener = build_opener(ProxyHandler({}), _NoRedirect(), _PinnedHTTPHandler(), _PinnedHTTPSHandler())
    remaining = operation_deadline - time.monotonic()
    if remaining <= 0:
        return _result(url, FetchStatus.TRANSPORT_ERROR, None, "", b"", error="fetch deadline exceeded before connect")
    try:
        with opener.open(request, timeout=remaining) as response:
            http_status = response.getcode()
            headers = response.headers
            try:
                declared_length = _declared_content_length(headers)
            except ValueError as exc:
                return _result(url, FetchStatus.TRANSPORT_ERROR, http_status, _content_type(headers), b"", error=str(exc))
            try:
                body, too_large = read_bounded(response, max_bytes=max_bytes, deadline=operation_deadline)
            except http.client.IncompleteRead as exc:
                body = exc.partial if isinstance(exc.partial, bytes) else b""
                return _result(url, FetchStatus.TRANSPORT_ERROR, http_status, _content_type(headers), body, error="incomplete HTTP response")
            except (HTTPError, OSError, TypeError, TimeoutError, http.client.HTTPException) as exc:
                return _result(url, FetchStatus.TRANSPORT_ERROR, http_status, _content_type(headers), b"", error=str(exc))
            if declared_length is not None and not too_large and len(body) != declared_length:
                return _result(url, FetchStatus.TRANSPORT_ERROR, http_status, _content_type(headers), body, error="incomplete HTTP response")
            location = headers.get("Location")
            if 300 <= http_status < 400:
                return _result(url, FetchStatus.REDIRECT, http_status, _content_type(headers), body, too_large=too_large, redirect_location=location)
            if too_large:
                return _result(url, FetchStatus.TOO_LARGE, http_status, _content_type(headers), body, too_large=True)
            status = FetchStatus.OK if http_status == 200 else FetchStatus.HTTP_ERROR
            return _result(url, status, http_status, _content_type(headers), body)
    except HTTPError as exc:
        body, too_large, read_error = _read_error_body(exc, max_bytes, operation_deadline)
        location = exc.headers.get("Location") if exc.headers else None
        status = FetchStatus.REDIRECT if 300 <= exc.code < 400 else FetchStatus.HTTP_ERROR
        if too_large:
            status = FetchStatus.TOO_LARGE
        return _result(url, status, exc.code, _content_type(exc.headers or {}), body, too_large=too_large, redirect_location=location, error=read_error or str(exc))
    except (URLError, TimeoutError, OSError, http.client.HTTPException, TypeError, ValueError) as exc:
        return _result(url, FetchStatus.TRANSPORT_ERROR, None, "", b"", error=str(exc))
