from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from urllib.parse import unquote, urljoin, urlparse, urlunparse

from mks123_pipeline.evidence_bundle import (
    APPROVED_EVIDENCE_ROOT,
    BundleError,
    path_is_within,
    paths_overlap,
    publish_bundle,
    read_committed_json_with_marker,
)
from mks123_pipeline.manufacturer_evidence import (
    TRUSTED_DOMAIN_REGISTRY_SHA256,
    ManufacturerIdentity,
    classify_candidates,
    has_exact_product_page_signal,
    load_domain_registry,
    page_identity_text,
    registry_domains,
)
from mks123_pipeline.manufacturer_fetch import (
    MAX_BODY_BYTES,
    FetchStatus,
    _validate_limits,
    fetch_bounded,
)
from mks123_pipeline.manufacturer_fields import has_labeled_identity


def same_host_family(source_host: str, target_host: str, allowed_domains: set[str] | None = None) -> bool:
    source = source_host.lower().removeprefix("www.").rstrip(".")
    target = target_host.lower().removeprefix("www.").rstrip(".")
    if source == target:
        return True
    if not allowed_domains:
        return False
    return any(
        (source == domain or source.endswith(f".{domain}")) and (target == domain or target.endswith(f".{domain}"))
        for domain in allowed_domains
    )


_SENSITIVE_CONTENT_RE = re.compile(rb"(?i)(?:authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|csrf[_-]?token|xsrf[_-]?token|password|passwd|secret|session(?:[_-]?id)?|credential|private[_-]?key|bearer|x-amz-[a-z0-9_-]+)\s*(?:[:=]|\b[^\s<>\"']{0,2})\s*[\"']?[^\s<>\"']{4,}|-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----")
_SENSITIVE_PATH_RE = re.compile(r"(?i)^(?:token|secret|session(?:[-_]?id)?|auth|credential|signature|password|passwd|api[-_]?key|access[-_]?token|bearer)$")


def _url_for_output(url: object) -> str:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(char) < 32 for char in url):
        return "[invalid-or-redacted-url]"
    try:
        parsed = urlparse(url)
        path_parts = [unquote(part) for part in parsed.path.split("/") if part]
        sensitive_path = any(_SENSITIVE_PATH_RE.fullmatch(part) or len(part) > 128 for part in path_parts)
        sensitive = bool(parsed.fragment or parsed.username or parsed.password or parsed.query or sensitive_path)
        if not sensitive:
            return url
        if not parsed.scheme or not parsed.hostname:
            return "[invalid-or-redacted-url]"
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        safe_path = "/[redacted-path]" if sensitive_path else parsed.path
        return urlunparse((parsed.scheme, host, safe_path, "", "", ""))
    except ValueError:
        return "[invalid-or-redacted-url]"


def _error_for_output(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    redacted = re.sub(r"https?://[^\s<>\"']+", lambda match: _url_for_output(match.group(0)), text)
    return redacted[:1024]


def _sensitive_body(body: bytes) -> bool:
    return bool(_SENSITIVE_CONTENT_RE.search(body[:MAX_BODY_BYTES]))


def _fetchable_url(url: object) -> bool:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(char) < 32 for char in url):
        return False
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or port not in {None, 443} or parsed.fragment:
        return False
    return not parsed.query


def _host_allowed(host: str, allowed_domains: set[str]) -> bool:
    normalized_host = host.lower().removeprefix("www.").rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in allowed_domains)


def _urls(value: object) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for child in value.values():
            result.extend(_urls(child))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for child in value:
            result.extend(_urls(child))
        return result
    if isinstance(value, str):
        return re.findall(r'https?://[^\s<>"\']+', value)
    return []


def _text_value(*values: object) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _consistent_value(first: object, second: object, field: str) -> str:
    values: list[str] = []
    for value in (first, second):
        if value is None:
            continue
        if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(ord(char) < 32 for char in value):
            raise TypeError(f"preview {field} value is invalid or empty")
        values.append(value.strip())
    if len(values) == 2 and values[0].casefold() != values[1].casefold():
        raise ValueError(f"preview {field} values disagree across sources")
    return values[0] if values else ""


def _identity(item: dict) -> ManufacturerIdentity:
    identifiers = item.get("identifiers")
    if not isinstance(identifiers, dict):
        raise TypeError("preview item identifiers must be an object")
    clone = identifiers.get("clone") if isinstance(identifiers.get("clone"), dict) else {}
    netlab = identifiers.get("netlab") if isinstance(identifiers.get("netlab"), dict) else {}
    manufacturer = _consistent_value(clone.get("manufacturer_name"), netlab.get("manufacturer"), "manufacturer")
    model = _consistent_value(clone.get("model"), netlab.get("model"), "model")
    mpn = _consistent_value(clone.get("mpn"), netlab.get("mpn"), "MPN") or None
    ean = _consistent_value(clone.get("ean"), netlab.get("ean"), "EAN") or None
    return ManufacturerIdentity(manufacturer, model, mpn, ean)


def _body_text(result) -> str:
    if result.content_type in {"text/html", "application/xhtml+xml", "text/plain", "application/xml", "text/xml"}:
        return result.body.decode("utf-8")
    return ""


def _discovery_handoff(preview_items: list[dict]) -> dict[str, object]:
    discovered: set[tuple[str, str]] = set()
    requested_urls: set[str] = set()
    for item in preview_items:
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            continue
        bundle = provenance.get("manufacturer_discovery_search_bundle")
        digest = provenance.get("manufacturer_discovery_search_sha256")
        urls = provenance.get("manufacturer_discovery_urls")
        if bundle is None and digest is None and urls is None:
            continue
        if not isinstance(bundle, str) or not bundle or len(bundle) > 200 or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest) or not isinstance(urls, list) or len(urls) > 32:
            raise ValueError("discovery search handoff metadata is malformed")
        if any(not isinstance(url_value, str) or not _fetchable_url(url_value) for url_value in urls):
            raise ValueError("discovery search URL metadata is malformed")
        discovered.add((bundle, digest.casefold()))
        requested_urls.update(urls)
    if not discovered:
        return {"bundle": None, "sha256": None, "urls": []}
    if len(discovered) != 1:
        raise ValueError("discovery search handoff metadata disagrees across preview items")
    bundle, expected_digest = next(iter(discovered))
    search_path = APPROVED_EVIDENCE_ROOT / bundle / "SEARCH_RESULTS.json"
    if not path_is_within(search_path.parent, APPROVED_EVIDENCE_ROOT):
        raise BundleError("discovery search bundle is outside approved root")
    marker, data, raw = read_committed_json_with_marker(search_path)
    if marker.get("bundle") != "manufacturer-discovery-search-v1" or data.get("read_only") is not True or data.get("production_writes") != 0 or data.get("publication_enabled") is not False:
        raise BundleError("discovery search bundle is not a committed read-only artifact")
    actual_digest = hashlib.sha256(raw).hexdigest()
    if actual_digest != expected_digest:
        raise BundleError("discovery search handoff hash mismatch")
    search_urls: set[str] = set()
    queries = data.get("queries")
    if not isinstance(queries, list) or len(queries) > 100:
        raise BundleError("discovery search artifact query schema is invalid")
    for packet in queries:
        if not isinstance(packet, dict) or not isinstance(packet.get("results"), list) or len(packet["results"]) > 100:
            raise BundleError("discovery search result schema is invalid")
        for result in packet["results"]:
            if isinstance(result, dict) and isinstance(result.get("url"), str) and _fetchable_url(result["url"]):
                search_urls.add(result["url"])
    if not requested_urls.issubset(search_urls):
        raise BundleError("discovery URL is not present in pinned search results")
    return {"bundle": bundle, "sha256": actual_digest, "urls": sorted(requested_urls)}


def _runtime_code_hashes() -> dict[str, str]:
    repo = Path(__file__).resolve().parent.parent
    relative_paths = (
        "scripts/run_manufacturer_source_fetch.py",
        "mks123_pipeline/manufacturer_fetch.py",
        "mks123_pipeline/manufacturer_evidence.py",
        "mks123_pipeline/manufacturer_fields.py",
        "mks123_pipeline/evidence_bundle.py",
        "scripts/run_manufacturer_field_resolution.py",
    )
    return {relative: hashlib.sha256((repo / relative).read_bytes()).hexdigest() for relative in relative_paths}


def _fallback_entry(result, url: str, error: object) -> dict:
    return {
        "url": _url_for_output(url),
        "status": result.status.value,
        "http_status": result.http_status,
        "content_type": result.content_type,
        "bytes_read": result.bytes_read,
        "body_sha256": result.body_sha256,
        "too_large": result.too_large,
        "redirect_location": _url_for_output(result.redirect_location) if result.redirect_location is not None else None,
        "error": _error_for_output(error),
        "retrieved_at": result.retrieved_at,
        "body_b64": "",
        "body_persisted": False,
        "sensitive_content": True,
        "request_started": True,
        "match_status": "body_not_evaluated",
    }


def _attempt_failure_entry(url: str, error: object, retrieved_at: str) -> dict:
    empty_hash = hashlib.sha256(b"").hexdigest()
    return {
        "url": _url_for_output(url),
        "status": "transport_error",
        "http_status": None,
        "content_type": "",
        "bytes_read": 0,
        "body_sha256": empty_hash,
        "too_large": False,
        "redirect_location": None,
        "error": _error_for_output(error),
        "retrieved_at": retrieved_at,
        "body_b64": "",
        "body_persisted": False,
        "sensitive_content": True,
        "request_started": True,
        "match_status": "body_not_evaluated",
    }


def _code_manifest_digest(manifest: dict[str, str]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _entry(result, url: str, identity: ManufacturerIdentity, trusted_official_domains: set[str]) -> dict:
    sensitive = _sensitive_body(result.body)
    entry = {
        "url": _url_for_output(url),
        "status": result.status.value,
        "http_status": result.http_status,
        "content_type": result.content_type,
        "bytes_read": result.bytes_read,
        "body_sha256": result.body_sha256,
        "too_large": result.too_large,
        "redirect_location": _url_for_output(result.redirect_location) if result.redirect_location is not None else None,
        "error": _error_for_output(result.error),
        "retrieved_at": result.retrieved_at,
        "body_b64": "" if sensitive else base64.b64encode(result.body).decode("ascii"),
        "body_persisted": not sensitive,
        "sensitive_content": sensitive,
        "request_started": True,
        "match_status": "sensitive_body_not_evaluated" if sensitive else "not_evaluated",
    }
    if sensitive:
        return entry
    text = _body_text(result)
    if result.status is FetchStatus.OK and text:
        title_text, heading_text = page_identity_text(text)
        candidate_result = classify_candidates(
            identity,
            [{"title": "", "url": url, "description": f"{title_text} {heading_text}"}],
            official_domains=trusted_official_domains,
        )
        candidate = candidate_result.candidates[0]
        product_page_signal = has_exact_product_page_signal(url, text, identity.model)
        exact = candidate.official_domain and candidate.manufacturer_match and candidate.exact_model and has_labeled_identity(text, identity) and product_page_signal
        entry.update(
            {
                "manufacturer_match": candidate.manufacturer_match,
                "exact_model": candidate.exact_model,
                "exact_mpn": candidate.exact_mpn,
                "exact_ean": candidate.exact_ean,
                "product_page_signal": product_page_signal,
                "match_status": "declared_source_exact" if exact else "declared_source_model_mention" if candidate.manufacturer_match and candidate.exact_model else "declared_source_no_exact_match",
                "body_text": text,
                "body_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        )
    return entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded read-only fetch of source-declared manufacturer URLs.")
    parser.add_argument("--preview", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--domain-registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-bytes", type=int, default=MAX_BODY_BYTES)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--expected-preview-sha256", required=True)
    parser.add_argument("--expected-selection-sha256", required=True)
    parser.add_argument("--expected-registry-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if any(not path_is_within(path.parent, APPROVED_EVIDENCE_ROOT) for path in (args.preview, args.selection, args.domain_registry)):
            raise BundleError("input bundle is outside approved evidence root")
        if any(paths_overlap(args.output, path.parent) for path in (args.preview, args.selection, args.domain_registry)):
            raise BundleError("output overlaps an input bundle")
        _validate_limits(args.max_bytes, args.timeout)
        batch_deadline = monotonic() + min(600.0, max(args.timeout, 1.0) * 20.0)
        preview_marker, preview, preview_bytes = read_committed_json_with_marker(args.preview)
        selection_marker, selection, selection_bytes = read_committed_json_with_marker(args.selection)
        registry_marker, registry_data, registry_bytes = read_committed_json_with_marker(args.domain_registry)
        if any(marker.get("bundle") != "manufacturer-inputs-v1" for marker in (preview_marker, selection_marker, registry_marker)):
            raise BundleError("preview/selection/registry bundle identity is not pinned")
        expected_hashes = {"preview": args.expected_preview_sha256, "selection": args.expected_selection_sha256, "registry": args.expected_registry_sha256}
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in expected_hashes.values()):
            raise ValueError("an expected input SHA-256 is malformed")
        actual_hashes = {"preview": hashlib.sha256(preview_bytes).hexdigest(), "selection": hashlib.sha256(selection_bytes).hexdigest(), "registry": hashlib.sha256(registry_bytes).hexdigest()}
        if any(actual_hashes[key].casefold() != value.casefold() for key, value in expected_hashes.items()):
            raise BundleError("source fetch input does not match externally pinned SHA-256")
        if actual_hashes["registry"] != TRUSTED_DOMAIN_REGISTRY_SHA256:
            raise BundleError("domain registry is outside trusted digest pin")
        if monotonic() >= batch_deadline:
            raise BundleError("batch deadline exceeded during input validation")
        if not isinstance(preview.get("items"), list) or not isinstance(selection.get("items"), list):
            raise TypeError("preview/selection items must be lists")
        discovery_handoff = _discovery_handoff(preview["items"])
        discovery_urls = set(discovery_handoff.get("urls", []))
        if preview.get("read_only") is not True or preview.get("production_writes") != 0 or preview.get("publication_enabled") is not False:
            raise ValueError("preview violates read-only contract")
        if selection.get("read_only") is not True or selection.get("production_writes") != 0 or selection.get("publication_enabled") is not False:
            raise ValueError("selection violates read-only contract")
        registry = load_domain_registry(registry_data)
        selected_packets = selection["items"]
        if any(not isinstance(x, dict) or not isinstance(x.get("catalog_sku"), str) or not x["catalog_sku"].strip() for x in selected_packets):
            raise TypeError("selection items require non-empty catalog_sku strings")
        selected = [x["catalog_sku"] for x in selected_packets]
        if len(selected) != 10 or len(set(selected)) != 10:
            raise ValueError("selection must contain exactly 10 unique SKU values")
        total_body_bytes = 0
        max_total_body_bytes = min(5_000_000, args.max_bytes * len(selected))
        if any(not isinstance(x, dict) or not isinstance(x.get("catalog_sku"), str) or not isinstance(x.get("name"), str) or len(x["catalog_sku"]) > 128 or len(x["name"]) > 1024 or any(ord(char) < 32 for char in f"{x['catalog_sku']}{x['name']}") for x in preview["items"]):
            raise TypeError("preview items require bounded catalog_sku and name strings")
        preview_skus = [x["catalog_sku"] for x in preview["items"]]
        if len(preview_skus) != len(set(preview_skus)):
            raise ValueError("preview contains duplicate catalog_sku values")
        preview_by_sku = {x["catalog_sku"]: x for x in preview["items"]}
        if set(selected) - set(preview_by_sku):
            raise ValueError("selection contains SKU missing from preview")
        results = []
        redirects_followed = 0
        total_discovered = 0
        total_rejected = 0
        total_blocked = 0
        total_requests = 0
        total_responses = 0
        for sku in selected:
            item = preview_by_sku[sku]
            try:
                identity = _identity(item)
            except (TypeError, ValueError) as exc:
                results.append({"catalog_sku": sku, "name": item["name"], "identity": None, "fetched": [], "item_exception": _error_for_output(str(exc)), "metrics": {"urls_discovered": 0, "urls_rejected": 0, "blocked_urls": 0, "http_requests_started": 0, "responses_received": 0}})
                continue
            allowed_domains = registry_domains(registry, identity.manufacturer, trusted_only=False)
            trusted_domains = registry_domains(registry, identity.manufacturer, trusted_only=True)
            urls = []
            for key in ("facts", "compatibility_evidence", "provenance"):
                urls.extend(_urls(item.get(key)))
            unique_urls = list(dict.fromkeys(urls))
            item_metrics = {"urls_discovered": min(len(unique_urls), 8), "urls_rejected": 0, "blocked_urls": 0, "http_requests_started": 0, "responses_received": 0}
            total_discovered += item_metrics["urls_discovered"]
            fetched = []
            for url in unique_urls[:8]:
                evidence_url = _url_for_output(url)
                if not _fetchable_url(url):
                    item_metrics["urls_rejected"] += 1
                    total_rejected += 1
                    fetched.append({"url": evidence_url, "status": "input_or_fetch_error", "error": "source URL rejected before network", "match_status": "not_fetched"})
                    continue
                try:
                    parsed_url = urlparse(url)
                    host = (parsed_url.hostname or "").lower().removeprefix("www.").rstrip(".")
                except ValueError as exc:
                    fetched.append({"url": evidence_url, "status": "input_or_fetch_error", "error": _error_for_output(str(exc)), "match_status": "not_fetched"})
                    continue
                if not _host_allowed(host, allowed_domains):
                    item_metrics["blocked_urls"] += 1
                    total_blocked += 1
                    fetched.append({"url": evidence_url, "status": "blocked_untrusted_domain", "match_status": "not_fetched"})
                    continue
                current_url = url
                visited_urls = {url}
                redirects_for_url = 0
                redirected_from: str | None = None
                redirected_location: str | None = None
                remaining_bytes = min(args.max_bytes, max_total_body_bytes - total_body_bytes)
                while True:
                    if monotonic() >= batch_deadline or remaining_bytes <= 0:
                        if not fetched:
                            item_metrics["urls_rejected"] += 1
                            total_rejected += 1
                            fetched.append({"url": _url_for_output(current_url), "status": "input_or_fetch_error", "error": "batch fetch budget exceeded", "match_status": "not_fetched"})
                        break
                    result = None
                    try:
                        operation_deadline = min(monotonic() + args.timeout, batch_deadline)
                        timeout = min(args.timeout, max(0.001, batch_deadline - monotonic()))
                        item_metrics["http_requests_started"] += 1
                        total_requests += 1
                        result = fetch_bounded(current_url, allowed_domains, max_bytes=remaining_bytes, timeout=timeout, deadline=operation_deadline)
                        if result.http_status is not None:
                            item_metrics["responses_received"] += 1
                            total_responses += 1
                        total_body_bytes += result.bytes_read
                        try:
                            entry = _entry(result, current_url, identity, trusted_domains)
                        except (IndexError, KeyError, TypeError, UnicodeError, ValueError) as exc:
                            entry = _fallback_entry(result, current_url, exc)
                        if current_url in discovery_urls:
                            entry["discovery_search_url"] = _url_for_output(current_url)
                        if redirected_from is not None:
                            redirects_followed += 1
                            entry["redirect_followed_from"] = redirected_from
                            entry["redirect_location_raw"] = redirected_location
                        fetched.append(entry)
                        remaining_bytes -= result.bytes_read
                    except (ValueError, OSError) as exc:
                        entry = _fallback_entry(result, current_url, exc) if result is not None else _attempt_failure_entry(current_url, exc, datetime.now(UTC).isoformat())
                        if current_url in discovery_urls:
                            entry["discovery_search_url"] = _url_for_output(current_url)
                        if redirected_from is not None:
                            redirects_followed += 1
                            entry["redirect_followed_from"] = redirected_from
                            entry["redirect_location_raw"] = redirected_location
                        fetched.append(entry)
                        break
                    location = result.redirect_location
                    if result.status is not FetchStatus.REDIRECT or not location or redirects_for_url >= 3 or remaining_bytes <= 0 or total_body_bytes >= max_total_body_bytes:
                        break
                    try:
                        target_url = urljoin(current_url, location)
                        target_host = urlparse(target_url).hostname
                        normalized_target_host = target_host.lower().removeprefix("www.").rstrip(".") if target_host else None
                    except ValueError:
                        break
                    if not normalized_target_host or target_url in visited_urls or not _fetchable_url(target_url) or not same_host_family(host, normalized_target_host, allowed_domains) or not _host_allowed(normalized_target_host, allowed_domains):
                        break
                    visited_urls.add(target_url)
                    redirects_for_url += 1
                    redirected_from = _url_for_output(current_url)
                    redirected_location = _url_for_output(location)
                    current_url = target_url
            results.append({"catalog_sku": sku, "name": item["name"], "identity": identity.__dict__, "fetched": fetched, "metrics": item_metrics})
        summary = {
            "items": len(results),
            "urls_attempted": sum(len(x["fetched"]) for x in results),
            "urls_discovered": total_discovered,
            "urls_rejected": total_rejected,
            "blocked_urls": total_blocked,
            "http_requests_started": total_requests,
            "responses_received": total_responses,
            "http_200": sum(1 for x in results for y in x["fetched"] if y.get("http_status") == 200),
            "declared_source_exact": sum(1 for x in results for y in x["fetched"] if y.get("match_status") == "declared_source_exact"),
            "redirects_followed_same_host": redirects_followed,
            "production_writes": 0,
            "publication_enabled": False,
        }
        code_hashes = _runtime_code_hashes()
        artifact = {"probe_version": "manufacturer-source-fetch-v4", "read_only": True, "production_writes": 0, "publication_enabled": False, "preview_sha256": actual_hashes["preview"], "selection_sha256": actual_hashes["selection"], "domain_registry_sha256": actual_hashes["registry"], "expected_preview_sha256": args.expected_preview_sha256.casefold(), "expected_selection_sha256": args.expected_selection_sha256.casefold(), "expected_registry_sha256": args.expected_registry_sha256.casefold(), "discovery_search_bundle": discovery_handoff["bundle"], "discovery_search_sha256": discovery_handoff["sha256"], "discovery_search_urls": sorted(discovery_urls), "producer_code_sha256": code_hashes["scripts/run_manufacturer_source_fetch.py"], "code_manifest_sha256": _code_manifest_digest(code_hashes), "code_sha256": code_hashes, "summary": summary, "items": results}
        lines = [
            "# Manufacturer source fetch — bounded read-only probe",
            "",
            f"- Items: **{summary['items']}**",
            f"- URL results: **{summary['urls_attempted']}**",
            f"- URLs discovered (initial, capped): **{summary['urls_discovered']}**",
            f"- URLs rejected before request: **{summary['urls_rejected']}**",
            f"- URLs blocked by domain policy: **{summary['blocked_urls']}**",
            f"- HTTP requests started: **{summary['http_requests_started']}**",
            f"- HTTP responses received: **{summary['responses_received']}**",
            f"- HTTP 200: **{summary['http_200']}**",
            f"- Same-host redirects followed (max 3 hops): **{summary['redirects_followed_same_host']}**",
            f"- Exact product-page matches: **{summary['declared_source_exact']}**",
            "- Production writes: **0**",
            "- Publication: **false**",
            "",
            "Source-declared domains are fetch candidates only. Exact matches require body manufacturer/model/MPN plus a product-page signal; no field is auto-accepted.",
            "",
        ]
        for item in results:
            exact = sum(1 for fetched in item["fetched"] if fetched.get("match_status") == "declared_source_exact")
            lines.append(f"- `{item['catalog_sku']}` — {item['name']}: {len(item['fetched'])} URL result(s), exact={exact}")
        report = "\n".join(lines) + "\n"
        if monotonic() >= batch_deadline:
            raise BundleError("batch deadline exceeded before bundle publication")
        publish_bundle(
            args.output,
            {
                "FETCH_RESULTS.json": json.dumps(artifact, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
                "REPORT.md": report.encode("utf-8"),
            },
            bundle_id="manufacturer-source-fetch-v4",
            approved_root=APPROVED_EVIDENCE_ROOT,
        )
    except (BundleError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "PASS", "output": str(args.output), "summary": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
