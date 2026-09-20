from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

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
    load_domain_registry,
    registry_domains,
)
from mks123_pipeline.manufacturer_fetch import MAX_BODY_BYTES
from mks123_pipeline.manufacturer_fields import resolve_fetch_item

_MAX_FETCH_BODY_BYTES = MAX_BODY_BYTES
_MAX_FETCH_ENTRIES_PER_ITEM = 32
_CODE_MANIFEST_PATHS = (
    "scripts/run_manufacturer_source_fetch.py",
    "mks123_pipeline/manufacturer_fetch.py",
    "mks123_pipeline/manufacturer_evidence.py",
    "mks123_pipeline/manufacturer_fields.py",
    "mks123_pipeline/evidence_bundle.py",
    "scripts/run_manufacturer_field_resolution.py",
)
_ALLOWED_FETCH_STATUSES = {"ok", "http_error", "redirect", "too_large", "transport_error", "blocked_untrusted_domain", "input_or_fetch_error"}


def _current_code_hashes() -> dict[str, str]:
    repo = Path(__file__).resolve().parent.parent
    return {relative: hashlib.sha256((repo / relative).read_bytes()).hexdigest() for relative in _CODE_MANIFEST_PATHS}


def _code_manifest_digest(manifest: dict[str, str]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _validate_fetch_entry(entry: object, seen_urls: set[str]) -> None:
    if not isinstance(entry, dict):
        raise TypeError("fetch entries must be objects")
    url = entry.get("url")
    if not isinstance(url, str) or not url or len(url) > 4096 or any(ord(char) < 32 for char in url):
        raise TypeError("fetch entry url must be a bounded string")
    if url in seen_urls:
        raise ValueError(f"duplicate fetch URL: {url}")
    seen_urls.add(url)
    status = entry.get("status")
    if not isinstance(status, str) or status not in _ALLOWED_FETCH_STATUSES:
        raise ValueError(f"unsupported fetch status: {status!r}")
    http_status = entry.get("http_status")
    if http_status is not None and (isinstance(http_status, bool) or not isinstance(http_status, int) or not 100 <= http_status <= 599):
        raise TypeError("fetch entry http_status is invalid")
    for field, limit in (("content_type", 256), ("match_status", 128), ("redirect_location", 4096), ("redirect_followed_from", 4096), ("redirect_location_raw", 4096), ("error", 1024), ("retrieved_at", 128)):
        if field in entry and entry[field] is not None and (not isinstance(entry[field], str) or len(entry[field]) > limit or any(ord(char) < 32 for char in entry[field])):
            raise TypeError(f"fetch entry {field} is invalid or unbounded")
    bytes_read = entry.get("bytes_read")
    if bytes_read is not None and (isinstance(bytes_read, bool) or not isinstance(bytes_read, int) or not 0 <= bytes_read <= _MAX_FETCH_BODY_BYTES):
        raise ValueError("fetch entry bytes_read is outside bounds")
    if "too_large" in entry and not isinstance(entry["too_large"], bool):
        raise TypeError("fetch entry too_large must be boolean")
    if status in {"ok", "http_error", "redirect", "too_large", "transport_error"}:
        if entry.get("request_started") is not True:
            raise ValueError("fetch response entry must mark request_started=true")
        required_fields = {"content_type", "bytes_read", "body_sha256", "too_large", "redirect_location", "error", "retrieved_at", "body_b64", "body_persisted", "sensitive_content", "request_started", "match_status"}
        missing_fields = sorted(required_fields - entry.keys())
        if missing_fields:
            raise ValueError(f"fetch response entry is missing fields: {missing_fields}")
    sensitive = entry.get("sensitive_content", False)
    if not isinstance(sensitive, bool):
        raise TypeError("fetch entry sensitive_content must be boolean")
    if "body_persisted" in entry and not isinstance(entry["body_persisted"], bool):
        raise TypeError("fetch entry body_persisted must be boolean")
    raw_b64 = entry.get("body_b64")
    if sensitive:
        if entry.get("body_persisted") is not False or raw_b64 not in {None, ""} or "body_text" in entry:
            raise ValueError("sensitive fetch body must not be persisted")
        if not isinstance(entry.get("body_sha256"), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["body_sha256"]):
            raise ValueError("sensitive fetch body hash is missing")
        return
    if "body_persisted" in entry and entry["body_persisted"] is not True:
        raise ValueError("normal fetch body must be persisted")
    if isinstance(entry.get("body_text"), str) and raw_b64 is None:
        raise ValueError("fetch entry body_text requires body_b64")
    if raw_b64 is not None:
        if not isinstance(raw_b64, str) or len(raw_b64) > 4 * ((_MAX_FETCH_BODY_BYTES + 2) // 3) + 4:
            raise ValueError("fetch entry body_b64 is outside bounds")
        try:
            raw_body = base64.b64decode(raw_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("fetch entry body_b64 is malformed") from exc
        if len(raw_body) > _MAX_FETCH_BODY_BYTES:
            raise ValueError("fetch entry decoded body exceeds bounds")
        if bytes_read is not None and len(raw_body) != bytes_read:
            raise ValueError("fetch entry bytes_read disagrees with body_b64")
        if entry.get("body_sha256") != hashlib.sha256(raw_body).hexdigest():
            raise ValueError("fetch entry body_sha256 disagrees with body_b64")
        if isinstance(entry.get("body_text"), str):
            try:
                decoded_body = raw_body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("fetch entry body_text is not valid UTF-8") from exc
            if decoded_body != entry["body_text"]:
                raise ValueError("fetch entry body_text disagrees with body_b64")
            if entry.get("body_text_sha256") != hashlib.sha256(entry["body_text"].encode("utf-8")).hexdigest():
                raise ValueError("fetch entry body_text_sha256 disagrees with body_text")
    if isinstance(entry.get("body_text"), str) and len(entry["body_text"].encode("utf-8")) > _MAX_FETCH_BODY_BYTES:
        raise ValueError("fetch entry body_text is outside bounds")


def _bounded_text(value: object, *, field: str, limit: int, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value.strip()) or len(value) > limit or any(ord(char) < 32 for char in value):
        raise TypeError(f"{field} is invalid or unbounded")
    return value


def _validate_item_identity(item: dict[str, Any], sku: str) -> None:
    identity = item.get("identity")
    if identity is None:
        _bounded_text(item.get("item_exception"), field=f"item {sku} item_exception", limit=1024, required=True)
        return
    if not isinstance(identity, dict):
        raise TypeError(f"item {sku} identity must be object or null")
    _bounded_text(identity.get("manufacturer"), field=f"item {sku} identity.manufacturer", limit=256, required=True)
    _bounded_text(identity.get("model"), field=f"item {sku} identity.model", limit=256, required=True)
    for field, limit in (("mpn", 256), ("ean", 64)):
        if field in identity:
            _bounded_text(identity[field], field=f"item {sku} identity.{field}", limit=limit, required=True)


def _validate_item_metrics(item: dict[str, Any], sku: str) -> None:
    metrics = item.get("metrics")
    if not isinstance(metrics, dict):
        raise TypeError(f"item {sku} metrics must be an object")
    for field in ("urls_discovered", "urls_rejected", "blocked_urls", "http_requests_started", "responses_received"):
        if isinstance(metrics.get(field), bool) or not isinstance(metrics.get(field), int) or metrics[field] < 0:
            raise ValueError(f"item {sku} metric {field} is invalid")
    if metrics["urls_discovered"] > 8 or metrics["urls_rejected"] + metrics["blocked_urls"] > metrics["urls_discovered"] or metrics["http_requests_started"] > metrics["urls_discovered"] * 4 or metrics["responses_received"] > metrics["http_requests_started"]:
        raise ValueError(f"item {sku} metrics are inconsistent")


def _validate_input(data: dict[str, Any]) -> list[dict[str, Any]]:
    if data.get("read_only") is not True or data.get("production_writes") != 0 or data.get("publication_enabled") is not False:
        raise ValueError("fetch evidence violates read-only contract")
    if data.get("probe_version") != "manufacturer-source-fetch-v4" or not isinstance(data.get("summary"), dict):
        raise ValueError("unexpected fetch producer schema")
    code_manifest = data.get("code_sha256")
    if not isinstance(code_manifest, dict) or set(code_manifest) != set(_CODE_MANIFEST_PATHS) or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in code_manifest.values()):
        raise ValueError("fetch producer code manifest is missing or malformed")
    if data.get("producer_code_sha256") != code_manifest["scripts/run_manufacturer_source_fetch.py"]:
        raise ValueError("fetch producer code identity is inconsistent")
    if code_manifest != _current_code_hashes():
        raise ValueError("fetch producer code manifest does not match current code")
    code_manifest_digest = data.get("code_manifest_sha256")
    if not isinstance(code_manifest_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", code_manifest_digest) or _code_manifest_digest(code_manifest) != code_manifest_digest.casefold():
        raise ValueError("fetch code manifest digest is invalid")
    for field in ("preview_sha256", "selection_sha256", "domain_registry_sha256", "expected_preview_sha256", "expected_selection_sha256", "expected_registry_sha256"):
        if not isinstance(data.get(field), str) or not re.fullmatch(r"[0-9a-fA-F]{64}", data[field]):
            raise ValueError(f"fetch producer {field} is missing or malformed")
    for expected_field, actual_field in (("expected_preview_sha256", "preview_sha256"), ("expected_selection_sha256", "selection_sha256"), ("expected_registry_sha256", "domain_registry_sha256")):
        if data[expected_field].casefold() != data[actual_field].casefold():
            raise ValueError("fetch producer digest handoff is inconsistent")
    discovery_bundle = data.get("discovery_search_bundle")
    discovery_digest = data.get("discovery_search_sha256")
    discovery_urls = data.get("discovery_search_urls")
    if not isinstance(discovery_urls, list) or len(discovery_urls) > 32 or any(not isinstance(url, str) or not url.startswith("https://") or "?" in url or "#" in url for url in discovery_urls):
        raise ValueError("discovery search URL list is malformed")
    if len(set(discovery_urls)) != len(discovery_urls) or (discovery_bundle is None and discovery_urls):
        raise ValueError("discovery search URL list is not canonically bound")
    if (discovery_bundle is not None or discovery_digest is not None) and (not isinstance(discovery_bundle, str) or not discovery_bundle or len(discovery_bundle) > 200 or not isinstance(discovery_digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", discovery_digest) or not discovery_urls):
        raise ValueError("fetch discovery-search handoff is missing or malformed")
    items = data.get("items")
    if not isinstance(items, list) or not items or len(items) > 1000:
        raise TypeError("fetch evidence items must be a bounded non-empty list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("catalog_sku"), str) or not item["catalog_sku"].strip() or not isinstance(item.get("fetched"), list) or len(item["fetched"]) > _MAX_FETCH_ENTRIES_PER_ITEM:
            raise TypeError("each fetch item has an invalid bounded shape")
        sku = item["catalog_sku"]
        if sku in seen:
            raise ValueError(f"duplicate catalog_sku: {sku}")
        if len(sku) > 128:
            raise ValueError(f"catalog_sku is too long: {sku}")
        seen.add(sku)
        if sku != sku.strip():
            raise ValueError(f"catalog_sku contains surrounding whitespace: {sku}")
        _bounded_text(item.get("name"), field=f"item {sku} name", limit=1024, required=True)
        _validate_item_identity(item, sku)
        _validate_item_metrics(item, sku)
        seen_urls: set[str] = set()
        for entry in item["fetched"]:
            _validate_fetch_entry(entry, seen_urls)
        result.append(item)
    summary = data["summary"]
    for field in ("items", "urls_attempted", "urls_discovered", "urls_rejected", "blocked_urls", "http_requests_started", "responses_received", "http_200", "declared_source_exact", "redirects_followed_same_host"):
        if isinstance(summary.get(field), bool) or not isinstance(summary.get(field), int) or summary[field] < 0:
            raise ValueError(f"fetch summary {field} is invalid")
    flat_entries = [entry for item in result for entry in item["fetched"]]
    for entry in flat_entries:
        if "discovery_search_url" in entry and (not isinstance(entry["discovery_search_url"], str) or entry["discovery_search_url"] not in set(discovery_urls)):
            raise ValueError("fetch entry has an orphan discovery URL binding")
    metric_totals = {field: sum(item["metrics"][field] for item in result) for field in ("urls_discovered", "urls_rejected", "blocked_urls", "http_requests_started", "responses_received")}
    if (
        summary["items"] != len(result)
        or summary["urls_attempted"] != len(flat_entries)
        or any(summary[field] != metric_totals[field] for field in metric_totals)
        or summary["http_requests_started"] != sum(entry.get("request_started") is True for entry in flat_entries)
        or summary["responses_received"] != sum(entry.get("http_status") is not None for entry in flat_entries)
        or summary["http_200"] != sum(entry.get("http_status") == 200 for entry in flat_entries)
        or summary["declared_source_exact"] != sum(entry.get("match_status") == "declared_source_exact" for entry in flat_entries)
        or summary["redirects_followed_same_host"] != sum("redirect_followed_from" in entry for entry in flat_entries)
    ):
        raise ValueError("fetch summary is inconsistent with entries or item metrics")
    return result


def _report(artifact: dict[str, Any]) -> str:
    summary = artifact["summary"]
    lines = [
        "# Manufacturer field resolution — read-only proposal",
        "",
        f"- Items: **{summary['items']}**",
        f"- Items with proposal candidates: **{summary['proposal_items']}**",
        f"- Proposal field candidates: **{summary['proposal_fields']}**",
        f"- Items without exact source: **{summary['no_exact_source']}**",
        f"- Items with grouped/manual exceptions: **{summary['items_with_exceptions']}**",
        f"- Exception entries: **{summary['exception_entries']}**",
        "- Auto apply: **false**",
        "- Compatibility relations: **0**",
        "- Production writes: **0**",
        "- Publication: **false**",
        "",
        "Exact identity and body hashes are recomputed from the committed fetch bundle using only verified registry domains. Candidates remain staged; no catalog, CMS, media, or compatibility write is performed.",
        "",
        "## Grouped exception queue",
        "",
    ]
    for reason, count in artifact["summary"]["exception_groups"].items():
        lines.append(f"- `{reason}` — **{count}** item(s)")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve exact manufacturer page fields without applying catalog changes.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--domain-registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--expected-producer-code-sha256", required=True)
    parser.add_argument("--expected-code-manifest-sha256", required=True)
    parser.add_argument("--expected-resolver-code-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if not path_is_within(args.input.parent, APPROVED_EVIDENCE_ROOT) or not path_is_within(args.domain_registry.parent, APPROVED_EVIDENCE_ROOT):
            raise BundleError("input bundle is outside approved evidence root")
        if paths_overlap(args.output, args.input.parent) or paths_overlap(args.output, args.domain_registry.parent):
            raise BundleError("output overlaps an input bundle")
        input_marker, data, input_bytes = read_committed_json_with_marker(args.input)
        if args.input.name != "FETCH_RESULTS.json" or input_marker.get("bundle") != "manufacturer-source-fetch-v4":
            raise BundleError("input is not a committed manufacturer-source-fetch-v4 bundle")
        if not isinstance(args.expected_input_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_input_sha256):
            raise ValueError("expected input SHA-256 is malformed")
        actual_input_hash = hashlib.sha256(input_bytes).hexdigest()
        if actual_input_hash.casefold() != args.expected_input_sha256.casefold():
            raise BundleError("input does not match externally pinned SHA-256")
        if data.get("probe_version") != "manufacturer-source-fetch-v4" or not isinstance(data.get("items"), list) or not isinstance(data.get("summary"), dict):
            raise BundleError("fetch input has an unexpected producer/schema")
        producer_code_hash = data.get("producer_code_sha256")
        if not isinstance(args.expected_producer_code_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_producer_code_sha256) or not isinstance(producer_code_hash, str) or producer_code_hash.casefold() != args.expected_producer_code_sha256.casefold():
            raise BundleError("fetch producer code does not match external handoff pin")
        if not isinstance(args.expected_resolver_code_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_resolver_code_sha256) or args.expected_resolver_code_sha256.casefold() != _current_code_hashes()["scripts/run_manufacturer_field_resolution.py"]:
            raise BundleError("resolver code does not match external handoff pin")
        if not isinstance(args.expected_code_manifest_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_code_manifest_sha256) or not isinstance(data.get("code_manifest_sha256"), str) or args.expected_code_manifest_sha256.casefold() != data["code_manifest_sha256"].casefold():
            raise BundleError("code manifest does not match external handoff pin")
        registry_marker, registry_data, registry_bytes = read_committed_json_with_marker(args.domain_registry)
        if registry_marker.get("bundle") != "manufacturer-inputs-v1":
            raise BundleError("domain registry bundle identity is not pinned")
        expected_registry_hash = data.get("domain_registry_sha256")
        actual_registry_hash = hashlib.sha256(registry_bytes).hexdigest()
        if actual_registry_hash != TRUSTED_DOMAIN_REGISTRY_SHA256 or expected_registry_hash != actual_registry_hash:
            raise BundleError("domain registry does not match trusted fetch evidence")
        registry = load_domain_registry(registry_data)
        items = _validate_input(data)
        resolved = []
        for item in items:
            identity = item.get("identity") if isinstance(item.get("identity"), dict) else {}
            manufacturer = identity.get("manufacturer") if isinstance(identity.get("manufacturer"), str) else ""
            verified_domains = registry_domains(registry, manufacturer, trusted_only=True)
            resolved.append(resolve_fetch_item(item, verified_domains=verified_domains))
        exception_groups = Counter(exception for item in resolved for exception in item["exceptions"])
        summary = {
            "items": len(resolved),
            "proposal_items": sum(bool(item["proposal_candidates"]) for item in resolved),
            "proposal_fields": sum(len(item["proposal_candidates"]) for item in resolved),
            "no_exact_source": sum(item["status"] == "no_exact_source" for item in resolved),
            "items_with_exceptions": sum(bool(item["exceptions"]) for item in resolved),
            "exception_entries": sum(len(item["exceptions"]) for item in resolved),
            "exception_groups": dict(sorted(exception_groups.items())),
        }
        artifact = {
            "resolution_version": "manufacturer-field-resolution-v2",
            "read_only": True,
            "auto_apply": False,
            "compatibility_relations": 0,
            "production_writes": 0,
            "publication_enabled": False,
            "input_sha256": actual_input_hash,
            "expected_input_sha256": args.expected_input_sha256.casefold(),
            "producer_code_sha256": data["producer_code_sha256"],
            "expected_producer_code_sha256": args.expected_producer_code_sha256.casefold(),
            "expected_code_manifest_sha256": args.expected_code_manifest_sha256.casefold(),
            "code_manifest_sha256": data["code_manifest_sha256"],
            "expected_resolver_code_sha256": args.expected_resolver_code_sha256.casefold(),
            "resolver_code_sha256": _current_code_hashes()["scripts/run_manufacturer_field_resolution.py"],
            "code_sha256": data["code_sha256"],
            "discovery_search_bundle": data.get("discovery_search_bundle"),
            "discovery_search_sha256": data.get("discovery_search_sha256"),
            "domain_registry_sha256": actual_registry_hash,
            "summary": summary,
            "items": resolved,
        }
        publish_bundle(
            args.output,
            {
                "FIELD_RESOLUTION.json": json.dumps(artifact, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
                "REPORT.md": _report(artifact).encode("utf-8"),
            },
            bundle_id="manufacturer-field-resolution-v2",
            approved_root=APPROVED_EVIDENCE_ROOT,
        )
    except (BundleError, OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "PASS", "output": str(args.output), "summary": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
