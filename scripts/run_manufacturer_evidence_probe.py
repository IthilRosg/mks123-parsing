from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    ManufacturerIdentity,
    classify_candidates,
    load_domain_registry,
    registry_domains,
)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{field} must be a non-empty string")
    return value.strip()


def _validate_search_packet(packet: object, seen_skus: set[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(packet, dict) or not isinstance(packet.get("identity"), dict) or not isinstance(packet.get("results"), list):
        raise TypeError("each search packet must contain identity object and results list")
    ident = packet["identity"]
    normalized = dict(ident)
    for field in ("catalog_sku", "name", "manufacturer", "model"):
        normalized[field] = _required_text(ident.get(field), f"identity.{field}")
    for field in ("mpn", "ean"):
        if field in ident and ident[field] is not None:
            normalized[field] = _required_text(ident[field], f"identity.{field}")
    if normalized["catalog_sku"] in seen_skus:
        raise ValueError(f"duplicate catalog_sku: {normalized['catalog_sku']}")
    seen_skus.add(normalized["catalog_sku"])
    results: list[dict[str, Any]] = []
    for raw in packet["results"]:
        if not isinstance(raw, dict):
            raise TypeError("search results must be objects")
        result = dict(raw)
        for field in ("title", "url", "description"):
            if field in result and result[field] is not None and not isinstance(result[field], str):
                raise TypeError(f"search result {field} must be a string")
        results.append(result)
    return normalized, results


def build_report(artifact: dict[str, Any]) -> str:
    lines = [
        "# Manufacturer evidence probe",
        "",
        f"- Items: **{artifact['summary']['items']}**",
        f"- Official identity candidates (not fetched proof): **{artifact['summary']['official_identity_candidate']}**",
        f"- Official family only: **{artifact['summary']['official_family_only']}**",
        f"- Secondary only: **{artifact['summary']['secondary_only']}**",
        f"- Unconfirmed: **{artifact['summary']['unconfirmed']}**",
        "- Auto publication: **false**",
        "- Production writes: **0**",
        "",
        "Only `verified` entries from the independent domain registry can produce official statuses. Candidate domains may be fetched for bounded evidence, but they cannot establish manufacturer ownership. Even `official_exact` remains review-only.",
        "",
        "## Per-item status",
        "",
    ]
    for item in artifact["items"]:
        lines.append(f"- `{item['catalog_sku']}` — {item['name']}: **{item['status']}**; candidates={len(item['candidates'])}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify bounded manufacturer search evidence without publication.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--domain-registry", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--expected-registry-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if not path_is_within(args.input.parent, APPROVED_EVIDENCE_ROOT) or not path_is_within(args.domain_registry.parent, APPROVED_EVIDENCE_ROOT):
            raise BundleError("input bundle is outside approved evidence root")
        if paths_overlap(args.output, args.input.parent) or paths_overlap(args.output, args.domain_registry.parent):
            raise BundleError("output overlaps an input bundle")
        input_marker, data, input_bytes = read_committed_json_with_marker(args.input)
        registry_marker, registry_data, registry_bytes = read_committed_json_with_marker(args.domain_registry)
        if input_marker.get("bundle") != "manufacturer-inputs-v1" or registry_marker.get("bundle") != "manufacturer-inputs-v1":
            raise BundleError("input/search/registry bundle identity is not pinned")
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value) for value in (args.expected_input_sha256, args.expected_registry_sha256)):
            raise ValueError("an expected input SHA-256 is malformed")
        actual_input_hash = hashlib.sha256(input_bytes).hexdigest()
        actual_registry_hash = hashlib.sha256(registry_bytes).hexdigest()
        if actual_input_hash.casefold() != args.expected_input_sha256.casefold() or actual_registry_hash.casefold() != args.expected_registry_sha256.casefold():
            raise BundleError("search input does not match externally pinned SHA-256")
        if hashlib.sha256(registry_bytes).hexdigest() != TRUSTED_DOMAIN_REGISTRY_SHA256:
            raise BundleError("domain registry is outside trusted digest pin")
        if data.get("read_only") is not True or data.get("production_writes") != 0 or data.get("publication_enabled") is not False:
            raise ValueError("input evidence packet violates read-only contract")
        if not isinstance(data.get("items"), list):
            raise TypeError("input evidence packet items must be a list")
        registry = load_domain_registry(registry_data)
        output_items: list[dict[str, Any]] = []
        counts = {"official_identity_candidate": 0, "official_family_only": 0, "secondary_only": 0, "unconfirmed": 0}
        seen_skus: set[str] = set()
        for packet in data["items"]:
            ident, raw_results = _validate_search_packet(packet, seen_skus)
            identity = ManufacturerIdentity(ident["manufacturer"], ident["model"], ident.get("mpn"), ident.get("ean"))
            trusted_domains = registry_domains(registry, identity.manufacturer, trusted_only=True)
            result = classify_candidates(identity, raw_results, official_domains=trusted_domains)
            candidates = [candidate.__dict__ for candidate in result.candidates]
            status = result.status.value
            counts[status] += 1
            output_items.append({"catalog_sku": ident["catalog_sku"], "name": ident["name"], "manufacturer": ident["manufacturer"], "model": ident["model"], "mpn": ident.get("mpn"), "status": status, "auto_publish": result.auto_publish, "trusted_official_domains": sorted(trusted_domains), "candidates": candidates})
        artifact = {"probe_version": "manufacturer-evidence-classification-v2", "read_only": True, "production_writes": 0, "publication_enabled": False, "input_sha256": actual_input_hash, "expected_input_sha256": args.expected_input_sha256.casefold(), "domain_registry_sha256": actual_registry_hash, "expected_registry_sha256": args.expected_registry_sha256.casefold(), "summary": {"items": len(output_items), **counts}, "items": output_items}
        publish_bundle(
            args.output,
            {
                "EVIDENCE_RESULTS.json": json.dumps(artifact, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
                "REPORT.md": build_report(artifact).encode("utf-8"),
            },
            bundle_id="manufacturer-evidence-classification-v2",
            approved_root=APPROVED_EVIDENCE_ROOT,
        )
    except (BundleError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"status": "PASS", "output": str(args.output), "summary": artifact["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
