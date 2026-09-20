from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mks123_pipeline.evidence_bundle import publish_bundle
from scripts.run_manufacturer_field_resolution import (
    _code_manifest_digest,
    _current_code_hashes,
    main,
)


def _input(path, registry_path, *, read_only: bool = True) -> None:
    registry_raw = (Path(r"D:/ServerBackups/mks123webserver/manufacturer-evidence-probe-10-20260909/manufacturer-domain-registry.json")).read_bytes()
    registry_path.parent.parent.mkdir(parents=True, exist_ok=True)
    publish_bundle(registry_path.parent, {registry_path.name: registry_raw}, bundle_id="manufacturer-inputs-v1", approved_root=registry_path.parent.parent)
    preview_hash = hashlib.sha256(b"preview").hexdigest()
    selection_hash = hashlib.sha256(b"selection").hexdigest()
    code_hashes = _current_code_hashes()
    data = {
        "read_only": read_only,
        "production_writes": 0,
        "publication_enabled": False,
        "probe_version": "manufacturer-source-fetch-v4",
        "producer_code_sha256": code_hashes["scripts/run_manufacturer_source_fetch.py"],
        "code_sha256": code_hashes,
        "code_manifest_sha256": _code_manifest_digest(code_hashes),
        "preview_sha256": preview_hash,
        "selection_sha256": selection_hash,
        "domain_registry_sha256": hashlib.sha256(registry_raw).hexdigest(),
        "expected_preview_sha256": preview_hash,
        "expected_selection_sha256": selection_hash,
        "expected_registry_sha256": hashlib.sha256(registry_raw).hexdigest(),
        "summary": {
            "items": 1,
            "urls_attempted": 1,
            "urls_discovered": 1,
            "urls_rejected": 0,
            "blocked_urls": 0,
            "http_requests_started": 1,
            "responses_received": 0,
            "http_200": 0,
            "declared_source_exact": 0,
            "redirects_followed_same_host": 0,
        },
        "discovery_search_urls": [],
        "items": [
            {
                "catalog_sku": "1",
                "name": "TP-Link TL-SF1005D",
                "identity": {"manufacturer": "TP-Link", "model": "TL-SF1005D", "mpn": "TL-SF1005D"},
                "metrics": {"urls_discovered": 1, "urls_rejected": 0, "blocked_urls": 0, "http_requests_started": 1, "responses_received": 0},
                "fetched": [{
                    "url": "https://www.tp-link.com/products/details/?model=TL-SF1005D",
                    "status": "transport_error",
                    "http_status": None,
                    "content_type": "",
                    "bytes_read": 0,
                    "too_large": False,
                    "redirect_location": None,
                    "error": "test transport failure",
                    "retrieved_at": "2026-09-09T19:00:00+00:00",
                    "body_b64": "",
                    "body_persisted": True,
                    "sensitive_content": False,
                    "request_started": True,
                    "body_sha256": hashlib.sha256(b"").hexdigest(),
                    "match_status": "declared_source_model_mention",
                }],
            }
        ],
    }
    raw = json.dumps(data).encode("utf-8")
    path.parent.parent.mkdir(parents=True, exist_ok=True)
    publish_bundle(path.parent, {path.name: raw}, bundle_id="manufacturer-source-fetch-v4", approved_root=path.parent.parent)


def test_field_resolution_cli_is_proposal_only_and_committed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("scripts.run_manufacturer_field_resolution.APPROVED_EVIDENCE_ROOT", tmp_path)
    source = tmp_path / "fetch" / "FETCH_RESULTS.json"
    registry = tmp_path / "registry" / "manufacturer-domain-registry.json"
    output = tmp_path / "resolution"
    _input(source, registry)
    args = ["--input", str(source), "--domain-registry", str(registry), "--output", str(output), "--expected-input-sha256", hashlib.sha256(source.read_bytes()).hexdigest(), "--expected-producer-code-sha256", _current_code_hashes()["scripts/run_manufacturer_source_fetch.py"], "--expected-code-manifest-sha256", _code_manifest_digest(_current_code_hashes()), "--expected-resolver-code-sha256", _current_code_hashes()["scripts/run_manufacturer_field_resolution.py"]]
    assert main(args) == 0
    artifact = json.loads((output / "FIELD_RESOLUTION.json").read_text(encoding="utf-8"))
    assert artifact["summary"]["no_exact_source"] == 1
    assert artifact["auto_apply"] is False
    assert artifact["compatibility_relations"] == 0
    assert json.loads((output / "COMMITTED").read_text(encoding="utf-8"))["files"]
    with pytest.raises(SystemExit):
        main(args)


def test_field_resolution_rejects_external_digest_mismatch(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("scripts.run_manufacturer_field_resolution.APPROVED_EVIDENCE_ROOT", tmp_path)
    source = tmp_path / "fetch" / "FETCH_RESULTS.json"
    registry = tmp_path / "registry" / "manufacturer-domain-registry.json"
    output = tmp_path / "resolution"
    _input(source, registry)
    with pytest.raises(SystemExit):
        main(["--input", str(source), "--domain-registry", str(registry), "--output", str(output), "--expected-input-sha256", "0" * 64, "--expected-producer-code-sha256", _current_code_hashes()["scripts/run_manufacturer_source_fetch.py"], "--expected-code-manifest-sha256", _code_manifest_digest(_current_code_hashes()), "--expected-resolver-code-sha256", _current_code_hashes()["scripts/run_manufacturer_field_resolution.py"]])
    assert not output.exists()


def test_field_resolution_cli_rejects_non_read_only_input(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("scripts.run_manufacturer_field_resolution.APPROVED_EVIDENCE_ROOT", tmp_path)
    source = tmp_path / "fetch" / "FETCH_RESULTS.json"
    registry = tmp_path / "registry" / "manufacturer-domain-registry.json"
    _input(source, registry, read_only=False)
    with pytest.raises(SystemExit):
        main(["--input", str(source), "--domain-registry", str(registry), "--output", str(tmp_path / "resolution"), "--expected-input-sha256", hashlib.sha256(source.read_bytes()).hexdigest(), "--expected-producer-code-sha256", _current_code_hashes()["scripts/run_manufacturer_source_fetch.py"], "--expected-code-manifest-sha256", _code_manifest_digest(_current_code_hashes()), "--expected-resolver-code-sha256", _current_code_hashes()["scripts/run_manufacturer_field_resolution.py"]])
