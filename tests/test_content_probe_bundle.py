from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mks123_pipeline.content_probe_bundle import (
    BundleError,
    create_content_bundle,
    verify_content_bundle,
)

IDENTITY = {
    "bundle_id": "content-probe-hardening-test-v1",
    "code_identity": "code-test-identity",
    "source_identity": "source-test-identity",
    "source_seal_sha256": "source-seal-test",
    "probe_data_sha256": "probe-data-test",
    "probe_code_sha256": "probe-code-test",
    "verifier_code_sha256": "verifier-code-test",
    "bundle_helper_sha256": "bundle-helper-test",
    "integrity_sha256": "integrity-test",
}


def test_create_and_verify_bundle_with_external_trust_manifest(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    trust = tmp_path / "trust" / "manifest.json"
    trust.parent.mkdir()
    files = {"probe-data.json": b'{"status":"PASS"}\n', "REPORT.md": b"bounded\n"}

    created = create_content_bundle(bundle, trust, files=files, identity=IDENTITY, test_only_allow_unenforced=True)
    verified = verify_content_bundle(bundle, trust, expected_identity=IDENTITY,
                                     expected_trust_sha256=created["trust_manifest_sha256"],
                                     test_only_allow_unenforced=True)

    assert created["status"] == "PASS"
    assert verified["status"] == "PASS"
    assert (bundle / "seal.json").is_file()
    assert trust.is_file()
    assert verified["files"] == sorted(["REPORT.md", "probe-data.json"])


def test_create_refuses_existing_bundle_or_trust(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    trust = tmp_path / "trust.json"
    bundle.mkdir()
    with pytest.raises(BundleError, match="bundle already exists"):
        create_content_bundle(bundle, trust, files={"a": b"a"}, identity=IDENTITY,
                              test_only_allow_unenforced=True)

    fresh = tmp_path / "fresh"
    trust.write_text("existing", encoding="utf-8")
    with pytest.raises(BundleError, match="trust manifest already exists"):
        create_content_bundle(fresh, trust, files={"a": b"a"}, identity=IDENTITY,
                              test_only_allow_unenforced=True)


def test_verify_rejects_bundle_mutation(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    trust = tmp_path / "trust.json"
    created = create_content_bundle(bundle, trust, files={"probe-data.json": b"original"}, identity=IDENTITY,
                                    test_only_allow_unenforced=True)
    target = bundle / "probe-data.json"
    target.chmod(0o600)
    target.write_bytes(b"mutated")

    with pytest.raises((BundleError, ValueError), match="hash|changed|identity|seal"):
        verify_content_bundle(bundle, trust, expected_identity=IDENTITY,
                              expected_trust_sha256=created["trust_manifest_sha256"],
                              test_only_allow_unenforced=True)


def test_verify_rejects_identity_or_external_trust_mismatch(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    trust = tmp_path / "trust.json"
    created = create_content_bundle(bundle, trust, files={"a": b"a"}, identity=IDENTITY,
                                    test_only_allow_unenforced=True)

    with pytest.raises(BundleError, match="identity"):
        verify_content_bundle(bundle, trust, expected_identity={**IDENTITY, "code_identity": "wrong"},
                              expected_trust_sha256=created["trust_manifest_sha256"],
                              test_only_allow_unenforced=True)

    trust_data = json.loads(trust.read_text(encoding="utf-8"))
    trust_data["files"]["a"]["sha256"] = hashlib.sha256(b"forged").hexdigest()
    trust.write_text(json.dumps(trust_data), encoding="utf-8")
    with pytest.raises(BundleError, match="trust|hash"):
        verify_content_bundle(bundle, trust, expected_identity=IDENTITY,
                              expected_trust_sha256=created["trust_manifest_sha256"],
                              test_only_allow_unenforced=True)
