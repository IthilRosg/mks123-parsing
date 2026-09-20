from __future__ import annotations

import json

import pytest

from mks123_pipeline.evidence_bundle import (
    BundleError,
    publish_bundle,
    read_committed_bundle,
    read_committed_json,
)


def test_publish_bundle_commits_payload_manifest(tmp_path) -> None:
    output = tmp_path / "bundle"
    marker = publish_bundle(output, {"data.json": b'{"ok":true}\n'}, bundle_id="test-v1", approved_root=tmp_path)
    assert output.is_dir()
    assert json.loads((output / "COMMITTED").read_text(encoding="utf-8")) == marker
    assert marker["bundle"] == "test-v1"
    assert marker["files"]["data.json"]["size"] == len(b'{"ok":true}\n')
    assert not list(tmp_path.glob(".bundle.*"))


def test_publish_bundle_refuses_existing_directory_and_symlink(tmp_path) -> None:
    output = tmp_path / "bundle"
    output.mkdir()
    with pytest.raises(BundleError):
        publish_bundle(output, {"data.json": b"x"}, bundle_id="test-v1", approved_root=tmp_path)

    link = tmp_path / "link"
    try:
        link.symlink_to(output, target_is_directory=True)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("symlink creation requires Windows privilege")
        raise
    with pytest.raises(BundleError):
        publish_bundle(link, {"data.json": b"x"}, bundle_id="test-v1", approved_root=tmp_path)


def test_publish_bundle_rejects_nested_payload_name(tmp_path) -> None:
    with pytest.raises(BundleError):
        publish_bundle(tmp_path / "bundle", {"../escape": b"x"}, bundle_id="test-v1", approved_root=tmp_path)


@pytest.mark.parametrize("name", ["file:stream", "CON.txt", "CON.foo.txt", "COM¹.data.json", "file.", "file ", "nested\\file.txt"])
def test_publish_bundle_rejects_windows_unsafe_payload_name(tmp_path, name: str) -> None:
    with pytest.raises(BundleError):
        publish_bundle(tmp_path / "bundle", {name: b"x"}, bundle_id="test-v1", approved_root=tmp_path)


def test_read_committed_bundle_rejects_tampering(tmp_path) -> None:
    output = tmp_path / "bundle"
    publish_bundle(output, {"data.json": b"x"}, bundle_id="test-v1", approved_root=tmp_path)
    output.joinpath("data.json").chmod(0o644)
    output.joinpath("data.json").write_bytes(b"tampered")
    with pytest.raises(BundleError):
        read_committed_bundle(output)


def test_read_committed_json_requires_bundle_marker(tmp_path) -> None:
    output = tmp_path / "bundle"
    publish_bundle(output, {"data.json": b'{"ok":true}\n'}, bundle_id="test-v1", approved_root=tmp_path)
    data, raw = read_committed_json(output / "data.json")
    assert data == {"ok": True}
    assert raw == b'{"ok":true}\n'
    with pytest.raises(BundleError):
        read_committed_json(tmp_path / "standalone.json")


def test_read_committed_json_rejects_duplicate_keys_and_nan(tmp_path) -> None:
    for index, raw in enumerate((b'{"x":1,"x":2}', b'{"x":NaN}')):
        output = tmp_path / f"bundle{index}"
        publish_bundle(output, {"data.json": raw}, bundle_id="test-v1", approved_root=tmp_path)
        with pytest.raises(BundleError):
            read_committed_json(output / "data.json")
