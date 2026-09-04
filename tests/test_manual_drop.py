from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mks123_pipeline.electrozone import parse_yml
from mks123_pipeline.snapshot_store import install_snapshot, snapshot_target
from scripts import import_manual_drop as manual

SCRIPT = Path(__file__).parents[1] / "scripts" / "import_manual_drop.py"


def _valid_feed() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<yml_catalog date="2026-09-04 12:00">
  <shop>
    <currencies><currency id="RUR" rate="1"/></currencies>
    <categories><category id="1">Test</category></categories>
    <offers>
      <offer id="100" available="true">
        <name>Test product</name>
        <categoryId>1</categoryId>
        <currencyId>RUR</currencyId>
        <price>100</price>
      </offer>
    </offers>
  </shop>
</yml_catalog>
"""


def _run(source: Path, raw_root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--raw-root",
            str(raw_root),
            "--min-offers",
            "1",
            *extra,
        ],
        cwd=SCRIPT.parents[1],
        capture_output=True,
        text=True,
        check=False,
    )


def test_manual_drop_installs_valid_feed_without_modifying_source(tmp_path: Path) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    source_bytes = _valid_feed()
    source.write_bytes(source_bytes)

    result = _run(source, raw_root)

    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["supplier"] == "electrozone"
    assert output["source"] == "manual_drop"
    assert output["offer_count"] == 1
    assert output["credentials_persisted"] is False
    assert output["publication_enabled"] is False
    assert output["production_writes"] == 0
    assert source.read_bytes() == source_bytes
    assert output["sha256"] == hashlib.sha256(source_bytes).hexdigest()
    snapshots = list(raw_root.glob("*.yml"))
    assert len(snapshots) == 1
    assert snapshots[0].read_bytes() == source_bytes
    assert list(raw_root.glob("*.part")) == []


def test_manual_drop_rejects_malformed_xml_and_cleans_part(tmp_path: Path) -> None:
    source = tmp_path / "broken.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(b"<yml_catalog><broken>")

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "MANUAL_DROP_FAILED" in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.metadata.json")) == []
    assert list(raw_root.glob("*.yml")) == []


def test_manual_drop_rejects_missing_catalog_date_without_traceback(tmp_path: Path) -> None:
    source = tmp_path / "missing-date.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(_valid_feed().replace(b' date="2026-09-04 12:00"', b""))

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "MANUAL_DROP_FAILED" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.metadata.json")) == []


def test_manual_drop_rejects_xml_entities_and_cleans_part(tmp_path: Path) -> None:
    source = tmp_path / "entity.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(
        b'<!DOCTYPE yml_catalog [<!ENTITY secret SYSTEM "file:///etc/passwd">]>'
        b'<yml_catalog date="2026-09-04 12:00"><shop><currencies>'
        b'<currency id="RUR" rate="1"/></currencies><offers>'
        b'<offer id="1"><name>&secret;</name><price>1</price><currencyId>RUR</currencyId></offer>'
        b'</offers></shop></yml_catalog>'
    )

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "MANUAL_DROP_FAILED" in result.stderr
    assert "Traceback" not in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.metadata.json")) == []
    assert list(raw_root.glob("*.yml")) == []


def test_manual_drop_rejects_oversized_source_before_snapshot_install(tmp_path: Path) -> None:
    source = tmp_path / "oversized.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(_valid_feed())

    result = _run(source, raw_root, "--max-source-bytes", "8")

    assert result.returncode != 0
    assert "source size exceeds 8 bytes" in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.metadata.json")) == []
    assert list(raw_root.glob("*.yml")) == []


def test_manual_drop_is_idempotent_for_same_content(tmp_path: Path) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(_valid_feed())

    first = _run(source, raw_root)
    second = _run(source, raw_root)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert json.loads(first.stdout)["created"] is True
    assert json.loads(second.stdout)["created"] is False
    assert len(list(raw_root.glob("*.yml"))) == 1
    assert len(list(raw_root.glob("*.metadata.json"))) == 1
    assert list(raw_root.glob("*.part")) == []


def test_manual_drop_rejects_source_inside_raw_root(tmp_path: Path) -> None:
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    source = raw_root / "incoming.yml"
    source.write_bytes(_valid_feed())

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "source must be outside the immutable raw snapshot root" in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.metadata.json")) == []


def test_manual_drop_rejects_part_swap_between_parse_and_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    source.write_bytes(_valid_feed())
    original_parse = manual.parse_yml

    def parse_swapped_part(path: Path, *args, **kwargs):
        part = Path(path)
        original = part.read_bytes()
        altered = original.replace(b"2026-09-04 12:00", b"2026-09-05 13:00").replace(b' id="100"', b' id="200"')
        part.write_bytes(altered)
        try:
            return original_parse(part, *args, **kwargs)
        finally:
            part.write_bytes(original)

    monkeypatch.setattr(manual, "parse_yml", parse_swapped_part)

    with pytest.raises(SystemExit, match="source changed during validation"):
        manual.main(["--source", str(source), "--raw-root", str(raw_root), "--min-offers", "1"])
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.yml")) == []


def test_bounded_copy_rejects_descriptor_that_does_not_match_source_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "incoming.yml"
    alternate = tmp_path / "alternate.yml"
    part = tmp_path / "copy.part"
    source.write_bytes(_valid_feed())
    alternate.write_bytes(_valid_feed().replace(b' id="100"', b' id="200"'))
    original_os_open = os.open

    def redirect_source_open(path, flags, mode=0o777, *, dir_fd=None):
        if Path(path) == source:
            return original_os_open(alternate, flags, mode, dir_fd=dir_fd)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(manual.os, "open", redirect_source_open)

    with pytest.raises(RuntimeError, match="opened source does not match requested path"):
        manual._copy_bounded(source, part, manual.DEFAULT_MAX_SOURCE_BYTES)


def test_manual_drop_rejects_symbolic_link_source(tmp_path: Path) -> None:
    target = tmp_path / "target.yml"
    source = tmp_path / "incoming-link.yml"
    raw_root = tmp_path / "raw"
    target.write_bytes(_valid_feed())
    try:
        source.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are not available: {exc}")

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "symbolic links and reparse points are not accepted" in result.stderr
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.yml")) == []


def test_manual_drop_rejects_conflicting_preexisting_metadata(tmp_path: Path) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    source_bytes = _valid_feed()
    source.write_bytes(source_bytes)
    part = raw_root / ".seed.part"
    part.write_bytes(source_bytes)
    digest = hashlib.sha256(source_bytes).hexdigest()
    snapshot = parse_yml(part, "2026-09-04T12:00:00Z")
    install_snapshot(
        part,
        raw_root,
        feed_date=snapshot.catalog_date,
        content_hash=digest,
        metadata={
            "supplier": "electrozone",
            "source": "direct_https_basic_auth",
            "publication_enabled": True,
            "production_writes": 3,
        },
    )
    part.unlink()

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "snapshot metadata conflict" in result.stderr
    assert list(raw_root.glob("*.part")) == []


def test_manual_drop_rejects_conflicting_content_derived_metadata(tmp_path: Path) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    source_bytes = _valid_feed()
    source.write_bytes(source_bytes)
    part = raw_root / ".seed.part"
    part.write_bytes(source_bytes)
    digest = hashlib.sha256(source_bytes).hexdigest()
    snapshot = parse_yml(part, "2026-09-04T12:00:00Z")
    install_snapshot(
        part,
        raw_root,
        feed_date=snapshot.catalog_date,
        content_hash=digest,
        metadata={
            "supplier": "electrozone",
            "source": "manual_drop",
            "source_filename": source.name,
            "received_at_utc": "2099-01-01T00:00:00Z",
            "catalog_date": "2099-01-01 00:00",
            "offer_count": 999,
            "currency_ids": ["USD"],
            "size_bytes": 0,
            "credentials_persisted": False,
            "publication_enabled": False,
            "production_writes": 0,
        },
    )
    part.unlink()

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert "snapshot metadata conflict" in result.stderr
    assert list(raw_root.glob("*.part")) == []


def test_manual_drop_rolls_back_new_target_when_orphan_metadata_conflicts(tmp_path: Path) -> None:
    source = tmp_path / "incoming.yml"
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    source_bytes = _valid_feed()
    source.write_bytes(source_bytes)
    digest = hashlib.sha256(source_bytes).hexdigest()
    raw_target = snapshot_target(raw_root, "2026-09-04 12:00", digest)
    metadata_target = raw_target.with_suffix(".metadata.json")
    metadata_target.write_text(
        json.dumps(
            {
                "supplier": "electrozone",
                "source": "direct_https_basic_auth",
                "publication_enabled": True,
                "production_writes": 5,
                "local_file": raw_target.name,
                "sha256": digest,
            }
        ),
        encoding="utf-8",
    )

    result = _run(source, raw_root)

    assert result.returncode != 0
    assert list(raw_root.glob("*.part")) == []
    assert list(raw_root.glob("*.yml")) == []
    assert "snapshot metadata conflict" in result.stderr
