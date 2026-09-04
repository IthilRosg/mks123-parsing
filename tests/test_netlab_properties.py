from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline.electrozone import FeedValidationError
from mks123_pipeline.netlab_properties import scan_netlab_properties

PROPERTIES_FIXTURE = """<?xml version="1.0" encoding="windows-1251"?>
<xml_catalog date="2026-09-04 08:46">
  <name>Компания Нетлаб</name>
  <properties>
    <property id="p1">Производитель <b>товара</b></property>
    <property id="p2">Модель</property>
  </properties>
  <items>
    <item id="100">
      <p1>ACME</p1>
      <p2>-</p2>
    </item>
    <item id="101">
      <p1>Rex</p1>
    </item>
  </items>
</xml_catalog>
"""


def _write_source(tmp_path: Path, text: str) -> Path:
    source = tmp_path / "GoodsProperties.xml"
    source.write_bytes(text.encode("cp1251"))
    return source


def test_scan_netlab_properties_streams_definitions_and_items(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE)
    observations: list[tuple[str, str, str, str, bool]] = []

    stats = scan_netlab_properties(
        source,
        max_bytes=64 * 1024,
        emit=lambda observation: observations.append(
            (
                observation.item_id,
                observation.property_id,
                observation.property_name,
                observation.value,
                observation.missing,
            )
        ),
    )

    assert stats.catalog_date == "2026-09-04 08:46"
    assert stats.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stats.property_count == 2
    assert stats.item_count == 2
    assert stats.observation_count == 3
    assert stats.missing_observation_count == 1
    assert observations == [
        ("100", "p1", "Производитель товара", "ACME", False),
        ("100", "p2", "Модель", "-", True),
        ("101", "p1", "Производитель товара", "Rex", False),
    ]


def test_scan_netlab_properties_rejects_unknown_property(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p1>ACME</p1>", "<p999>ACME</p999>"))

    with pytest.raises(FeedValidationError, match="unknown property p999"):
        scan_netlab_properties(source, max_bytes=64 * 1024)


def test_scan_netlab_properties_can_preserve_unknown_property_as_review_only(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p1>ACME</p1>", "<p999>ACME</p999>"))
    observations = []

    stats = scan_netlab_properties(
        source,
        max_bytes=64 * 1024,
        allow_unknown_property_ids=True,
        emit=observations.append,
    )

    assert stats.unknown_property_id_count == 1
    assert stats.unknown_observation_count == 1
    assert observations[0].property_name is None
    assert observations[0].definition_missing is True


def test_scan_netlab_properties_rejects_duplicate_property_tag(tmp_path: Path) -> None:
    source = _write_source(tmp_path, PROPERTIES_FIXTURE.replace("<p2>-</p2>", "<p2>-</p2><p2>other</p2>"))

    with pytest.raises(FeedValidationError, match="duplicate property p2"):
        scan_netlab_properties(source, max_bytes=64 * 1024)


def test_scan_netlab_properties_accepts_official_archive_and_seals_archive(tmp_path: Path) -> None:
    source = tmp_path / "GoodsProperties.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("GoodsProperties.xml", PROPERTIES_FIXTURE.encode("cp1251"))

    stats = scan_netlab_properties(source, max_bytes=64 * 1024)

    assert stats.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert stats.item_count == 2
