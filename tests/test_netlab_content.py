from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.netlab_acquisition import (
    validate_netlab_properties_acquisition_metadata,
)
from mks123_pipeline.netlab_content import enrich_netlab_snapshot
from mks123_pipeline.netlab_properties import scan_netlab_properties

PRICE_XML = """<?xml version="1.0" encoding="utf-8"?>
<xml_catalog date="2026-09-05 09:00">
  <shop>
    <currencies><currency id="USD" rate="86.89"/></currencies>
    <offers>
      <offer id="10" available="true">
        <uid>90010</uid>
        <name>First product</name><priceE>10</priceE><currencyId>USD</currencyId>
        <picture>https://nlimg.netlab.ru/good.jpg</picture>
        <picture2>https://evil.example/bad.jpg</picture2>
      </offer>
      <offer id="11" available="true">
        <uid>90011</uid>
        <name>Second product</name><priceE>20</priceE><currencyId>USD</currencyId>
      </offer>
    </offers>
  </shop>
</xml_catalog>
"""

PROPERTIES_XML = """<?xml version="1.0" encoding="windows-1251"?>
<xml_catalog date="2026-09-05 09:01">
  <properties>
    <property id="p9999995">Описание</property>
    <property id="p2">Цвет</property>
  </properties>
  <items>
    <item id="90010">
      <p9999995>&lt;p onclick="alert(1)"&gt;Safe &lt;script&gt;bad()&lt;/script&gt; text&lt;/p&gt;</p9999995>
      <p2>Blue</p2>
      <p999>Unknown</p999>
    </item>
  </items>
</xml_catalog>
"""


def _write_zip(path: Path, member: str, data: str, encoding: str = "utf-8") -> None:
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(member, data.encode(encoding))


def test_netlab_enrichment_binds_uid_and_sanitizes_content(tmp_path: Path) -> None:
    price_path = tmp_path / "price.zip"
    properties_path = tmp_path / "properties.zip"
    _write_zip(price_path, "Price.xml", PRICE_XML)
    _write_zip(properties_path, "GoodsProperties.xml", PROPERTIES_XML, encoding="cp1251")
    snapshot = NetlabAdapter().parse(
        price_path,
        fetched_at="2026-09-05T09:02:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    result = enrich_netlab_snapshot(snapshot, properties_path, max_bytes=64 * 1024)

    first, second = result.items
    assert first.description == "<p>Safe text</p>"
    assert first.description_html == '<p onclick="alert(1)">Safe <script>bad()</script> text</p>'
    assert first.image_urls == ["https://nlimg.netlab.ru/good.jpg"]
    assert [item["property_id"] for item in first.properties] == ["p9999995", "p2", "p999"]
    assert first.content_provenance["join"] == {"key": "uid", "item_id": "90010", "matched": True}
    assert first.content_provenance["review_only"] is True
    assert first.content_provenance["description"]["property_id"] == "p9999995"
    assert second.description is None
    assert second.properties == []
    assert result.uid_price_items == 2
    assert result.uid_properties_overlap == 1
    assert result.description_items == 1
    assert result.unknown_property_id_count == 1


def test_netlab_properties_metadata_is_bound_to_stats_and_archive(tmp_path: Path) -> None:
    source = tmp_path / "properties.zip"
    _write_zip(source, "GoodsProperties.xml", PROPERTIES_XML, encoding="cp1251")
    stats = scan_netlab_properties(source, max_bytes=64 * 1024, allow_unknown_property_ids=True)
    payload = {
        "supplier": "netlab",
        "feed_kind": "properties",
        "source": "direct_https",
        "source_url": "https://www.netlab.ru/products/GoodsProperties.zip",
        "fetched_at_utc": "2026-09-05T09:02:00Z",
        "local_file": source.name,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "size_bytes": source.stat().st_size,
        "content_type": "application/zip",
        "http_status": 200,
        "feed_catalog_date": stats.catalog_date,
        "item_count": stats.item_count,
        "property_count": stats.property_count,
        "observation_count": stats.observation_count,
        "missing_observation_count": stats.missing_observation_count,
        "unknown_property_id_count": stats.unknown_property_id_count,
        "unknown_observation_count": stats.unknown_observation_count,
        "credentials_persisted": False,
        "publication_enabled": False,
        "production_writes": 0,
        "max_feed_age_hours": None,
        "feed_age_seconds": None,
    }

    assert validate_netlab_properties_acquisition_metadata(
        payload,
        source_data=source.read_bytes(),
        expected_fetched_at="2026-09-05T09:02:00Z",
        expected_catalog_date=stats.catalog_date,
        expected_stats=stats,
    ) == payload
    payload["item_count"] += 1
    with pytest.raises(ValueError, match="item_count"):
        validate_netlab_properties_acquisition_metadata(
            payload,
            source_data=source.read_bytes(),
            expected_fetched_at="2026-09-05T09:02:00Z",
            expected_catalog_date=stats.catalog_date,
            expected_stats=stats,
        )
