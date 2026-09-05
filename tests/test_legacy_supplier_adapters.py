from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline.adapters import NetlabAdapter, VetcomAdapter, create_adapter
from mks123_pipeline.electrozone import FeedValidationError
from mks123_pipeline.runner import run_pilot

NETLAB_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<xml_catalog date="2026-03-12 16:39">
  <shop>
    <currencies><currency id="USD" rate="1" /></currencies>
    <categories>
      <category id="1">Сеть</category>
      <category id="10" parentId="1">Кабели</category>
    </categories>
    <offers>
      <offer id="1000463" available="true">
        <uid>11000463</uid>
        <url>http://serv.netlab.ru/descr.asp?id=1000463</url>
        <priceR>300</priceR>
        <priceB>290</priceB>
        <priceC>280</priceC>
        <priceD>275</priceD>
        <priceE>270</priceE>
        <priceF>265</priceF>
        <priceRRP>350.0</priceRRP>
        <currencyId>USD</currencyId>
        <categoryId>10</categoryId>
        <picture>http://img.example/1.jpg</picture>
        <count>4</count>
        <name>Кабель Netlab</name>
        <warranty>12 мес.</warranty>
        <PN>13-3035</PN>
        <volume>0.1</volume>
        <weight>0.25</weight>
        <RussianName>Кабель сетевой</RussianName>
        <DescrUpdated>2026-03-01</DescrUpdated>
        <Model>Basic</Model>
        <Vendor>Rexant</Vendor>
        <LastCountry>CN</LastCountry>
        <WarrantyType>manufacturer</WarrantyType>
        <picture2>http://img.example/2.jpg</picture2>
        <picture3>http://img.example/3.jpg</picture3>
        <OutOfProd>false</OutOfProd>
        <QtyInPack>1</QtyInPack>
        <length>100</length>
        <width>20</width>
        <height>20</height>
        <custom>kept</custom>
        <GTIN>04601004138230</GTIN>
      </offer>
    </offers>
  </shop>
</xml_catalog>
"""


VETCOM_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<yml_catalog date="2023-05-24 11:16">
  <shop>
    <currencies><currency id="RUR" rate="1" /></currencies>
    <categories>
      <category id="500">Техника</category>
      <category id="501" parentId="500">Телевизоры</category>
    </categories>
    <offers>
      <offer id="176107" available="true">
        <price>285</price>
        <currencyId>RUR</currencyId>
        <categoryId>501</categoryId>
        <name>TV Aiwa 40 FLE 9600</name>
        <vendor>AIWA</vendor>
        <description>Черный\nдиагональ 40\nяркость 250 кд/м2</description>
        <barcode>4894659007789</barcode>
        <barcode>4897125301534</barcode>
        <picture>http://opt.vetkom.ru/1.jpg</picture>
        <picture>http://opt.vetkom.ru/2.jpg</picture>
        <quantity>2</quantity>
        <sales_notes></sales_notes>
      </offer>
    </offers>
  </shop>
</yml_catalog>
"""


def _write_netlab_metadata(
    source: Path,
    *,
    fetched_at: str,
    feed_catalog_date: str = "2026-03-12 16:39",
    item_count: int = 1,
    usd_rate: str = "1",
) -> Path:
    data = source.read_bytes()
    metadata = {
        "supplier": "netlab",
        "feed_kind": "price",
        "source": "direct_https",
        "source_url": "https://www.netlab.ru/products/pricexml4.zip",
        "fetched_at_utc": fetched_at,
        "local_file": source.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "content_type": "application/zip",
        "http_status": 200,
        "etag": None,
        "last_modified": None,
        "feed_catalog_date": feed_catalog_date,
        "item_count": item_count,
        "currency_rates": {"USD": usd_rate},
        "credentials_persisted": False,
        "publication_enabled": False,
        "production_writes": 0,
        "max_feed_age_hours": 24,
        "feed_age_seconds": 10860.0,
    }
    path = source.with_suffix(".metadata.json")
    path.write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _write_feed(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_netlab_adapter_maps_real_feed_fields_and_legacy_price_column(tmp_path: Path) -> None:
    source = _write_feed(tmp_path, "netlab.xml", NETLAB_FIXTURE)

    snapshot = NetlabAdapter().parse(
        source,
        fetched_at="2026-03-12T16:40:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    item = snapshot.items[0]
    assert snapshot.catalog_date == "2026-03-12 16:39"
    assert snapshot.currencies == {"USD": Decimal(1)}
    assert item.supplier == "netlab"
    assert item.supplier_item_id == "1000463"
    assert item.supplier_sku == "1000463"
    assert item.catalog_sku == "311000463"
    assert item.name == "Кабель Netlab"
    assert item.manufacturer == "Rexant"
    assert item.model == "Basic"
    assert item.mpn == "13-3035"
    assert item.ean == "04601004138230"
    assert item.source_price == Decimal(270)
    assert item.currency == "USD"
    assert item.quantity == 4
    assert item.available is True
    assert item.category_path == ["Сеть", "Кабели"]
    assert item.source_url == "http://serv.netlab.ru/descr.asp?id=1000463"
    assert item.image_urls == [
        "http://img.example/1.jpg",
        "http://img.example/2.jpg",
        "http://img.example/3.jpg",
    ]
    assert item.weight == Decimal("0.25")
    assert item.dimensions == "100 x 20 x 20"
    assert item.description is None
    assert item.attributes["uid"] == "11000463"
    assert item.attributes["priceR"] == "300"
    assert item.attributes["priceF"] == "265"
    assert item.attributes["custom"] == "kept"
    assert len(item.raw_hash) == 64


def test_netlab_adapter_accepts_documented_symbolic_stock_marker(tmp_path: Path) -> None:
    source = _write_feed(tmp_path, "netlab-symbolic.xml", NETLAB_FIXTURE.replace("<count>4</count>", "<count>***</count>"))

    snapshot = NetlabAdapter().parse(
        source,
        fetched_at="2026-09-04T09:05:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    item = snapshot.items[0]
    assert item.quantity is None
    assert item.available is True
    assert item.attributes["count"] == "***"


def test_netlab_adapter_rejects_unknown_symbolic_stock_marker(tmp_path: Path) -> None:
    source = _write_feed(tmp_path, "netlab-unknown-symbol.xml", NETLAB_FIXTURE.replace("<count>4</count>", "<count>****</count>"))

    with pytest.raises(FeedValidationError, match="invalid quantity"):
        NetlabAdapter().parse(
            source,
            fetched_at="2026-09-04T09:05:00Z",
            min_items=1,
            max_items=10,
            max_bytes=64 * 1024,
        )


def test_netlab_adapter_accepts_official_price_zip_and_seals_archive(tmp_path: Path) -> None:
    source = tmp_path / "pricexml4.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("Price.xml", NETLAB_FIXTURE)

    snapshot = NetlabAdapter().parse(
        source,
        fetched_at="2026-09-04T09:05:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    assert snapshot.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert snapshot.items[0].supplier_item_id == "1000463"


def test_vetcom_adapter_maps_historical_feed_and_keeps_ambiguous_barcodes(tmp_path: Path) -> None:
    source = _write_feed(tmp_path, "vetcom.xml", VETCOM_FIXTURE)

    snapshot = VetcomAdapter().parse(
        source,
        fetched_at="2026-03-12T16:40:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    item = snapshot.items[0]
    assert snapshot.catalog_date == "2023-05-24 11:16"
    assert item.supplier == "vetcom"
    assert item.supplier_item_id == "176107"
    assert item.supplier_sku == "176107"
    assert item.catalog_sku == "41176107"
    assert item.name == "TV Aiwa 40 FLE 9600"
    assert item.manufacturer == "AIWA"
    assert item.model is None
    assert item.mpn is None
    assert item.ean is None
    assert item.source_price == Decimal(285)
    assert item.currency == "RUR"
    assert item.quantity == 2
    assert item.available is True
    assert item.category_path == ["Техника", "Телевизоры"]
    assert item.description == "Черный\nдиагональ 40\nяркость 250 кд/м2"
    assert item.image_urls == [
        "http://opt.vetkom.ru/1.jpg",
        "http://opt.vetkom.ru/2.jpg",
    ]
    assert item.attributes["barcode"] == "4894659007789"
    assert item.attributes["barcode#2"] == "4897125301534"


def test_factory_registers_both_non_first_suppliers() -> None:
    netlab = create_adapter("netlab", expected_catalog_sku_prefix="31")
    vetcom = create_adapter("vetcom", expected_catalog_sku_prefix="41")

    assert isinstance(netlab, NetlabAdapter)
    assert isinstance(vetcom, VetcomAdapter)


def test_netlab_adapter_rejects_wrong_root(tmp_path: Path) -> None:
    source = _write_feed(
        tmp_path,
        "wrong.xml",
        NETLAB_FIXTURE.replace("<xml_catalog", "<yml_catalog", 1).replace(
            "</xml_catalog>", "</yml_catalog>"
        ),
    )

    with pytest.raises(FeedValidationError, match="invalid root element"):
        NetlabAdapter().parse(
            source,
            fetched_at="2026-03-12T16:40:00Z",
            min_items=1,
            max_items=10,
            max_bytes=64 * 1024,
        )


def test_vetcom_negative_quantity_is_preserved_and_not_available(tmp_path: Path) -> None:
    source = _write_feed(tmp_path, "vetcom-negative.xml", VETCOM_FIXTURE.replace("<quantity>2</quantity>", "<quantity>-2</quantity>"))

    snapshot = VetcomAdapter().parse(
        source,
        fetched_at="2026-03-12T16:40:00Z",
        min_items=1,
        max_items=10,
        max_bytes=64 * 1024,
    )

    item = snapshot.items[0]
    assert item.quantity == -2
    assert item.available is False
    assert item.attributes["quantity"] == "-2"
    assert item.attributes["@available"] == "true"


def test_runner_does_not_compare_usd_source_to_rub_catalog(tmp_path: Path) -> None:
    source = tmp_path / "netlab-run.zip"
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("Price.xml", NETLAB_FIXTURE)
    source_metadata = _write_netlab_metadata(
        source,
        fetched_at="2026-03-12T16:40:00Z",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "1,13-3035,311000463,04601004138230,Кабель Netlab,Rexant,100,1,1,10,Кабели\n",
        encoding="utf-8",
    )

    summary = run_pilot(
        source,
        catalog,
        tmp_path / "run",
        fetched_at="2026-03-12T16:40:00Z",
        min_source_items=1,
        max_source_items=10,
        max_source_bytes=64 * 1024,
        adapter=NetlabAdapter(),
        source_metadata_path=source_metadata,
    )

    assert summary["matches"] == {"exact": 1}
    assert summary["exact_source_price_vs_current"] == {
        "equal": 0,
        "source_higher": 0,
        "source_lower": 0,
        "not_comparable": 1,
    }


def test_vetcom_adapter_rejects_empty_feed(tmp_path: Path) -> None:
    source = _write_feed(
        tmp_path,
        "empty.xml",
        '<yml_catalog date="2026-03-12 16:39"><shop><currencies><currency id="RUR" rate="1" /></currencies><offers /></shop></yml_catalog>',
    )

    with pytest.raises(FeedValidationError, match="below minimum"):
        VetcomAdapter().parse(
            source,
            fetched_at="2026-03-12T16:40:00Z",
            min_items=1,
            max_items=10,
            max_bytes=64 * 1024,
        )
