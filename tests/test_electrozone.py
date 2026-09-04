from decimal import Decimal
from pathlib import Path

import pytest

from mks123_pipeline.electrozone import FeedValidationError, parse_yml


def test_parse_yml_normalizes_identity_price_stock_and_attributes(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<yml_catalog date="2026-08-13 17:10"><shop>
<currencies><currency id="RUR" rate="1"/></currencies>
<categories><category id="10">Ноутбуки</category></categories>
<offers><offer id="404042" available="true">
<url>https://electrozon.ru/item/404042</url><price>61498</price><oldprice>65000</oldprice>
<currencyId>RUR</currencyId><categoryId>10</categoryId><picture>https://electrozon.ru/a.jpg</picture>
<store>true</store><pickup>true</pickup><delivery>false</delivery>
<name>Ноутбук TECNO</name><vendor>Tecno</vendor>
<vendorCode>71005000262</vendorCode><barcode>4894947054457</barcode>
<description>Описание</description><sales_notes>Условия</sales_notes>
<manufacturer_warranty>false</manufacturer_warranty><warranty-days>P1Y</warranty-days>
<vat>VAT_22</vat><weight>2.46</weight><dimensions>49/6/31</dimensions>
<param name="Оперативная память (ГБ)">16</param><custom-field>kept</custom-field>
</offer></offers></shop></yml_catalog>""",
        encoding="utf-8",
    )

    snapshot = parse_yml(source, fetched_at="2026-09-01T06:44:44Z")

    assert snapshot.catalog_date == "2026-08-13 17:10"
    assert snapshot.currencies == {"RUR": Decimal(1)}
    assert snapshot.categories["10"].name == "Ноутбуки"
    assert len(snapshot.items) == 1
    item = snapshot.items[0]
    assert item.supplier == "electrozone"
    assert item.supplier_item_id == "404042"
    assert item.catalog_sku == "11404042"
    assert item.mpn == "71005000262"
    assert item.ean == "4894947054457"
    assert item.source_price == Decimal(61498)
    assert item.old_price == Decimal(65000)
    assert item.currency == "RUR"
    assert item.available is True
    assert item.store is True
    assert item.pickup is True
    assert item.delivery is False
    assert item.description == "Описание"
    assert item.sales_notes == "Условия"
    assert item.manufacturer_warranty is False
    assert item.warranty_days == "P1Y"
    assert item.vat == "VAT_22"
    assert item.weight == Decimal("2.46")
    assert item.dimensions == "49/6/31"
    assert item.image_urls == ["https://electrozon.ru/a.jpg"]
    assert item.attributes["Оперативная память (ГБ)"] == "16"
    assert item.attributes["price"] == "61498"
    assert item.attributes["picture"] == "https://electrozon.ru/a.jpg"
    assert item.attributes["custom-field"] == "kept"
    assert len(item.raw_hash) == 64


def test_parse_yml_rejects_wrong_root(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text("<catalog><shop><offers/></shop></catalog>", encoding="utf-8")
    with pytest.raises(FeedValidationError, match="root"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_duplicate_offer_ids(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        """<yml_catalog><shop><currencies><currency id="RUR" rate="1"/></currencies><categories/>
<offers>
<offer id="7" available="true"><name>A</name><price>1</price><currencyId>RUR</currencyId></offer>
<offer id="7" available="true"><name>B</name><price>2</price><currencyId>RUR</currencyId></offer>
</offers></shop></yml_catalog>""",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="duplicate supplier item id"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_feed_below_required_baseline(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        """<yml_catalog><shop><currencies><currency id="RUR" rate="1"/></currencies><categories/>
<offers><offer id="7"><name>A</name><price>1</price><currencyId>RUR</currencyId></offer></offers>
</shop></yml_catalog>""",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="below minimum"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z", min_items=2)


def test_parse_yml_rejects_source_larger_than_byte_limit(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text("<yml_catalog>" + ("x" * 5000) + "</yml_catalog>", encoding="utf-8")
    with pytest.raises(FeedValidationError, match="byte limit"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z", max_bytes=1024)


def test_parse_yml_does_not_use_separate_stat_size_preflight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="7"><name>A</name><price>1</price><currencyId>RUR</currencyId></offer>'
        "</offers></shop></yml_catalog>",
        encoding="utf-8",
    )

    def reject_stat(self: Path, *args, **kwargs):
        if self == source:
            raise AssertionError("separate stat/open sequence is TOCTOU-vulnerable")
        return original_stat(self, *args, **kwargs)

    original_stat = Path.stat
    monkeypatch.setattr(Path, "stat", reject_stat)
    snapshot = parse_yml(source, fetched_at="2026-09-01T00:00:00Z", max_bytes=1024)

    assert snapshot.items[0].name == "A"
    assert len(snapshot.source_sha256) == 64


def test_parse_yml_requires_exactly_one_shop_and_offers_container(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        """<yml_catalog>
<shop><offers><offer id="1"><price>1</price><currencyId>RUR</currencyId></offer></offers></shop>
<shop><offers><offer id="2"><price>2</price><currencyId>RUR</currencyId></offer></offers></shop>
</yml_catalog>""",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="exactly one shop"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_unknown_availability_token(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1" available="maybe"><name>One</name><price>1</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="availability"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_malformed_decimal(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>not-a-number</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="invalid decimal"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_undeclared_offer_currency(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>USD</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="currency"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_missing_currency_container(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="currencies"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_preserves_repeated_parameter_values(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId>'
        '<param name="Memory">8</param><param name="Memory">16</param>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    snapshot = parse_yml(source, fetched_at="2026-09-01T00:00:00Z")
    assert snapshot.items[0].attributes["Memory"] == "8"
    assert snapshot.items[0].attributes["Memory#2"] == "16"


def test_parse_yml_rejects_conflicting_scalar_values(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>1</price><price>2</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="conflicting price"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_rejects_offer_with_unknown_category(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies>"
        "<categories><category id=\"10\">Known</category></categories><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId><categoryId>99</categoryId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    with pytest.raises(FeedValidationError, match="unknown category"):
        parse_yml(source, fetched_at="2026-09-01T00:00:00Z")


def test_parse_yml_marks_conflicting_barcodes_as_identity_warning(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId>'
        '<barcode>111</barcode><barcode>222</barcode>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    snapshot = parse_yml(source, fetched_at="2026-09-01T00:00:00Z")
    assert snapshot.items[0].ean is None
    assert snapshot.items[0].identity_warnings == ["ambiguous_ean"]
