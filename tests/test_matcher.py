from decimal import Decimal

import pytest

from mks123_pipeline.matcher import CatalogItem, match_supplier_items
from mks123_pipeline.models import SupplierItem


def supplier_item(**overrides) -> SupplierItem:
    data = {
        "supplier_item_id": "404042",
        "supplier_sku": "404042",
        "catalog_sku": "11404042",
        "manufacturer": "Tecno",
        "model": "71005000262",
        "mpn": "71005000262",
        "ean": "4894947054457",
        "name": "Ноутбук TECNO",
        "source_price": Decimal(61498),
        "currency": "RUR",
        "available": True,
        "fetched_at": "2026-09-01T06:44:44Z",
        "raw_hash": "a" * 64,
    }
    data.update(overrides)
    return SupplierItem(**data)


def test_exact_sku_with_consistent_identity_is_exact() -> None:
    catalog = [CatalogItem(product_id=77, sku="11404042", model="71005000262", ean="4894947054457", manufacturer="TECNO", name="Ноутбук")]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "exact"
    assert result.matches[0].catalog_product_id == 77
    assert result.matches[0].matched_by == "sku"
    assert result.matches[0].confidence == Decimal("1.00")
    assert result.matches[0].warnings == []


def test_exact_sku_with_conflicting_ean_is_blocked_as_conflict() -> None:
    catalog = [CatalogItem(product_id=77, sku="11404042", model="71005000262", ean="0000000000000", manufacturer="TECNO", name="Ноутбук")]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "conflict"
    assert "ean_mismatch" in result.matches[0].warnings


def test_missing_sku_is_unmatched_and_catalog_gap_is_reported() -> None:
    catalog = [CatalogItem(product_id=77, sku="11999999", model="X", ean="", manufacturer="Brand", name="Old")]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "unmatched"
    assert result.catalog_missing_supplier == [77]


def test_unique_ean_can_propose_high_confidence_match_without_overriding_sku() -> None:
    catalog = [CatalogItem(product_id=88, sku="11999999", model="OTHER", ean="4894947054457", manufacturer="TECNO", name="Ноутбук")]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "high_confidence"
    assert result.matches[0].catalog_product_id == 88
    assert result.matches[0].matched_by == "ean_unique"
    assert result.matches[0].confidence == Decimal("0.95")
    assert result.catalog_missing_supplier == []


def test_duplicate_ean_is_ambiguous_and_never_selects_a_product() -> None:
    catalog = [
        CatalogItem(product_id=88, sku="11999998", model="A", ean="4894947054457", manufacturer="TECNO", name="A"),
        CatalogItem(product_id=89, sku="11999999", model="B", ean="4894947054457", manufacturer="TECNO", name="B"),
    ]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "ambiguous"
    assert result.matches[0].catalog_product_id is None
    assert result.matches[0].warnings == ["ean_not_unique"]
    assert result.catalog_missing_supplier == [88, 89]


def test_unique_manufacturer_and_model_can_propose_high_confidence_match() -> None:
    catalog = [CatalogItem(product_id=90, sku="11999990", model="71005000262", ean="", manufacturer="TECNO", name="Ноутбук")]
    result = match_supplier_items([supplier_item(ean=None)], catalog)
    assert result.matches[0].status == "high_confidence"
    assert result.matches[0].catalog_product_id == 90
    assert result.matches[0].matched_by == "manufacturer_model_unique"
    assert result.matches[0].confidence == Decimal("0.90")


def test_manufacturer_model_candidate_with_conflicting_ean_is_conflict() -> None:
    catalog = [CatalogItem(product_id=90, sku="11999990", model="71005000262", ean="000", manufacturer="TECNO", name="Ноутбук")]
    result = match_supplier_items([supplier_item(ean="4894947054457")], catalog)
    assert result.matches[0].status == "conflict"
    assert result.matches[0].catalog_product_id == 90
    assert "ean_mismatch" in result.matches[0].warnings


def test_duplicate_catalog_sku_is_ambiguous_and_selects_nothing() -> None:
    catalog = [
        CatalogItem(product_id=91, sku="11404042", model="A", ean="", manufacturer="TECNO", name="A"),
        CatalogItem(product_id=92, sku="11404042", model="B", ean="", manufacturer="TECNO", name="B"),
    ]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "ambiguous"
    assert result.matches[0].catalog_product_id is None
    assert result.matches[0].warnings == ["catalog_sku_not_unique"]
    assert result.catalog_missing_supplier == [91, 92]


def test_exact_sku_with_manufacturer_conflict_is_blocked() -> None:
    catalog = [
        CatalogItem(
            product_id=93,
            sku="11404042",
            model="71005000262",
            ean="4894947054457",
            manufacturer="DELL",
            name="Ноутбук",
        )
    ]
    result = match_supplier_items([supplier_item()], catalog)
    assert result.matches[0].status == "conflict"
    assert result.matches[0].warnings == ["manufacturer_mismatch"]


def test_duplicate_catalog_product_id_fails_closed() -> None:
    catalog = [
        CatalogItem(product_id=93, sku="11404042", name="A"),
        CatalogItem(product_id=93, sku="11999999", name="B"),
    ]
    with pytest.raises(ValueError, match="catalog product id is not unique"):
        match_supplier_items([supplier_item()], catalog)


def test_duplicate_source_identity_fails_closed() -> None:
    duplicate = supplier_item(name="Different payload")
    with pytest.raises(ValueError, match="supplier item id is not unique"):
        match_supplier_items([supplier_item(), duplicate], [])


def test_two_supplier_offers_cannot_select_one_catalog_product() -> None:
    catalog = [
        CatalogItem(
            product_id=77,
            sku="11404042",
            model="71005000262",
            ean="4894947054457",
            manufacturer="TECNO",
            name="Ноутбук",
        )
    ]
    exact = supplier_item(ean=None)
    ean_candidate = supplier_item(
        supplier_item_id="999999",
        supplier_sku="999999",
        catalog_sku="11999999",
        ean="4894947054457",
        model="OTHER",
        mpn="OTHER",
    )
    result = match_supplier_items([exact, ean_candidate], catalog)
    assert result.matches[0].status == "exact"
    assert result.matches[1].status == "ambiguous"
    assert result.matches[1].catalog_product_id is None
    assert result.matches[1].matched_by == "catalog_product_reused"
    assert result.matches[1].warnings == ["catalog_product_reused"]
    assert result.catalog_missing_supplier == []


def test_ambiguous_supplier_identity_cannot_be_exact_sku_match() -> None:
    catalog = [
        CatalogItem(product_id=77, sku="11404042", model="71005000262", ean="4894947054457", manufacturer="TECNO", name="Ноутбук")
    ]
    result = match_supplier_items([supplier_item(identity_warnings=["ambiguous_ean"])], catalog)
    assert result.matches[0].status == "ambiguous"
    assert result.matches[0].catalog_product_id is None
    assert result.matches[0].warnings == ["ambiguous_ean"]
