from __future__ import annotations

import re
from decimal import Decimal

from pydantic import BaseModel, Field

from .models import SupplierItem


class CatalogItem(BaseModel):
    product_id: int
    sku: str
    model: str = ""
    ean: str = ""
    manufacturer: str = ""
    name: str
    price: Decimal = Decimal(0)
    quantity: int = 0
    status: int = 0
    category_ids: str = ""
    categories: str = ""


class MatchRecord(BaseModel):
    supplier_item_id: str
    catalog_sku: str
    catalog_product_id: int | None = None
    status: str
    confidence: Decimal
    matched_by: str | None = None
    warnings: list[str] = Field(default_factory=list)


class MatchResult(BaseModel):
    matches: list[MatchRecord]
    catalog_missing_supplier: list[int]


def _identity(value: str | None) -> str:
    return re.sub(r"[^0-9A-ZА-Я]+", "", (value or "").upper())


def match_supplier_items(supplier_items: list[SupplierItem], catalog_items: list[CatalogItem]) -> MatchResult:
    supplier_item_ids = [item.supplier_item_id for item in supplier_items]
    if len(supplier_item_ids) != len(set(supplier_item_ids)):
        raise ValueError("supplier item id is not unique")
    supplier_catalog_skus = [item.catalog_sku for item in supplier_items]
    if len(supplier_catalog_skus) != len(set(supplier_catalog_skus)):
        raise ValueError("supplier generated catalog sku is not unique")
    product_ids = [item.product_id for item in catalog_items]
    if len(product_ids) != len(set(product_ids)):
        raise ValueError("catalog product id is not unique")
    catalog_by_sku: dict[str, list[CatalogItem]] = {}
    catalog_by_ean: dict[str, list[CatalogItem]] = {}
    catalog_by_brand_model: dict[tuple[str, str], list[CatalogItem]] = {}
    supplier_ean_counts: dict[str, int] = {}
    supplier_brand_model_counts: dict[tuple[str, str], int] = {}
    for item in catalog_items:
        catalog_by_sku.setdefault(item.sku, []).append(item)
        if item.ean.strip():
            catalog_by_ean.setdefault(item.ean.strip(), []).append(item)
        brand_model = (_identity(item.manufacturer), _identity(item.model))
        if all(brand_model):
            catalog_by_brand_model.setdefault(brand_model, []).append(item)
    for item in supplier_items:
        if item.ean and item.ean.strip():
            key = item.ean.strip()
            supplier_ean_counts[key] = supplier_ean_counts.get(key, 0) + 1
        brand_model = (_identity(item.manufacturer), _identity(item.mpn or item.model))
        if all(brand_model):
            supplier_brand_model_counts[brand_model] = supplier_brand_model_counts.get(brand_model, 0) + 1
    seen_product_ids: set[int] = set()
    matches: list[MatchRecord] = []
    for supplier in supplier_items:
        if supplier.identity_warnings:
            matches.append(MatchRecord(
                supplier_item_id=supplier.supplier_item_id,
                catalog_sku=supplier.catalog_sku,
                status="ambiguous",
                confidence=Decimal(0),
                matched_by="identity_conflict",
                warnings=list(dict.fromkeys(supplier.identity_warnings)),
            ))
            continue
        sku_candidates = catalog_by_sku.get(supplier.catalog_sku, [])
        catalog = sku_candidates[0] if len(sku_candidates) == 1 else None
        matched_by = "sku"
        ambiguity_reason: str | None = "catalog_sku_not_unique" if len(sku_candidates) > 1 else None
        if catalog is None and ambiguity_reason is None and supplier.ean:
            ean = supplier.ean.strip()
            candidates = catalog_by_ean.get(ean, [])
            if len(candidates) == 1 and supplier_ean_counts.get(ean) == 1:
                catalog = candidates[0]
                matched_by = "ean_unique"
            elif candidates:
                ambiguity_reason = "ean_not_unique"
        if catalog is None and ambiguity_reason is None:
            brand_model = (_identity(supplier.manufacturer), _identity(supplier.mpn or supplier.model))
            candidates = catalog_by_brand_model.get(brand_model, []) if all(brand_model) else []
            if len(candidates) == 1 and supplier_brand_model_counts.get(brand_model) == 1:
                catalog = candidates[0]
                matched_by = "manufacturer_model_unique"
            elif candidates:
                ambiguity_reason = "manufacturer_model_not_unique"
        if catalog is None and ambiguity_reason:
            matches.append(MatchRecord(
                supplier_item_id=supplier.supplier_item_id,
                catalog_sku=supplier.catalog_sku,
                status="ambiguous",
                confidence=Decimal(0),
                matched_by="sku" if ambiguity_reason == "catalog_sku_not_unique" else "identity_candidate",
                warnings=[ambiguity_reason],
            ))
            continue
        if catalog is None:
            matches.append(MatchRecord(
                supplier_item_id=supplier.supplier_item_id,
                catalog_sku=supplier.catalog_sku,
                status="unmatched",
                confidence=Decimal(0),
            ))
            continue
        if catalog.product_id in seen_product_ids:
            matches.append(MatchRecord(
                supplier_item_id=supplier.supplier_item_id,
                catalog_sku=supplier.catalog_sku,
                status="ambiguous",
                confidence=Decimal(0),
                matched_by="catalog_product_reused",
                warnings=["catalog_product_reused"],
            ))
            continue
        seen_product_ids.add(catalog.product_id)
        warnings: list[str] = []
        if supplier.ean and catalog.ean and supplier.ean.strip() != catalog.ean.strip():
            warnings.append("ean_mismatch")
        if supplier.mpn and catalog.model and _identity(supplier.mpn) != _identity(catalog.model):
            warnings.append("model_mismatch")
        if supplier.manufacturer and catalog.manufacturer and _identity(supplier.manufacturer) != _identity(catalog.manufacturer):
            warnings.append("manufacturer_mismatch")
        if matched_by in ("ean_unique", "manufacturer_model_unique"):
            secondary_conflict = matched_by == "manufacturer_model_unique" and "ean_mismatch" in warnings
            confidence = Decimal("0.95") if matched_by == "ean_unique" else Decimal("0.90")
            matches.append(MatchRecord(
                supplier_item_id=supplier.supplier_item_id,
                catalog_sku=supplier.catalog_sku,
                catalog_product_id=catalog.product_id,
                status="conflict" if secondary_conflict else "high_confidence",
                confidence=Decimal("0.50") if secondary_conflict else confidence,
                matched_by=matched_by,
                warnings=warnings,
            ))
            continue
        blocking = any(w in warnings for w in ("ean_mismatch", "model_mismatch", "manufacturer_mismatch"))
        matches.append(MatchRecord(
            supplier_item_id=supplier.supplier_item_id,
            catalog_sku=supplier.catalog_sku,
            catalog_product_id=catalog.product_id,
            status="conflict" if blocking else "exact",
            confidence=Decimal("0.50") if blocking else Decimal("1.00"),
            matched_by=matched_by,
            warnings=warnings,
        ))
    missing = sorted(item.product_id for item in catalog_items if item.product_id not in seen_product_ids)
    return MatchResult(matches=matches, catalog_missing_supplier=missing)
