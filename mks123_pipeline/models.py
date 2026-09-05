from __future__ import annotations

from decimal import Decimal
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Category(BaseModel):
    id: str
    name: str
    parent_id: str | None = None


class SupplierItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    supplier: str = "electrozone"
    supplier_item_id: str
    catalog_sku: str
    supplier_sku: str
    manufacturer: str | None = None
    model: str | None = None
    mpn: str | None = None
    ean: str | None = None
    identity_warnings: list[str] = Field(default_factory=list)
    name: str
    category_id: str | None = None
    category_path: list[str] = Field(default_factory=list)
    source_price: Decimal
    old_price: Decimal | None = None
    currency: str
    quantity: int | None = None
    available: bool
    store: bool | None = None
    pickup: bool | None = None
    delivery: bool | None = None
    source_url: str | None = None
    image_urls: list[str] = Field(default_factory=list)
    description: str | None = None
    description_html: str | None = None
    properties: list[dict[str, Any]] = Field(default_factory=list)
    content_provenance: dict[str, Any] = Field(default_factory=dict)
    sales_notes: str | None = None
    manufacturer_warranty: bool | None = None
    warranty_days: str | None = None
    vat: str | None = None
    weight: Decimal | None = None
    dimensions: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)
    fetched_at: str
    raw_hash: str


class SupplierSnapshot(BaseModel):
    catalog_date: str | None = None
    source_sha256: str
    currencies: dict[str, Decimal]
    categories: dict[str, Category]
    items: list[SupplierItem]
