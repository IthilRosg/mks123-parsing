from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .electrozone import parse_yml
from .legacy_xml import LegacyXmlMapping, parse_legacy_xml
from .models import SupplierSnapshot


class SupplierAdapter(Protocol):
    """Supplier-specific acquisition/parser boundary for the common pipeline."""

    supplier_id: str
    catalog_sku_prefix: str

    def parse(
        self,
        source_path: Path,
        *,
        fetched_at: str,
        min_items: int,
        max_items: int,
        max_bytes: int,
    ) -> SupplierSnapshot:
        """Read one bounded source snapshot into the common supplier contract."""
        ...


class ElectrozoneAdapter:
    """YML adapter for the first supplier; generic stages remain outside it."""

    supplier_id = "electrozone"
    catalog_sku_prefix = "11"

    def parse(
        self,
        source_path: Path,
        *,
        fetched_at: str,
        min_items: int,
        max_items: int,
        max_bytes: int,
    ) -> SupplierSnapshot:
        return parse_yml(
            source_path,
            fetched_at=fetched_at,
            min_items=min_items,
            max_items=max_items,
            max_bytes=max_bytes,
        )


class NetlabAdapter:
    """Explicit adapter for the observed Netlab ``xml_catalog`` feed."""

    supplier_id = "netlab"
    catalog_sku_prefix = "31"
    mapping = LegacyXmlMapping(
        supplier_id=supplier_id,
        catalog_sku_prefix=catalog_sku_prefix,
        root_tag="xml_catalog",
        # Persisted form 3 selected legacy column 8; in the observed feed
        # sequence this is the E price level. Keep every price level in attrs.
        price_fields=("priceE",),
        name_fields=("name",),
        category_fields=("categoryId",),
        currency_fields=("currencyId",),
        quantity_fields=("count",),
        manufacturer_fields=("Vendor",),
        model_fields=("Model",),
        mpn_fields=("PN",),
        ean_fields=("GTIN",),
        description_fields=(),
        image_fields=("picture", "picture2", "picture3"),
        source_url_fields=("url",),
        warranty_fields=("warranty",),
        weight_fields=("weight",),
        dimension_fields=("length", "width", "height"),
        out_of_product_fields=("OutOfProd",),
        quantity_symbol_values=("*", "**", "***"),
    )

    def parse(
        self,
        source_path: Path,
        *,
        fetched_at: str,
        min_items: int,
        max_items: int,
        max_bytes: int,
    ) -> SupplierSnapshot:
        return parse_legacy_xml(
            source_path,
            fetched_at=fetched_at,
            mapping=self.mapping,
            min_items=min_items,
            max_items=max_items,
            max_bytes=max_bytes,
        )


class VetcomAdapter:
    """Explicit adapter for the historical Vetcom (ВТК) YML feed."""

    supplier_id = "vetcom"
    catalog_sku_prefix = "41"
    mapping = LegacyXmlMapping(
        supplier_id=supplier_id,
        catalog_sku_prefix=catalog_sku_prefix,
        root_tag="yml_catalog",
        price_fields=("price",),
        name_fields=("name",),
        category_fields=("categoryId",),
        currency_fields=("currencyId",),
        quantity_fields=("quantity",),
        manufacturer_fields=("vendor",),
        model_fields=(),
        mpn_fields=(),
        ean_fields=("barcode",),
        description_fields=("description",),
        image_fields=("picture",),
        source_url_fields=(),
        sales_notes_fields=("sales_notes",),
    )

    def parse(
        self,
        source_path: Path,
        *,
        fetched_at: str,
        min_items: int,
        max_items: int,
        max_bytes: int,
    ) -> SupplierSnapshot:
        return parse_legacy_xml(
            source_path,
            fetched_at=fetched_at,
            mapping=self.mapping,
            min_items=min_items,
            max_items=max_items,
            max_bytes=max_bytes,
        )


_ADAPTER_FACTORIES: dict[str, Callable[[], SupplierAdapter]] = {
    "electrozone": ElectrozoneAdapter,
    "netlab": NetlabAdapter,
    "vetcom": VetcomAdapter,
}


def create_adapter(supplier_id: str, *, expected_catalog_sku_prefix: str) -> SupplierAdapter:
    try:
        adapter = _ADAPTER_FACTORIES[supplier_id]()
    except KeyError as exc:
        raise ValueError(f"no adapter registered for supplier: {supplier_id}") from exc
    if adapter.supplier_id != supplier_id:
        raise ValueError(f"adapter supplier ID mismatch: {adapter.supplier_id} != {supplier_id}")
    if adapter.catalog_sku_prefix != expected_catalog_sku_prefix:
        raise ValueError(
            "adapter SKU prefix does not match config: "
            f"{adapter.catalog_sku_prefix} != {expected_catalog_sku_prefix}"
        )
    return adapter
