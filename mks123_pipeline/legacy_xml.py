from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from .electrozone import FeedValidationError
from .models import Category, SupplierItem, SupplierSnapshot


@dataclass(frozen=True)
class LegacyXmlMapping:
    """Explicit field contract for one legacy XML/YML supplier feed."""

    supplier_id: str
    catalog_sku_prefix: str
    root_tag: str
    price_fields: tuple[str, ...]
    name_fields: tuple[str, ...]
    category_fields: tuple[str, ...]
    currency_fields: tuple[str, ...]
    quantity_fields: tuple[str, ...]
    manufacturer_fields: tuple[str, ...]
    model_fields: tuple[str, ...]
    mpn_fields: tuple[str, ...]
    ean_fields: tuple[str, ...]
    description_fields: tuple[str, ...]
    image_fields: tuple[str, ...]
    source_url_fields: tuple[str, ...]
    sales_notes_fields: tuple[str, ...] = ()
    warranty_fields: tuple[str, ...] = ()
    weight_fields: tuple[str, ...] = ()
    dimension_fields: tuple[str, ...] = ()
    vat_fields: tuple[str, ...] = ()
    out_of_product_fields: tuple[str, ...] = ()
    availability_attr: str = "available"
    quantity_symbol_values: tuple[str, ...] = ()


def _node_text(node: ET.Element) -> str:
    return "".join(node.itertext()).strip()


def _values(offer: ET.Element, fields: tuple[str, ...]) -> list[str]:
    if not fields:
        return []
    allowed = set(fields)
    return [_node_text(node) for node in list(offer) if node.tag in allowed and _node_text(node)]


def _scalar(
    offer: ET.Element,
    fields: tuple[str, ...],
    *,
    label: str,
    item_id: str,
    required: bool = False,
    allow_multiple: bool = False,
) -> str | None:
    values = _values(offer, fields)
    if not values:
        if required:
            raise FeedValidationError(f"{label} is required for offer {item_id}")
        return None
    distinct = list(dict.fromkeys(values))
    if len(distinct) > 1:
        if allow_multiple:
            return None
        raise FeedValidationError(f"conflicting {label} values for offer {item_id}")
    return distinct[0]


def _decimal(value: str, *, label: str, item_id: str, positive: bool = False) -> Decimal:
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise FeedValidationError(f"invalid {label} for offer {item_id}: {value!r}") from exc
    if not result.is_finite() or (positive and result <= 0):
        qualifier = "positive " if positive else "finite "
        raise FeedValidationError(f"{label} must be {qualifier}for offer {item_id}: {value!r}")
    return result


def _quantity(value: str, *, item_id: str, symbolic_values: tuple[str, ...] = ()) -> int | None:
    if value in symbolic_values:
        return None
    if not re.fullmatch(r"-?[0-9]+", value):
        raise FeedValidationError(f"invalid quantity for offer {item_id}: {value!r}")
    return int(value)


def _boolean(value: str, *, label: str, item_id: str) -> bool:
    lowered = value.casefold()
    if lowered in {"true", "yes", "1", "+"}:
        return True
    if lowered in {"false", "no", "0", "-"}:
        return False
    raise FeedValidationError(f"invalid {label} for offer {item_id}: {value!r}")


def _category_path(category_id: str | None, categories: dict[str, Category], *, item_id: str) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    current = category_id
    while current:
        if current in seen:
            raise FeedValidationError(f"category cycle for offer {item_id}: {current}")
        category = categories.get(current)
        if category is None:
            raise FeedValidationError(f"unknown category {current} for offer {item_id}")
        seen.add(current)
        result.append(category.name)
        current = category.parent_id
    return list(reversed(result))


def _parse_categories(shop: ET.Element) -> dict[str, Category]:
    containers = shop.findall("categories")
    if len(containers) > 1:
        raise FeedValidationError(f"expected at most one categories element, found {len(containers)}")
    if not containers:
        return {}
    categories: dict[str, Category] = {}
    for node in containers[0].findall("category"):
        category_id = (node.attrib.get("id") or "").strip()
        name = _node_text(node)
        if not category_id or not name:
            raise FeedValidationError("category id and name are required")
        if category_id in categories:
            raise FeedValidationError(f"duplicate category id: {category_id}")
        categories[category_id] = Category(
            id=category_id,
            name=name,
            parent_id=(node.attrib.get("parentId") or "").strip() or None,
        )
    return categories


def _parse_currencies(shop: ET.Element) -> dict[str, Decimal]:
    containers = shop.findall("currencies")
    if len(containers) != 1:
        raise FeedValidationError(f"expected exactly one currencies element, found {len(containers)}")
    currencies: dict[str, Decimal] = {}
    for node in containers[0].findall("currency"):
        currency_id = (node.attrib.get("id") or "").strip()
        if not currency_id:
            raise FeedValidationError("currency id is required")
        if currency_id in currencies:
            raise FeedValidationError(f"duplicate currency id: {currency_id}")
        rate_text = (node.attrib.get("rate") or "1").strip()
        currencies[currency_id] = _decimal(rate_text, label="currency rate", item_id=currency_id, positive=True)
    if not currencies:
        raise FeedValidationError("at least one currency is required")
    return currencies


def _raw_attributes(offer: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {f"@{key}": value for key, value in offer.attrib.items()}
    counters: dict[str, int] = {}
    for node in list(offer):
        if node.tag == "param":
            base = f"param:{(node.attrib.get('name') or '').strip() or 'unnamed'}"
        else:
            base = node.tag
        counters[base] = counters.get(base, 0) + 1
        key = base if counters[base] == 1 else f"{base}#{counters[base]}"
        result[key] = _node_text(node)
        for attr_name, attr_value in node.attrib.items():
            result[f"{key}@{attr_name}"] = attr_value
    return result


def _images(offer: ET.Element, fields: tuple[str, ...]) -> list[str]:
    allowed = set(fields)
    return [_node_text(node) for node in list(offer) if node.tag in allowed and _node_text(node)]


def _read_source(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as handle:
        source_data = handle.read(max_bytes + 1)
    if len(source_data) > max_bytes:
        raise FeedValidationError(f"source size exceeds byte limit: {max_bytes}")
    return source_data


def _read_netlab_price_archive(source_data: bytes, max_bytes: int) -> bytes:
    try:
        with ZipFile(BytesIO(source_data)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) != 1 or members[0].filename.casefold() != "price.xml":
                raise FeedValidationError("Netlab archive must contain exactly one top-level Price.xml")
            info = members[0]
            if info.flag_bits & 0x1:
                raise FeedValidationError("encrypted Netlab archive is not accepted")
            if info.file_size > max_bytes:
                raise FeedValidationError(f"uncompressed Price.xml exceeds byte limit: {max_bytes}")
            with archive.open(info) as handle:
                xml_data = handle.read(max_bytes + 1)
            if len(xml_data) > max_bytes:
                raise FeedValidationError(f"uncompressed Price.xml exceeds byte limit: {max_bytes}")
            return xml_data
    except FeedValidationError:
        raise
    except (BadZipFile, KeyError, RuntimeError, ValueError) as exc:
        raise FeedValidationError(f"invalid Netlab XML archive: {exc}") from exc


def parse_legacy_xml(
    path: str | Path,
    fetched_at: str,
    *,
    mapping: LegacyXmlMapping,
    min_items: int = 1,
    max_items: int = 100_000,
    max_bytes: int = 64 * 1024 * 1024,
) -> SupplierSnapshot:
    """Parse one explicitly mapped, bounded XML/YML source into common models."""

    source_path = Path(path)
    source_data = _read_source(source_path, max_bytes)
    source_sha256 = hashlib.sha256(source_data).hexdigest()
    if source_path.suffix.casefold() == ".zip":
        if mapping.supplier_id != "netlab":
            raise FeedValidationError("zip source is supported only for the Netlab adapter")
        source_data = _read_netlab_price_archive(source_data, max_bytes)
    try:
        root = ET.fromstring(source_data)
    except (ET.ParseError, UnicodeError, DefusedXmlException) as exc:
        raise FeedValidationError(f"invalid XML feed: {exc}") from exc
    if root.tag != mapping.root_tag:
        raise FeedValidationError(f"invalid root element: {root.tag!r}")

    shops = root.findall("shop")
    if len(shops) != 1:
        raise FeedValidationError(f"expected exactly one shop element, found {len(shops)}")
    shop = shops[0]
    offers_containers = shop.findall("offers")
    if len(offers_containers) != 1:
        raise FeedValidationError(f"expected exactly one offers element, found {len(offers_containers)}")
    offers = offers_containers[0].findall("offer")
    if len(offers) > max_items:
        raise FeedValidationError(f"offer count exceeds maximum: {max_items}")

    categories = _parse_categories(shop)
    currencies = _parse_currencies(shop)
    items: list[SupplierItem] = []
    seen_item_ids: set[str] = set()
    seen_catalog_skus: set[str] = set()

    for offer in offers:
        item_id = (offer.attrib.get("id") or "").strip()
        if not item_id or any(char.isspace() or ord(char) < 32 for char in item_id):
            raise FeedValidationError("offer id is required and must not contain whitespace")
        if item_id in seen_item_ids:
            raise FeedValidationError(f"duplicate supplier item id: {item_id}")
        catalog_sku = f"{mapping.catalog_sku_prefix}{item_id}"
        if catalog_sku in seen_catalog_skus:
            raise FeedValidationError(f"duplicate generated catalog sku: {catalog_sku}")
        seen_item_ids.add(item_id)
        seen_catalog_skus.add(catalog_sku)

        source_price_text = _scalar(
            offer,
            mapping.price_fields,
            label="source price",
            item_id=item_id,
            required=True,
        )
        assert source_price_text is not None
        source_price = _decimal(source_price_text, label="source price", item_id=item_id, positive=True)
        currency = _scalar(
            offer,
            mapping.currency_fields,
            label="currency",
            item_id=item_id,
            required=True,
        )
        assert currency is not None
        if currency not in currencies:
            raise FeedValidationError(f"unknown currency {currency} for offer {item_id}")

        category_id = _scalar(
            offer,
            mapping.category_fields,
            label="category id",
            item_id=item_id,
        )
        category_path = _category_path(category_id, categories, item_id=item_id) if category_id else []
        quantity_text = _scalar(
            offer,
            mapping.quantity_fields,
            label="quantity",
            item_id=item_id,
        )
        quantity = (
            _quantity(
                quantity_text,
                item_id=item_id,
                symbolic_values=mapping.quantity_symbol_values,
            )
            if quantity_text is not None
            else None
        )

        availability_text = (offer.attrib.get(mapping.availability_attr) or "").strip()
        if availability_text:
            available = _boolean(availability_text, label="availability", item_id=item_id)
        elif quantity is not None:
            available = quantity > 0
        elif quantity_text in mapping.quantity_symbol_values:
            available = True
        else:
            raise FeedValidationError(f"availability is required for offer {item_id}")
        out_of_product = _scalar(
            offer,
            mapping.out_of_product_fields,
            label="out-of-product flag",
            item_id=item_id,
        )
        if out_of_product is not None and _boolean(out_of_product, label="out-of-product flag", item_id=item_id):
            available = False
        if quantity is not None and quantity <= 0:
            # Keep the supplier's raw availability attribute, but never expose
            # a non-positive stock signal as normalized availability.
            available = False

        dimensions = None
        if mapping.dimension_fields:
            dimension_values = [
                _scalar(offer, (field,), label=f"dimension {field}", item_id=item_id)
                for field in mapping.dimension_fields
            ]
            if any(value is not None for value in dimension_values):
                dimensions = " x ".join(value or "" for value in dimension_values)

        attributes = _raw_attributes(offer)
        items.append(
            SupplierItem(
                supplier=mapping.supplier_id,
                supplier_item_id=item_id,
                supplier_sku=item_id,
                catalog_sku=catalog_sku,
                manufacturer=_scalar(
                    offer,
                    mapping.manufacturer_fields,
                    label="manufacturer",
                    item_id=item_id,
                ),
                model=_scalar(offer, mapping.model_fields, label="model", item_id=item_id),
                mpn=_scalar(offer, mapping.mpn_fields, label="MPN", item_id=item_id),
                ean=_scalar(
                    offer,
                    mapping.ean_fields,
                    label="EAN/UPC",
                    item_id=item_id,
                    allow_multiple=True,
                ),
                name=_scalar(
                    offer,
                    mapping.name_fields,
                    label="name",
                    item_id=item_id,
                    required=True,
                )
                or "",
                category_id=category_id,
                category_path=category_path,
                source_price=source_price,
                currency=currency,
                quantity=quantity,
                available=available,
                source_url=_scalar(offer, mapping.source_url_fields, label="source URL", item_id=item_id),
                image_urls=_images(offer, mapping.image_fields),
                description=_scalar(offer, mapping.description_fields, label="description", item_id=item_id),
                sales_notes=_scalar(offer, mapping.sales_notes_fields, label="sales notes", item_id=item_id),
                warranty_days=_scalar(offer, mapping.warranty_fields, label="warranty", item_id=item_id),
                vat=_scalar(offer, mapping.vat_fields, label="VAT signal", item_id=item_id),
                weight=(
                    _decimal(
                        weight_text,
                        label="weight",
                        item_id=item_id,
                    )
                    if (weight_text := _scalar(offer, mapping.weight_fields, label="weight", item_id=item_id))
                    is not None
                    else None
                ),
                dimensions=dimensions,
                attributes=attributes,
                fetched_at=fetched_at,
                raw_hash=hashlib.sha256(ET.tostring(offer, encoding="utf-8")).hexdigest(),
            )
        )

    if len(items) < min_items:
        raise FeedValidationError(f"offer count {len(items)} is below minimum: {min_items}")
    return SupplierSnapshot(
        catalog_date=root.attrib.get("date"),
        source_sha256=source_sha256,
        currencies=currencies,
        categories=categories,
        items=items,
    )
