from __future__ import annotations

import hashlib
from decimal import Decimal, InvalidOperation
from pathlib import Path

from defusedxml import ElementTree as ET

from .models import Category, SupplierItem, SupplierSnapshot


class FeedValidationError(ValueError):
    """The supplier feed failed a structural or identity invariant."""


def _values(parent: ET.Element, name: str) -> list[str]:
    return [(node.text or "").strip() for node in parent.findall(name)]


def _text(parent: ET.Element, name: str) -> str | None:
    values = _values(parent, name)
    if not values:
        return None
    if len(set(values)) > 1:
        raise FeedValidationError(f"conflicting {name} values")
    return values[0] or None


def _parse_boolean_token(value: str, *, field: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "1", "+"}:
        return True
    if normalized in {"false", "no", "0", "-"}:
        return False
    raise FeedValidationError(f"invalid {field} boolean value: {value!r}")


def _boolean(parent: ET.Element, name: str) -> bool | None:
    value = _text(parent, name)
    return _parse_boolean_token(value, field=name) if value is not None else None


def _parse_decimal(value: str, *, field: str) -> Decimal:
    try:
        parsed = Decimal(value.strip())
    except (InvalidOperation, ValueError) as exc:
        raise FeedValidationError(f"invalid decimal for {field}: {value!r}") from exc
    if not parsed.is_finite():
        raise FeedValidationError(f"invalid decimal for {field}: {value!r}")
    return parsed


def _decimal(parent: ET.Element, name: str) -> Decimal | None:
    value = _text(parent, name)
    return _parse_decimal(value, field=name) if value is not None else None


def _category_path(category_id: str | None, categories: dict[str, Category]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    current = category_id
    while current and current in categories and current not in seen:
        seen.add(current)
        category = categories[current]
        result.append(category.name)
        current = category.parent_id
    return list(reversed(result))


def _validate_categories(categories: dict[str, Category]) -> None:
    for category in categories.values():
        if category.parent_id and category.parent_id not in categories:
            raise FeedValidationError(
                f"unknown parent category {category.parent_id} for category {category.id}"
            )
        seen: set[str] = set()
        current = category.id
        while current:
            if current in seen:
                raise FeedValidationError(f"category parent cycle detected at: {current}")
            seen.add(current)
            parent_id = categories[current].parent_id
            current = parent_id if parent_id in categories else ""


def _raw_attributes(offer: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {f"@{key}": value for key, value in offer.attrib.items()}
    counters: dict[str, int] = {}
    for node in list(offer):
        if node.tag == "param":
            base = node.attrib.get("name", "").strip()
            if not base:
                raise FeedValidationError("param name is required")
        else:
            base = node.tag
        counters[base] = counters.get(base, 0) + 1
        key = base if counters[base] == 1 else f"{base}#{counters[base]}"
        result[key] = "".join(node.itertext()).strip()
        for attr_name, attr_value in node.attrib.items():
            result[f"{key}@{attr_name}"] = attr_value
    return result


def parse_yml(
    path: str | Path,
    fetched_at: str,
    *,
    min_items: int = 1,
    max_items: int = 100_000,
    max_bytes: int = 64 * 1024 * 1024,
) -> SupplierSnapshot:
    path = Path(path)
    with path.open("rb") as handle:
        source_data = handle.read(max_bytes + 1)
    if len(source_data) > max_bytes:
        raise FeedValidationError(f"source size exceeds byte limit: {max_bytes}")
    try:
        root = ET.fromstring(source_data)
    except ET.ParseError as exc:
        raise FeedValidationError(f"invalid XML feed: {exc}") from exc
    if root.tag != "yml_catalog":
        raise FeedValidationError(f"invalid root element: {root.tag!r}")

    shops = root.findall("shop")
    if len(shops) != 1:
        raise FeedValidationError(f"expected exactly one shop element, found {len(shops)}")
    shop = shops[0]
    offers_containers = shop.findall("offers")
    if len(offers_containers) != 1:
        raise FeedValidationError(f"expected exactly one offers element, found {len(offers_containers)}")
    offers_container = offers_containers[0]
    categories: dict[str, Category] = {}
    for node in shop.findall("./categories/category"):
        category_id = node.attrib.get("id", "").strip()
        if not category_id:
            raise FeedValidationError("category id is required")
        if category_id in categories:
            raise FeedValidationError(f"duplicate category id: {category_id}")
        category_name = (node.text or "").strip()
        if not category_name:
            raise FeedValidationError(f"category name is required: {category_id}")
        categories[category_id] = Category(
            id=category_id,
            name=category_name,
            parent_id=(node.attrib.get("parentId") or "").strip() or None,
        )
    _validate_categories(categories)
    currency_containers = shop.findall("currencies")
    if len(currency_containers) != 1:
        raise FeedValidationError(
            f"expected exactly one currencies element, found {len(currency_containers)}"
        )
    currencies: dict[str, Decimal] = {}
    for node in currency_containers[0].findall("currency"):
        currency_id = node.attrib.get("id", "").strip()
        if not currency_id:
            raise FeedValidationError("currency id is required")
        if currency_id in currencies:
            raise FeedValidationError(f"duplicate currency id: {currency_id}")
        rate = _parse_decimal(node.attrib.get("rate", "1"), field=f"currency {currency_id} rate")
        if rate <= 0:
            raise FeedValidationError(f"currency rate must be positive: {currency_id}")
        currencies[currency_id] = rate
    if not currencies:
        raise FeedValidationError("at least one currency is required")
    items: list[SupplierItem] = []
    seen_item_ids: set[str] = set()
    seen_catalog_skus: set[str] = set()
    for offer in offers_container.findall("offer"):
        item_id = offer.attrib.get("id", "").strip()
        if not item_id:
            raise FeedValidationError("offer id is required")
        if item_id in seen_item_ids:
            raise FeedValidationError(f"duplicate supplier item id: {item_id}")
        catalog_sku = f"11{item_id}"
        if catalog_sku in seen_catalog_skus:
            raise FeedValidationError(f"duplicate generated catalog sku: {catalog_sku}")
        seen_item_ids.add(item_id)
        seen_catalog_skus.add(catalog_sku)
        attributes = _raw_attributes(offer)
        category_id = _text(offer, "categoryId")
        if category_id and category_id not in categories:
            raise FeedValidationError(f"unknown category for offer {item_id}: {category_id}")
        currency = _text(offer, "currencyId")
        if not currency:
            raise FeedValidationError(f"currencyId is required for offer: {item_id}")
        if currency not in currencies:
            raise FeedValidationError(f"offer currency is not declared: {currency}")
        raw_hash = hashlib.sha256(ET.tostring(offer, encoding="utf-8")).hexdigest()
        vendor_code = _text(offer, "vendorCode")
        barcode_values = list(dict.fromkeys(value for value in _values(offer, "barcode") if value))
        identity_warnings: list[str] = []
        if len(barcode_values) > 1:
            ean = None
            identity_warnings.append("ambiguous_ean")
        else:
            ean = barcode_values[0] if barcode_values else None
        availability_value = offer.attrib.get("available")
        available = (
            _parse_boolean_token(availability_value, field="availability")
            if availability_value is not None
            else False
        )
        items.append(
            SupplierItem(
                supplier_item_id=item_id,
                supplier_sku=item_id,
                catalog_sku=catalog_sku,
                manufacturer=_text(offer, "vendor"),
                model=vendor_code,
                mpn=vendor_code,
                ean=ean,
                identity_warnings=identity_warnings,
                name=_text(offer, "name") or "",
                category_id=category_id,
                category_path=_category_path(category_id, categories),
                source_price=_parse_decimal(_text(offer, "price") or "0", field="price"),
                old_price=_decimal(offer, "oldprice"),
                currency=currency,
                available=available,
                store=_boolean(offer, "store"),
                pickup=_boolean(offer, "pickup"),
                delivery=_boolean(offer, "delivery"),
                source_url=_text(offer, "url"),
                image_urls=[n.text.strip() for n in offer.findall("picture") if n.text and n.text.strip()],
                description=_text(offer, "description"),
                sales_notes=_text(offer, "sales_notes"),
                manufacturer_warranty=_boolean(offer, "manufacturer_warranty"),
                warranty_days=_text(offer, "warranty-days"),
                vat=_text(offer, "vat"),
                weight=_decimal(offer, "weight"),
                dimensions=_text(offer, "dimensions"),
                attributes=attributes,
                fetched_at=fetched_at,
                raw_hash=raw_hash,
            )
        )
        if len(items) > max_items:
            raise FeedValidationError(f"offer count exceeds maximum: {max_items}")
    if len(items) < min_items:
        raise FeedValidationError(f"offer count {len(items)} is below minimum: {min_items}")
    return SupplierSnapshot(
        catalog_date=root.attrib.get("date"),
        source_sha256=hashlib.sha256(source_data).hexdigest(),
        currencies=currencies,
        categories=categories,
        items=items,
    )
