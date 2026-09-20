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
from .integrity import read_evidence
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


def _offer_child_values(offer: ET.Element) -> list[tuple[ET.Element, str]]:
    return [(node, _node_text(node)) for node in offer]


def _values_from_children(
    children: list[tuple[ET.Element, str]],
    fields: tuple[str, ...],
) -> list[str]:
    if not fields:
        return []
    allowed = set(fields)
    return [value for node, value in children if node.tag in allowed and value]


def _values(offer: ET.Element, fields: tuple[str, ...]) -> list[str]:
    return _values_from_children(_offer_child_values(offer), fields)


def _scalar(
    offer: ET.Element,
    fields: tuple[str, ...],
    *,
    label: str,
    item_id: str,
    required: bool = False,
    allow_multiple: bool = False,
    child_values: list[tuple[ET.Element, str]] | None = None,
) -> str | None:
    values = _values(offer, fields) if child_values is None else _values_from_children(child_values, fields)
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


def _parse_categories_container(container: ET.Element) -> dict[str, Category]:
    categories: dict[str, Category] = {}
    for node in container.findall("category"):
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


def _parse_categories(shop: ET.Element) -> dict[str, Category]:
    containers = shop.findall("categories")
    if len(containers) > 1:
        raise FeedValidationError(f"expected at most one categories element, found {len(containers)}")
    if not containers:
        return {}
    return _parse_categories_container(containers[0])


def _parse_currencies_container(container: ET.Element) -> dict[str, Decimal]:
    currencies: dict[str, Decimal] = {}
    for node in container.findall("currency"):
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


def _parse_currencies(shop: ET.Element) -> dict[str, Decimal]:
    containers = shop.findall("currencies")
    if len(containers) != 1:
        raise FeedValidationError(f"expected exactly one currencies element, found {len(containers)}")
    return _parse_currencies_container(containers[0])


def _raw_attributes(
    offer: ET.Element,
    *,
    child_values: list[tuple[ET.Element, str]] | None = None,
) -> dict[str, str]:
    result: dict[str, str] = {f"@{key}": value for key, value in offer.attrib.items()}
    counters: dict[str, int] = {}
    children = _offer_child_values(offer) if child_values is None else child_values
    for node, value in children:
        if node.tag == "param":
            base = f"param:{(node.attrib.get('name') or '').strip() or 'unnamed'}"
        else:
            base = node.tag
        counters[base] = counters.get(base, 0) + 1
        key = base if counters[base] == 1 else f"{base}#{counters[base]}"
        result[key] = value
        for attr_name, attr_value in node.attrib.items():
            result[f"{key}@{attr_name}"] = attr_value
    return result


def _images(
    offer: ET.Element,
    fields: tuple[str, ...],
    *,
    child_values: list[tuple[ET.Element, str]] | None = None,
) -> list[str]:
    children = _offer_child_values(offer) if child_values is None else child_values
    return _values_from_children(children, fields)


def _read_source(path: Path, max_bytes: int) -> bytes:
    source_data = read_evidence(path, max_bytes=max_bytes).data
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


def _parse_offer(
    offer: ET.Element,
    mapping: LegacyXmlMapping,
    *,
    fetched_at: str,
) -> SupplierItem:
    item_id = (offer.attrib.get("id") or "").strip()
    if not item_id or any(char.isspace() or ord(char) < 32 for char in item_id):
        raise FeedValidationError("offer id is required and must not contain whitespace")

    catalog_sku = f"{mapping.catalog_sku_prefix}{item_id}"
    child_values = _offer_child_values(offer)
    source_price_text = _scalar(
        offer,
        mapping.price_fields,
        label="source price",
        item_id=item_id,
        child_values=child_values,
        required=True,
    )
    assert source_price_text is not None
    source_price = _decimal(source_price_text, label="source price", item_id=item_id, positive=True)
    currency = _scalar(
        offer,
        mapping.currency_fields,
        label="currency",
        item_id=item_id,
        child_values=child_values,
        required=True,
    )
    assert currency is not None
    category_id = _scalar(
        offer,
        mapping.category_fields,
        label="category id",
        item_id=item_id,
        child_values=child_values,
    )
    quantity_text = _scalar(
        offer,
        mapping.quantity_fields,
        label="quantity",
        item_id=item_id,
        child_values=child_values,
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
        child_values=child_values,
    )
    if out_of_product is not None and _boolean(out_of_product, label="out-of-product flag", item_id=item_id):
        available = False
    if quantity is not None and quantity <= 0:
        available = False

    dimensions = None
    if mapping.dimension_fields:
        dimension_values = [
            _scalar(
                offer,
                (field,),
                label=f"dimension {field}",
                item_id=item_id,
                child_values=child_values,
            )
            for field in mapping.dimension_fields
        ]
        if any(value is not None for value in dimension_values):
            dimensions = " x ".join(value or "" for value in dimension_values)

    attributes = _raw_attributes(offer, child_values=child_values)
    return SupplierItem(
        supplier=mapping.supplier_id,
        supplier_item_id=item_id,
        supplier_sku=item_id,
        catalog_sku=catalog_sku,
        manufacturer=_scalar(
            offer,
            mapping.manufacturer_fields,
            label="manufacturer",
            item_id=item_id,
            child_values=child_values,
        ),
        model=_scalar(offer, mapping.model_fields, label="model", item_id=item_id, child_values=child_values),
        mpn=_scalar(offer, mapping.mpn_fields, label="MPN", item_id=item_id, child_values=child_values),
        ean=_scalar(
            offer,
            mapping.ean_fields,
            label="EAN/UPC",
            item_id=item_id,
            child_values=child_values,
            allow_multiple=True,
        ),
        name=_scalar(
            offer,
            mapping.name_fields,
            label="name",
            item_id=item_id,
            child_values=child_values,
            required=True,
        )
        or "",
        category_id=category_id,
        source_price=source_price,
        currency=currency,
        quantity=quantity,
        available=available,
        source_url=_scalar(
            offer,
            mapping.source_url_fields,
            label="source URL",
            item_id=item_id,
            child_values=child_values,
        ),
        image_urls=_images(offer, mapping.image_fields, child_values=child_values),
        description=_scalar(
            offer,
            mapping.description_fields,
            label="description",
            item_id=item_id,
            child_values=child_values,
        ),
        sales_notes=_scalar(
            offer,
            mapping.sales_notes_fields,
            label="sales notes",
            item_id=item_id,
            child_values=child_values,
        ),
        warranty_days=_scalar(
            offer,
            mapping.warranty_fields,
            label="warranty",
            item_id=item_id,
            child_values=child_values,
        ),
        vat=_scalar(
            offer,
            mapping.vat_fields,
            label="VAT signal",
            item_id=item_id,
            child_values=child_values,
        ),
        weight=(
            _decimal(weight_text, label="weight", item_id=item_id)
            if (
                weight_text := _scalar(
                    offer,
                    mapping.weight_fields,
                    label="weight",
                    item_id=item_id,
                    child_values=child_values,
                )
            )
            is not None
            else None
        ),
        dimensions=dimensions,
        attributes=attributes,
        fetched_at=fetched_at,
        raw_hash=hashlib.sha256(ET.tostring(offer, encoding="utf-8")).hexdigest(),
    )


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

    categories: dict[str, Category] = {}
    currencies: dict[str, Decimal] | None = None
    catalog_date: str | None = None
    items: list[SupplierItem] = []
    seen_item_ids: set[str] = set()
    seen_catalog_skus: set[str] = set()
    element_stack: list[str] = []
    active_offer_depth: int | None = None
    active_container_depth: int | None = None
    root_seen = False
    shop_count = 0
    categories_container_count = 0
    currencies_container_count = 0
    offers_container_count = 0
    offer_count = 0
    pending_offer: ET.Element | None = None

    def flush_pending_offer() -> None:
        nonlocal pending_offer
        if pending_offer is None:
            return
        item = _parse_offer(pending_offer, mapping, fetched_at=fetched_at)
        if item.category_id and categories:
            item = item.model_copy(
                update={
                    "category_path": _category_path(
                        item.category_id,
                        categories,
                        item_id=item.supplier_item_id,
                    )
                }
            )
        if item.supplier_item_id in seen_item_ids:
            raise FeedValidationError(f"duplicate supplier item id: {item.supplier_item_id}")
        if item.catalog_sku in seen_catalog_skus:
            raise FeedValidationError(f"duplicate generated catalog sku: {item.catalog_sku}")
        seen_item_ids.add(item.supplier_item_id)
        seen_catalog_skus.add(item.catalog_sku)
        items.append(item)
        pending_offer.clear()
        pending_offer = None

    try:
        context = ET.iterparse(BytesIO(source_data), events=("start", "end"))
        for event, element in context:
            flush_pending_offer()
            tag = element.tag
            if not isinstance(tag, str):
                raise FeedValidationError("XML feed contains a non-text element name")

            if event == "start":
                parent = element_stack[-1] if element_stack else None
                if not root_seen:
                    root_seen = True
                    if tag != mapping.root_tag:
                        raise FeedValidationError(f"invalid root element: {tag!r}")
                    catalog_date = element.attrib.get("date")
                if len(element_stack) == 1 and parent == mapping.root_tag and tag == "shop":
                    shop_count += 1
                    if shop_count > 1:
                        raise FeedValidationError(f"expected exactly one shop element, found {shop_count}")
                if (
                    len(element_stack) == 2
                    and element_stack[-1] == "shop"
                    and element_stack[-2] == mapping.root_tag
                ):
                    if tag == "categories":
                        categories_container_count += 1
                        if categories_container_count > 1:
                            raise FeedValidationError(
                                f"expected at most one categories element, found {categories_container_count}"
                            )
                        active_container_depth = len(element_stack)
                    elif tag == "currencies":
                        currencies_container_count += 1
                        if currencies_container_count > 1:
                            raise FeedValidationError(
                                f"expected exactly one currencies element, found {currencies_container_count}"
                            )
                        active_container_depth = len(element_stack)
                    elif tag == "offers":
                        offers_container_count += 1
                        if offers_container_count > 1:
                            raise FeedValidationError(
                                f"expected exactly one offers element, found {offers_container_count}"
                            )
                if (
                    len(element_stack) == 3
                    and element_stack[-1] == "offers"
                    and element_stack[-2] == "shop"
                    and element_stack[-3] == mapping.root_tag
                    and tag == "offer"
                ):
                    offer_count += 1
                    if offer_count > max_items:
                        raise FeedValidationError(f"offer count exceeds maximum: {max_items}")
                    active_offer_depth = len(element_stack)
                element_stack.append(tag)
                continue

            if not element_stack or element_stack[-1] != tag:
                raise FeedValidationError("XML feed element ancestry is invalid")
            direct_shop_child = (
                len(element_stack) == 3
                and element_stack[-1] == tag
                and element_stack[-2] == "shop"
                and element_stack[-3] == mapping.root_tag
            )
            direct_categories = (
                direct_shop_child and tag == "categories"
            )
            direct_currencies = (
                direct_shop_child and tag == "currencies"
            )
            direct_offer = (
                len(element_stack) == 4
                and element_stack[-1] == tag == "offer"
                and element_stack[-2] == "offers"
                and element_stack[-3] == "shop"
                and element_stack[-4] == mapping.root_tag
            )
            if direct_offer:
                pending_offer = element
                active_offer_depth = None
            elif active_offer_depth is None and active_container_depth is not None:
                if direct_categories:
                    categories = _parse_categories_container(element)
                    active_container_depth = None
                elif direct_currencies:
                    currencies = _parse_currencies_container(element)
                    active_container_depth = None
            elif active_offer_depth is None:
                element.clear()
            element_stack.pop()
        flush_pending_offer()
    except FeedValidationError:
        raise
    except (ET.ParseError, UnicodeError, DefusedXmlException) as exc:
        raise FeedValidationError(f"invalid XML feed: {exc}") from exc

    if not root_seen:
        raise FeedValidationError("XML feed is empty")
    if shop_count != 1:
        raise FeedValidationError(f"expected exactly one shop element, found {shop_count}")
    if currencies_container_count != 1 or currencies is None:
        raise FeedValidationError(f"expected exactly one currencies element, found {currencies_container_count}")
    if offers_container_count != 1:
        raise FeedValidationError(f"expected exactly one offers element, found {offers_container_count}")
    for index, item in enumerate(items):
        if item.currency not in currencies:
            raise FeedValidationError(f"unknown currency {item.currency} for offer {item.supplier_item_id}")
        if item.category_id and not item.category_path:
            items[index] = item.model_copy(
                update={
                    "category_path": _category_path(
                        item.category_id,
                        categories,
                        item_id=item.supplier_item_id,
                    )
                }
            )
    if len(items) < min_items:
        raise FeedValidationError(f"offer count {len(items)} is below minimum: {min_items}")
    return SupplierSnapshot(
        catalog_date=catalog_date,
        source_sha256=source_sha256,
        currencies=currencies,
        categories=categories,
        items=items,
    )
