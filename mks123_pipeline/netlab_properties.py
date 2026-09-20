from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from .electrozone import FeedValidationError
from .integrity import read_evidence

_PROPERTY_ID_RE = re.compile(r"p[1-9][0-9]*\Z")
_ITEM_ID_RE = re.compile(r"[1-9][0-9]*\Z")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}\Z")
_DEFAULT_MAX_PROPERTIES = 100_000
_DEFAULT_MAX_ITEMS = 100_000
_DEFAULT_MAX_OBSERVATIONS = 5_000_000


@dataclass(frozen=True)
class NetlabPropertyDefinition:
    property_id: str
    name: str


@dataclass(frozen=True)
class NetlabPropertyObservation:
    item_id: str
    property_id: str
    property_name: str | None
    value: str
    missing: bool
    definition_missing: bool


@dataclass(frozen=True)
class NetlabPropertiesStats:
    catalog_date: str
    source_sha256: str
    property_count: int
    item_count: int
    observation_count: int
    missing_observation_count: int
    unknown_property_id_count: int
    unknown_observation_count: int


def _node_text(node: ET.Element) -> str:
    return "".join(node.itertext()).strip()


def _read_source(path: Path, max_bytes: int) -> bytes:
    try:
        data = read_evidence(path, max_bytes=max_bytes).data
    except (OSError, ValueError) as exc:
        raise FeedValidationError(f"cannot read Netlab properties source: {exc}") from exc
    if len(data) > max_bytes:
        raise FeedValidationError(f"Netlab properties source exceeds byte limit: {max_bytes}")
    return data


def _read_properties_archive(source_data: bytes, max_bytes: int) -> bytes:
    try:
        with ZipFile(BytesIO(source_data)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) != 1 or members[0].filename.casefold() != "goodsproperties.xml":
                raise FeedValidationError(
                    "Netlab properties archive must contain exactly one top-level GoodsProperties.xml"
                )
            info = members[0]
            if info.flag_bits & 0x1:
                raise FeedValidationError("encrypted Netlab properties archive is not accepted")
            if info.file_size > max_bytes:
                raise FeedValidationError(f"uncompressed GoodsProperties.xml exceeds byte limit: {max_bytes}")
            with archive.open(info) as handle:
                xml_data = handle.read(max_bytes + 1)
            if len(xml_data) > max_bytes:
                raise FeedValidationError(f"uncompressed GoodsProperties.xml exceeds byte limit: {max_bytes}")
            return xml_data
    except FeedValidationError:
        raise
    except (BadZipFile, KeyError, RuntimeError, ValueError) as exc:
        raise FeedValidationError(f"invalid Netlab properties archive: {exc}") from exc


def scan_netlab_properties(
    path: str | Path,
    *,
    max_bytes: int = 128 * 1024 * 1024,
    max_properties: int = _DEFAULT_MAX_PROPERTIES,
    max_items: int = _DEFAULT_MAX_ITEMS,
    max_observations: int = _DEFAULT_MAX_OBSERVATIONS,
    emit: Callable[[NetlabPropertyObservation], None] | None = None,
    emit_item: Callable[[str, tuple[NetlabPropertyObservation, ...]], None] | None = None,
    allow_unknown_property_ids: bool = False,
) -> NetlabPropertiesStats:
    """Validate and stream the official Netlab GoodsProperties XML."""

    for label, limit in (
        ("max_properties", max_properties),
        ("max_items", max_items),
        ("max_observations", max_observations),
    ):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise FeedValidationError(f"{label} parser bound must be a positive integer")

    source_path = Path(path)
    source_data = _read_source(source_path, max_bytes)
    source_sha256 = hashlib.sha256(source_data).hexdigest()
    if source_path.suffix.casefold() == ".zip":
        source_data = _read_properties_archive(source_data, max_bytes)
    definitions: dict[str, NetlabPropertyDefinition] = {}
    item_ids: set[str] = set()
    property_container_count = 0
    items_container_count = 0
    property_count = 0
    item_count = 0
    observation_count = 0
    observation_start_count = 0
    missing_observation_count = 0
    unknown_property_ids: set[str] = set()
    unknown_observation_count = 0
    catalog_date: str | None = None
    root_seen = False
    element_stack: list[str] = []

    try:
        context = ET.iterparse(BytesIO(source_data), events=("start", "end"))
        for event, element in context:
            tag = element.tag
            if not isinstance(tag, str):
                raise FeedValidationError("Netlab properties XML contains a non-text element name")
            if event == "start":
                if len(element_stack) >= 2 and element_stack[-1] == "item" and element_stack[-2] == "items":
                    observation_start_count += 1
                    if observation_start_count > max_observations:
                        raise FeedValidationError("observation count exceeds maximum")
                if not root_seen:
                    root_seen = True
                    if tag != "xml_catalog":
                        raise FeedValidationError(f"invalid Netlab properties root element: {tag!r}")
                    catalog_date = (element.attrib.get("date") or "").strip()
                    if not _DATE_RE.fullmatch(catalog_date):
                        raise FeedValidationError(f"invalid Netlab properties catalog date: {catalog_date!r}")
                element_stack.append(tag)
                continue

            parent = element_stack[-2] if len(element_stack) >= 2 else None
            if tag == "properties" and parent != "xml_catalog":
                raise FeedValidationError("Netlab properties container must be a direct child of xml_catalog")
            if tag == "items" and parent != "xml_catalog":
                raise FeedValidationError("Netlab items container must be a direct child of xml_catalog")
            if tag == "property" and parent != "properties":
                raise FeedValidationError("Netlab property must be a direct child of properties")
            if tag == "item" and parent != "items":
                raise FeedValidationError("Netlab item must be a direct child of items")
            if not element_stack or element_stack[-1] != tag:
                raise FeedValidationError("Netlab properties XML element ancestry is invalid")

            if tag == "property":
                if property_count >= max_properties:
                    raise FeedValidationError("property definition count exceeds maximum")
                property_id = (element.attrib.get("id") or "").strip()
                name = _node_text(element)
                if not _PROPERTY_ID_RE.fullmatch(property_id) or property_id == "p0":
                    raise FeedValidationError(f"invalid Netlab property id: {property_id!r}")
                if not name:
                    raise FeedValidationError(f"empty Netlab property name: {property_id}")
                if property_id in definitions:
                    raise FeedValidationError(f"duplicate Netlab property id: {property_id}")
                definitions[property_id] = NetlabPropertyDefinition(property_id=property_id, name=name)
                property_count += 1
                element.clear()
            elif tag == "properties":
                property_container_count += 1
                element.clear()
            elif tag == "item":
                if item_count >= max_items:
                    raise FeedValidationError("item count exceeds maximum")
                item_id = (element.attrib.get("id") or "").strip()
                if not _ITEM_ID_RE.fullmatch(item_id):
                    raise FeedValidationError(f"invalid Netlab properties item id: {item_id!r}")
                if item_id in item_ids:
                    raise FeedValidationError(f"duplicate Netlab properties item id: {item_id}")
                item_ids.add(item_id)
                seen_property_ids: set[str] = set()
                item_observations: list[NetlabPropertyObservation] = []
                for child in list(element):
                    if observation_count >= max_observations:
                        raise FeedValidationError("observation count exceeds maximum")
                    property_id = child.tag
                    if not isinstance(property_id, str) or not _PROPERTY_ID_RE.fullmatch(property_id):
                        raise FeedValidationError(
                            f"invalid Netlab property tag {property_id!r} for item {item_id}"
                        )
                    if property_id in seen_property_ids:
                        raise FeedValidationError(f"duplicate property {property_id} for item {item_id}")
                    definition = definitions.get(property_id)
                    if definition is None:
                        if not allow_unknown_property_ids:
                            raise FeedValidationError(f"unknown property {property_id} for item {item_id}")
                        unknown_property_ids.add(property_id)
                        unknown_observation_count += 1
                    seen_property_ids.add(property_id)
                    value = _node_text(child)
                    missing = value in {"", "-"}
                    observation = NetlabPropertyObservation(
                        item_id=item_id,
                        property_id=property_id,
                        property_name=definition.name if definition is not None else None,
                        value=value,
                        missing=missing,
                        definition_missing=definition is None,
                    )
                    if emit is not None:
                        emit(observation)
                    item_observations.append(observation)
                    observation_count += 1
                    if missing:
                        missing_observation_count += 1
                if emit_item is not None:
                    emit_item(item_id, tuple(item_observations))
                item_count += 1
                element.clear()
            elif tag == "items":
                items_container_count += 1
                element.clear()
            element_stack.pop()
    except FeedValidationError:
        raise
    except (ET.ParseError, UnicodeError, DefusedXmlException) as exc:
        raise FeedValidationError(f"invalid Netlab properties XML: {exc}") from exc

    if not root_seen:
        raise FeedValidationError("Netlab properties XML is empty")
    if property_container_count != 1:
        raise FeedValidationError(
            f"expected exactly one Netlab properties element, found {property_container_count}"
        )
    if items_container_count != 1:
        raise FeedValidationError(f"expected exactly one Netlab items element, found {items_container_count}")
    if not definitions:
        raise FeedValidationError("Netlab properties XML contains no property definitions")
    if not item_ids:
        raise FeedValidationError("Netlab properties XML contains no item descriptions")
    assert catalog_date is not None
    return NetlabPropertiesStats(
        catalog_date=catalog_date,
        source_sha256=source_sha256,
        property_count=property_count,
        item_count=item_count,
        observation_count=observation_count,
        missing_observation_count=missing_observation_count,
        unknown_property_id_count=len(unknown_property_ids),
        unknown_observation_count=unknown_observation_count,
    )
