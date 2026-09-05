from __future__ import annotations

import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from .electrozone import FeedValidationError
from .models import SupplierItem, SupplierSnapshot
from .netlab_properties import (
    NetlabPropertiesStats,
    NetlabPropertyObservation,
    scan_netlab_properties,
)

_DESCRIPTION_PROPERTY_ID = "p9999995"
_UID_RE = re.compile(r"[1-9][0-9]*\Z")
_ALLOWED_IMAGE_HOST = "nlimg.netlab.ru"
_ALLOWED_TAGS = {
    "b",
    "br",
    "div",
    "em",
    "h2",
    "h3",
    "h4",
    "h5",
    "i",
    "li",
    "ol",
    "p",
    "span",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}
_VOID_TAGS = {"br"}
_BLOCKED_TAGS = {"embed", "iframe", "object", "script", "style", "template"}


class _SafeHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._blocked_depth = 0
        self._open_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        tag = tag.casefold()
        if self._blocked_depth:
            if tag in _BLOCKED_TAGS:
                self._blocked_depth += 1
            return
        if tag in _BLOCKED_TAGS:
            self._blocked_depth = 1
            return
        if tag in _ALLOWED_TAGS:
            self.parts.append(f"<{tag}>")
            if tag not in _VOID_TAGS:
                self._open_tags.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() in _ALLOWED_TAGS and tag.casefold() not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if self._blocked_depth:
            if tag in _BLOCKED_TAGS:
                self._blocked_depth = max(0, self._blocked_depth - 1)
            return
        if tag not in _ALLOWED_TAGS or tag in _VOID_TAGS or tag not in self._open_tags:
            return
        while self._open_tags:
            open_tag = self._open_tags.pop()
            self.parts.append(f"</{open_tag}>")
            if open_tag == tag:
                break

    def handle_data(self, data: str) -> None:
        if not self._blocked_depth:
            self.parts.append(html.escape(data, quote=False))

    def handle_comment(self, data: str) -> None:
        del data

    def finish(self) -> None:
        if self._blocked_depth:
            raise ValueError("blocked Netlab HTML tag is not closed")
        while self._open_tags:
            self.parts.append(f"</{self._open_tags.pop()}>")


def sanitize_supplier_html(value: str, *, max_chars: int = 256_000) -> str:
    if not isinstance(value, str) or not value:
        return ""
    if len(value) > max_chars:
        raise FeedValidationError("Netlab description exceeds character limit")
    parser = _SafeHtmlParser()
    try:
        parser.feed(value)
        parser.close()
        parser.finish()
    except ValueError as exc:
        raise FeedValidationError("invalid Netlab description HTML") from exc
    result = re.sub(r"[ \t]{2,}", " ", "".join(parser.parts).strip())
    if len(result) > max_chars:
        raise FeedValidationError("sanitized Netlab description exceeds character limit")
    return result


def _safe_image_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return (
        parsed.scheme.casefold() == "https"
        and hostname is not None
        and hostname.casefold() == _ALLOWED_IMAGE_HOST
        and parsed.username is None
        and parsed.password is None
        and port in {None, 443}
        and bool(parsed.path)
        and not parsed.fragment
    )


def _property_record(observation: NetlabPropertyObservation) -> dict[str, object]:
    return {
        "property_id": observation.property_id,
        "property_name": observation.property_name,
        "value": observation.value,
        "missing": observation.missing,
        "definition_missing": observation.definition_missing,
    }


@dataclass(frozen=True)
class NetlabEnrichmentResult:
    items: list[SupplierItem]
    properties_stats: NetlabPropertiesStats
    uid_price_items: int
    uid_properties_overlap: int
    description_items: int
    invalid_image_url_count: int
    missing_uid_count: int
    duplicate_uid_count: int

    @property
    def unknown_property_id_count(self) -> int:
        return self.properties_stats.unknown_property_id_count

    @property
    def unknown_observation_count(self) -> int:
        return self.properties_stats.unknown_observation_count


def enrich_netlab_snapshot(
    snapshot: SupplierSnapshot,
    properties_path: str | Path,
    *,
    max_bytes: int = 128 * 1024 * 1024,
) -> NetlabEnrichmentResult:
    invalid_uid_supplier_ids: set[str] = set()
    uid_to_supplier_ids: dict[str, list[str]] = {}
    for item in snapshot.items:
        uid = item.attributes.get("uid")
        if not isinstance(uid, str) or not _UID_RE.fullmatch(uid):
            invalid_uid_supplier_ids.add(item.supplier_item_id)
            continue
        uid_to_supplier_ids.setdefault(uid, []).append(item.supplier_item_id)
    duplicate_uids = {uid for uid, supplier_ids in uid_to_supplier_ids.items() if len(supplier_ids) > 1}
    uid_by_supplier_id = {
        supplier_id: uid
        for uid, supplier_ids in uid_to_supplier_ids.items()
        for supplier_id in supplier_ids
    }
    price_uids = set(uid_to_supplier_ids)
    properties_by_uid: dict[str, tuple[dict[str, object], str | None]] = {}

    def emit_item(item_id: str, observations: tuple[NetlabPropertyObservation, ...]) -> None:
        if item_id not in price_uids:
            return
        description: str | None = None
        records: list[dict[str, object]] = []
        for observation in observations:
            records.append(_property_record(observation))
            if observation.property_id == _DESCRIPTION_PROPERTY_ID and not observation.missing:
                if description is not None:
                    raise FeedValidationError(f"duplicate Netlab description for uid: {item_id}")
                description = observation.value
        properties_by_uid[item_id] = (records, description)

    stats = scan_netlab_properties(
        properties_path,
        max_bytes=max_bytes,
        allow_unknown_property_ids=True,
        emit_item=emit_item,
    )
    enriched_items: list[SupplierItem] = []
    description_count = 0
    invalid_image_count = 0
    for item in snapshot.items:
        uid = uid_by_supplier_id.get(item.supplier_item_id)
        uid_joinable = uid is not None and uid not in duplicate_uids
        property_data = properties_by_uid.get(uid) if uid_joinable and uid is not None else None
        records, description_html = property_data if property_data is not None else ([], None)
        description = sanitize_supplier_html(description_html) if description_html is not None else None
        if description == "":
            description = None
        if description is not None:
            description_count += 1
        description_sanitized_empty = description_html is not None and description is None
        safe_images = [url for url in item.image_urls if _safe_image_url(url)]
        invalid_images = [url for url in item.image_urls if not _safe_image_url(url)]
        invalid_image_count += len(invalid_images)
        review_only = (
            item.supplier_item_id in invalid_uid_supplier_ids
            or uid in duplicate_uids
            or property_data is None and uid is not None
            or description_sanitized_empty
            or bool(invalid_images)
            or any(bool(record["definition_missing"]) for record in records)
        )
        join_provenance: dict[str, object] = {
            "key": "uid",
            "item_id": uid,
            "matched": property_data is not None,
        }
        if item.supplier_item_id in invalid_uid_supplier_ids:
            join_provenance["reason"] = "missing_price_uid"
        elif uid in duplicate_uids:
            join_provenance["reason"] = "duplicate_price_uid"
        elif property_data is None:
            join_provenance["reason"] = "uid_not_in_properties_feed"
        provenance: dict[str, object] = {
            "join": join_provenance,
            "properties": {
                "source": "GoodsProperties.zip",
                "source_sha256": stats.source_sha256,
                "catalog_date": stats.catalog_date,
                "item_id": uid,
            },
            "images": {
                "source": "pricexml4.zip",
                "source_sha256": snapshot.source_sha256,
                "fields": ["picture", "picture2", "picture3"],
                "invalid_urls": invalid_images,
            },
            "detail_page": {
                "source_url": item.source_url,
                "status": "not_fetched",
            },
            "review_only": review_only,
        }
        if description_html is not None:
            provenance["description"] = {
                "source": "GoodsProperties.zip",
                "source_sha256": stats.source_sha256,
                "property_id": _DESCRIPTION_PROPERTY_ID,
                "item_id": uid,
                "sanitized": True,
            }
        enriched_items.append(
            item.model_copy(
                update={
                    "description": description,
                    "description_html": description,
                    "properties": records,
                    "content_provenance": provenance,
                    "image_urls": safe_images,
                }
            )
        )
    return NetlabEnrichmentResult(
        items=enriched_items,
        properties_stats=stats,
        uid_price_items=len(price_uids),
        uid_properties_overlap=len(set(properties_by_uid).difference(duplicate_uids)),
        description_items=description_count,
        invalid_image_url_count=invalid_image_count,
        missing_uid_count=len(invalid_uid_supplier_ids),
        duplicate_uid_count=len(duplicate_uids),
    )
