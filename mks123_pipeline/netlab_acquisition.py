from __future__ import annotations

import hashlib
import math
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .netlab_properties import NetlabPropertiesStats

DEFAULT_PRICE_URL = "https://www.netlab.ru/products/pricexml4.zip"
DEFAULT_PROPERTIES_URL = "https://www.netlab.ru/products/GoodsProperties.zip"
_ALLOWED_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/octet-stream",
}
_REQUIRED_KEYS = {
    "supplier",
    "feed_kind",
    "source",
    "source_url",
    "fetched_at_utc",
    "local_file",
    "sha256",
    "size_bytes",
    "content_type",
    "http_status",
    "feed_catalog_date",
    "item_count",
    "currency_rates",
    "credentials_persisted",
    "publication_enabled",
    "production_writes",
    "max_feed_age_hours",
    "feed_age_seconds",
}


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Netlab acquisition metadata {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Netlab acquisition metadata {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"Netlab acquisition metadata {label} has no timezone")
    return parsed


def validate_netlab_acquisition_metadata(
    payload: Any,
    *,
    source_data: bytes,
    expected_fetched_at: str,
    expected_catalog_date: str | None,
    expected_item_count: int,
    expected_currency_rates: dict[str, Decimal],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError("Netlab acquisition metadata must be a JSON object")
    missing = sorted(_REQUIRED_KEYS - set(payload))
    if missing:
        raise ValueError(f"Netlab acquisition metadata is missing: {', '.join(missing)}")
    if payload["supplier"] != "netlab" or payload["feed_kind"] != "price":
        raise ValueError("Netlab acquisition metadata supplier/feed kind mismatch")
    if payload["source"] != "direct_https" or payload["source_url"] != DEFAULT_PRICE_URL:
        raise ValueError("Netlab acquisition metadata source is not allowlisted")
    if payload["http_status"] != 200:
        raise ValueError("Netlab acquisition metadata must describe HTTP 200")
    if payload["credentials_persisted"] is not False:
        raise ValueError("Netlab acquisition metadata records persisted credentials")
    if payload["publication_enabled"] is not False or payload["production_writes"] != 0:
        raise ValueError("Netlab acquisition metadata permits production writes")

    fetched_at = _parse_timestamp(payload["fetched_at_utc"], "fetched_at_utc")
    expected_time = _parse_timestamp(expected_fetched_at, "expected fetched_at")
    if fetched_at != expected_time:
        raise ValueError("Netlab acquisition timestamp does not match run timestamp")

    local_file = payload["local_file"]
    if (
        not isinstance(local_file, str)
        or not local_file
        or Path(local_file).name != local_file
        or "/" in local_file
        or "\\" in local_file
        or Path(local_file).suffix.casefold() != ".zip"
    ):
        raise ValueError("Netlab acquisition metadata local filename is invalid")
    source_hash = payload["sha256"]
    if not isinstance(source_hash, str) or len(source_hash) != 64 or any(
        character not in "0123456789abcdef" for character in source_hash
    ):
        raise ValueError("Netlab acquisition metadata source hash is invalid")
    if source_hash != hashlib.sha256(source_data).hexdigest():
        raise ValueError("Netlab acquisition metadata source hash does not match ZIP")

    size_bytes = payload["size_bytes"]
    if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < 1:
        raise ValueError("Netlab acquisition metadata size is invalid")
    if size_bytes != len(source_data):
        raise ValueError("Netlab acquisition metadata size does not match ZIP")
    content_type = payload["content_type"]
    if not isinstance(content_type, str) or content_type.lower() not in _ALLOWED_CONTENT_TYPES:
        raise ValueError("Netlab acquisition metadata content type is not an accepted ZIP type")

    if payload["feed_catalog_date"] != expected_catalog_date:
        raise ValueError("Netlab acquisition metadata feed date does not match ZIP")
    if payload["item_count"] != expected_item_count:
        raise ValueError("Netlab acquisition metadata item count does not match ZIP")
    expected_rates = {key: str(value) for key, value in sorted(expected_currency_rates.items())}
    if payload["currency_rates"] != expected_rates:
        raise ValueError("Netlab acquisition metadata currency rates do not match ZIP")

    max_age = payload["max_feed_age_hours"]
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 24:
        raise ValueError("Netlab acquisition metadata max age is invalid")
    try:
        age_seconds = float(payload["feed_age_seconds"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Netlab acquisition metadata feed age is invalid") from exc
    if not math.isfinite(age_seconds) or age_seconds < -900 or age_seconds > max_age * 3600:
        raise ValueError("Netlab acquisition metadata feed age is outside the contract")
    try:
        actual_rates = payload["currency_rates"]
        if not isinstance(actual_rates, dict):
            raise TypeError("currency_rates must be an object")
        for currency, expected_rate in expected_currency_rates.items():
            if not expected_rate.is_finite():
                raise ValueError("expected Netlab currency rate is not finite")
            if Decimal(str(actual_rates[currency])) != expected_rate:
                raise ValueError("Netlab acquisition metadata currency rate is invalid")
    except (InvalidOperation, KeyError, TypeError) as exc:
        raise ValueError("Netlab acquisition metadata currency rate is invalid") from exc
    return payload


def validate_netlab_properties_acquisition_metadata(
    payload: Any,
    *,
    source_data: bytes,
    expected_fetched_at: str,
    expected_catalog_date: str,
    expected_stats: NetlabPropertiesStats,
) -> dict[str, Any]:
    required = {
        "supplier",
        "feed_kind",
        "source",
        "source_url",
        "fetched_at_utc",
        "local_file",
        "sha256",
        "size_bytes",
        "content_type",
        "http_status",
        "feed_catalog_date",
        "item_count",
        "property_count",
        "observation_count",
        "unknown_property_id_count",
        "unknown_observation_count",
        "credentials_persisted",
        "publication_enabled",
        "production_writes",
        "max_feed_age_hours",
        "feed_age_seconds",
    }
    if not isinstance(payload, dict):
        raise TypeError("Netlab properties acquisition metadata must be a JSON object")
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"Netlab properties acquisition metadata is missing: {', '.join(missing)}")
    if payload["supplier"] != "netlab" or payload["feed_kind"] != "properties":
        raise ValueError("Netlab properties acquisition metadata supplier/feed kind mismatch")
    if payload["source"] != "direct_https" or payload["source_url"] != DEFAULT_PROPERTIES_URL:
        raise ValueError("Netlab properties acquisition metadata source is not allowlisted")
    if payload["http_status"] != 200:
        raise ValueError("Netlab properties acquisition metadata must describe HTTP 200")
    if payload["credentials_persisted"] is not False:
        raise ValueError("Netlab properties acquisition metadata records persisted credentials")
    if payload["publication_enabled"] is not False or payload["production_writes"] != 0:
        raise ValueError("Netlab properties acquisition metadata permits production writes")
    if _parse_timestamp(payload["fetched_at_utc"], "fetched_at_utc") != _parse_timestamp(
        expected_fetched_at, "expected fetched_at"
    ):
        raise ValueError("Netlab properties acquisition timestamp does not match run timestamp")
    local_file = payload["local_file"]
    if (
        not isinstance(local_file, str)
        or not local_file
        or Path(local_file).name != local_file
        or "/" in local_file
        or "\\" in local_file
        or Path(local_file).suffix.casefold() != ".zip"
    ):
        raise ValueError("Netlab properties acquisition metadata local filename is invalid")
    source_hash = payload["sha256"]
    if not isinstance(source_hash, str) or len(source_hash) != 64 or any(
        character not in "0123456789abcdef" for character in source_hash
    ):
        raise ValueError("Netlab properties acquisition metadata source hash is invalid")
    if source_hash != hashlib.sha256(source_data).hexdigest():
        raise ValueError("Netlab properties acquisition metadata source hash does not match ZIP")
    if payload["size_bytes"] != len(source_data):
        raise ValueError("Netlab properties acquisition metadata size does not match ZIP")
    if payload["content_type"].lower() not in _ALLOWED_CONTENT_TYPES:
        raise ValueError("Netlab properties acquisition metadata content type is not an accepted ZIP type")
    if payload["feed_catalog_date"] != expected_catalog_date:
        raise ValueError("Netlab properties acquisition metadata feed date does not match ZIP")
    expected_fields = {
        "item_count": expected_stats.item_count,
        "property_count": expected_stats.property_count,
        "observation_count": expected_stats.observation_count,
        "unknown_property_id_count": expected_stats.unknown_property_id_count,
        "unknown_observation_count": expected_stats.unknown_observation_count,
    }
    if "missing_observation_count" in payload:
        expected_fields["missing_observation_count"] = expected_stats.missing_observation_count
    for field, expected in expected_fields.items():
        if payload[field] != expected:
            raise ValueError(f"Netlab properties acquisition metadata {field} does not match ZIP")
    if payload["max_feed_age_hours"] is not None or payload["feed_age_seconds"] is not None:
        raise ValueError("Netlab properties acquisition metadata has price-feed age fields")
    return payload


def parse_netlab_acquisition_metadata(data: bytes) -> dict[str, Any]:
    import json

    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid Netlab acquisition metadata JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("Netlab acquisition metadata must be a JSON object")
    return payload
