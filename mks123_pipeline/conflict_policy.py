from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

_INTERNAL_TOKENS = (
    "сайт производителя",
    "сервисный центр",
    "горячая линия",
    "логистика",
    "предупрежд",
    "основные характеристики",
    "потребительские свойства",
    "внешние источники",
    "технические данные",
)
_DOCUMENTATION_TOKENS = ("драйвер", "инструкция", "документац")
_DESCRIPTION_TOKENS = ("описание",)
_COMPATIBILITY_TOKENS = ("совместим", "артикулы всех совместимых")
_PHYSICAL_TOKENS = ("габарит", "ширина", "высота", "глубина", "вес", "размер", "вентилятор", "температура", "влажность")
_ALLOWED_STATES = {"source_backed", "placeholder", "unknown", "internal"}
_ALLOWED_COMPARISON_STATUSES = {"same", "conflict", "clone_only", "source_only"}
_MIN_TOLERANCE = Decimal("0.01")
_MAX_TOLERANCE = Decimal("0.03")


@dataclass(frozen=True)
class ConflictDecision:
    field: str
    action: str
    reason: str
    normalized_value: str | None = None
    delta_percent: Decimal | None = None
    human_review: bool = True
    evidence_required: bool = True


@dataclass(frozen=True)
class PreviewClassification:
    entries: tuple[dict[str, Any], ...]
    summary: dict[str, Any]
    grouped_skus: dict[str, set[str]]


def validate_tolerance(tolerance: Decimal) -> Decimal:
    try:
        value = tolerance if isinstance(tolerance, Decimal) else Decimal(str(tolerance))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("tolerance must be a Decimal between 0.01 and 0.03") from exc
    if not value.is_finite() or not (_MIN_TOLERANCE <= value <= _MAX_TOLERANCE):
        raise ValueError("tolerance must be a finite Decimal between 0.01 and 0.03")
    return value


def _text(value: object) -> str:
    return str(value or "").strip()


def _field_lower(field: str) -> str:
    return field.strip().lower()


def _materialize_rows(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return list(rows)


def _schema_issue(rows: Iterable[Mapping[str, Any]]) -> bool:
    for row in rows:
        if not isinstance(row, Mapping):
            return True
        if not isinstance(row.get("value_state"), str) or row.get("value_state") not in _ALLOWED_STATES:
            return True
        if "value" not in row or row.get("value") is None:
            return True
        if not isinstance(row.get("customer_visible"), bool):
            return True
        if not isinstance(row.get("name"), str):
            return True
        value = row.get("value")
        if isinstance(value, float) and not math.isfinite(value):
            return True
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            return True
    return False


def _visible_source_rows(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [
        row
        for row in rows
        if row.get("value_state") == "source_backed" and row.get("customer_visible") is True
    ]


def _parse_weight(value: object, field: str, row_name: str) -> Decimal | None:
    text = _text(value).lower().replace(",", ".")
    field_text = f"{_field_lower(field)} {_field_lower(row_name)}"
    if "вес" not in field_text:
        return None
    match = re.fullmatch(r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(кг|kg|килограмм(?:а|ов)?|г|g|грамм(?:а|ов)?)?\s*", text)
    if match is None:
        return None
    try:
        number = Decimal(match.group(1))
    except InvalidOperation:
        return None
    if number < 0 or not number.is_finite():
        return None
    unit = match.group(2)
    field_expects_kg = bool(re.search(r"(?:^|\s)(?:кг|kg|килограмм(?:а|ов)?)(?:$|\s)", field_text))
    field_expects_g = bool(re.search(r"(?:^|\s)(?:г|g|грамм(?:а|ов)?)(?:\.|$|\s)", field_text))
    if field_expects_kg and field_expects_g:
        return None
    if unit in {"кг", "kg", "килограмм", "килограмма", "килограммов"}:
        return number * Decimal(1000)
    if unit in {"г", "g", "грамм", "грамма", "граммов"}:
        return number
    if field_expects_kg:
        return number * Decimal(1000)
    if field_expects_g:
        return number
    return None


def _weight_object(field: str, row_name: str, value: object) -> str | None:
    field_text = _field_lower(field)
    row_text = _field_lower(row_name)
    value_text = _text(value).lower()
    texts = (field_text, row_text, value_text)
    explicit_objects: set[str] = set()
    for text in (row_text, value_text):
        if "без товара" in text:
            explicit_objects.add("упаковка_без_товара")
        if "товар в упаков" in text:
            explicit_objects.add("товар_в_упаковке")
        if "товар с упаков" in text or "товара с упаков" in text:
            explicit_objects.add("товар_с_упаковкой")
    field_markers = {token for token in ("нетто", "брутто", "упаков") if token in field_text}
    row_markers = {token for token in ("нетто", "брутто", "упаков") if token in row_text}
    if len(explicit_objects) > 1:
        return None
    explicit = next(iter(explicit_objects), None)
    if explicit is not None:
        if "нетто" in field_markers or "брутто" in field_markers:
            return None
        return explicit
    if field_markers and row_markers and field_markers != row_markers:
        return None
    markers = set(field_markers) | set(row_markers)
    if "упаков" in row_text and "товар" in row_text:
        return None
    if len(markers) != 1:
        return None
    marker = next(iter(markers))
    if marker == "упаков":
        return None
    if any("товар" in text and "упаков" in text for text in texts):
        return None
    return marker


def _safe_format(field: str, clone_value: str, netlab_value: str) -> str | None:
    field_lower = _field_lower(field)
    if field_lower not in {"версия", "версия usb", "цвет", "цвет чернил", "цвет товара", "описание расцветки"}:
        return None
    if field_lower in {"версия", "версия usb"}:
        clone_display = clone_value.strip()
        netlab_display = netlab_value.strip()
        if (clone_display == "2" and netlab_display == "2.0") or (clone_display == "2.0" and netlab_display == "2"):
            return "2.0"
        return None
    if field_lower in {"цвет", "цвет чернил", "цвет товара", "описание расцветки"}:
        def color_token(value: str) -> str | None:
            display = re.sub(r"\s+", " ", value.strip().casefold().replace("ё", "е"))
            if display in {"черный", "black", "черный (black)"}:
                return "black"
            return None

        if color_token(clone_value) == color_token(netlab_value) == "black":
            return "Чёрный"
        return None
    return None


def _is_internal_or_unknown(rows: Iterable[Mapping[str, Any]], field: str) -> bool:
    field_lower = _field_lower(field)
    rows = list(rows)
    visible = any(row.get("value_state") == "source_backed" and row.get("customer_visible") is True for row in rows)
    if any(token in field_lower for token in _INTERNAL_TOKENS):
        return not visible
    return bool(rows) and not visible


def _grouped_action(field: str) -> tuple[str, str] | None:
    field_lower = _field_lower(field)
    if any(token in field_lower for token in _DOCUMENTATION_TOKENS):
        return "grouped_documentation_review", "Документ или ссылка требуют проверки модели, ревизии и доступности файла."
    if any(token in field_lower for token in _COMPATIBILITY_TOKENS):
        return "grouped_compatibility_review", "Совместимость остаётся evidence-only; relation автоматически не создаётся."
    if any(token in field_lower for token in _DESCRIPTION_TOKENS):
        return "grouped_description_review", "Описание проверяется группой по source-backed полям; шаблонный текст не публикуется."
    if field_lower in {"тип оборудования", "страна"}:
        return "grouped_dictionary_review", "Нужен утверждённый словарь поля, а не per-SKU ручное решение."
    if any(token in field_lower for token in _PHYSICAL_TOKENS):
        return "grouped_manufacturer_or_packaging_review", "Проверить товар/упаковку, ревизию и методику измерения."
    return None


def _exception(field: str, reason: str) -> ConflictDecision:
    return ConflictDecision(field=field, action="item_exception_review", reason=reason, human_review=True, evidence_required=True)


def classify_conflict(
    field: str,
    clone_rows: Iterable[Mapping[str, Any]],
    netlab_rows: Iterable[Mapping[str, Any]],
    *,
    tolerance: Decimal = Decimal("0.03"),
) -> ConflictDecision:
    tolerance = validate_tolerance(tolerance)
    clone_rows = _materialize_rows(clone_rows)
    netlab_rows = _materialize_rows(netlab_rows)
    all_rows = [*clone_rows, *netlab_rows]
    if _schema_issue(all_rows):
        return _exception(field, "Input row schema is incomplete or contains an unsupported value_state/customer_visible type.")
    if _is_internal_or_unknown(all_rows, field):
        return ConflictDecision(
            field=field,
            action="auto_hide_internal_or_placeholder",
            reason="Internal, placeholder or unknown data stays in audit and leaves the human queue.",
            human_review=False,
            evidence_required=False,
        )

    clone_visible = _visible_source_rows(clone_rows)
    netlab_visible = _visible_source_rows(netlab_rows)
    grouped = _grouped_action(field)
    if (clone_visible or netlab_visible) and any(row.get("value_state") != "source_backed" for row in all_rows):
        if grouped is not None:
            action, reason = grouped
            return ConflictDecision(field=field, action=action, reason=reason, human_review=True, evidence_required=True)
        return _exception(field, "Visible source-backed values are mixed with placeholder/unknown/internal rows.")
    if grouped is not None and grouped[0] != "grouped_manufacturer_or_packaging_review":
        action, reason = grouped
        return ConflictDecision(field=field, action=action, reason=reason, human_review=True, evidence_required=True)
    if not clone_visible or not netlab_visible:
        if grouped is not None:
            action, reason = grouped
            return ConflictDecision(field=field, action=action, reason=reason, human_review=True, evidence_required=True)
        return _exception(field, "A visible source-backed value is missing on one side.")
    if len(clone_visible) != 1 or len(netlab_visible) != 1:
        return _exception(field, "Multiple visible source-backed values require an explicit field-level decision.")

    clone_row = clone_visible[0]
    netlab_row = netlab_visible[0]
    formatted = _safe_format(field, _text(clone_row.get("value")), _text(netlab_row.get("value")))
    if formatted is not None:
        return ConflictDecision(
            field=field,
            action="normalization_candidate",
            reason="Only an approved display/format representation differs; original values remain in provenance.",
            normalized_value=formatted,
            human_review=False,
            evidence_required=False,
        )

    field_lower = _field_lower(field)
    if "вес" in field_lower:
        clone_object = _weight_object(field, _text(clone_row.get("name")), clone_row.get("value"))
        netlab_object = _weight_object(field, _text(netlab_row.get("name")), netlab_row.get("value"))
        current = _parse_weight(clone_row.get("value"), field, _text(clone_row.get("name")))
        candidate = _parse_weight(netlab_row.get("value"), field, _text(netlab_row.get("name")))
        if clone_object is None or clone_object != netlab_object or current is None or candidate is None:
            return ConflictDecision(
                field=field,
                action="grouped_manufacturer_or_packaging_review",
                reason="Weight object, units or value shape are not safely equivalent.",
                human_review=True,
                evidence_required=True,
            )
        delta = abs(candidate - current) / abs(current) if current != 0 else None
        if delta is not None and delta <= tolerance:
            return ConflictDecision(
                field=field,
                action="within_tolerance_preserve_current",
                reason="Same weight field is within the configured tolerance; preserve current and record the delta.",
                delta_percent=delta * Decimal(100),
                human_review=False,
                evidence_required=False,
            )

    if grouped is not None:
        action, reason = grouped
        return ConflictDecision(field=field, action=action, reason=reason, human_review=True, evidence_required=True)
    return _exception(field, "No safe field policy exists; keep current and review the exception.")


def classify_preview(items: Iterable[Mapping[str, Any]], *, tolerance: Decimal = Decimal("0.03")) -> PreviewClassification:
    tolerance = validate_tolerance(tolerance)
    output: list[dict[str, Any]] = []
    action_counts: Counter[str] = Counter()
    item_actions: defaultdict[str, set[str]] = defaultdict(set)
    grouped_skus: defaultdict[str, set[str]] = defaultdict(set)
    item_count = 0
    for item in items:
        if not isinstance(item, Mapping) or not isinstance(item.get("characteristic_comparison"), list):
            raise TypeError("each preview item must contain a characteristic_comparison list")
        sku = item.get("catalog_sku")
        if isinstance(sku, bool) or not isinstance(sku, (str, int)) or not str(sku).strip():
            raise TypeError("each preview item must contain a non-empty catalog_sku")
        for conflict in item["characteristic_comparison"]:
            if not isinstance(conflict, Mapping):
                raise TypeError("each characteristic comparison must be an object")
            if not isinstance(conflict.get("name"), str):
                raise TypeError("each characteristic comparison must contain a string name")
            if conflict.get("status") not in _ALLOWED_COMPARISON_STATUSES:
                raise ValueError("each characteristic comparison must contain a supported status")
            if "clone" not in conflict or "netlab" not in conflict:
                raise TypeError("comparison clone/netlab fields are required")
            clone_side = conflict["clone"]
            netlab_side = conflict["netlab"]
            if not isinstance(clone_side, list) or not isinstance(netlab_side, list):
                raise TypeError("comparison clone/netlab values must be lists")
            status = conflict.get("status")
            if status in {"same", "conflict"} and (not clone_side or not netlab_side):
                raise ValueError("same/conflict comparisons require both clone and netlab values")
            if status == "clone_only" and (not clone_side or netlab_side):
                raise ValueError("clone_only comparison requires only clone values")
            if status == "source_only" and (not netlab_side or clone_side):
                raise ValueError("source_only comparison requires only netlab values")
            for side in (clone_side, netlab_side):
                if _schema_issue(side):
                    raise TypeError("comparison rows do not satisfy the field schema")
        item_count += 1
        sku_text = str(sku)
        for conflict in item["characteristic_comparison"]:
            if conflict.get("status") != "conflict":
                continue
            decision = classify_conflict(
                str(conflict.get("name", "")),
                conflict.get("clone", []),
                conflict.get("netlab", []),
                tolerance=tolerance,
            )
            action_counts[decision.action] += 1
            item_actions[sku_text].add(decision.action)
            if decision.action.startswith("grouped_") or decision.action == "normalization_candidate":
                grouped_skus[decision.action].add(sku_text)
            output.append(
                {
                    "catalog_sku": sku_text,
                    "name": item.get("name"),
                    "field": decision.field,
                    "action": decision.action,
                    "reason": decision.reason,
                    "normalized_value": decision.normalized_value,
                    "delta_percent": str(decision.delta_percent) if decision.delta_percent is not None else None,
                    "human_review": decision.human_review,
                    "evidence_required": decision.evidence_required,
                    "clone": conflict.get("clone", []),
                    "netlab": conflict.get("netlab", []),
                }
            )
    non_review_actions = {"auto_hide_internal_or_placeholder", "normalization_candidate", "within_tolerance_preserve_current"}
    summary = {
        "items": item_count,
        "conflict_entries": len(output),
        "actions": dict(action_counts),
        "items_with_any_review_after_filter": sum(
            any(action not in non_review_actions for action in actions)
            for actions in item_actions.values()
        ),
        "grouped_sku_counts": {action: len(skus) for action, skus in grouped_skus.items()},
        "interpretation": "classification only; no value replacement or approval",
    }
    return PreviewClassification(tuple(output), summary, dict(grouped_skus))
