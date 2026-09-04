from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .matcher import MatchRecord
from .models import SupplierItem


class ExchangeRate(BaseModel):
    currency: str
    rub_per_unit: Decimal
    source: str
    observed_at: str


class MarkupRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    version: str
    approved: bool = False
    multiplier: Decimal


class PricingContext(BaseModel):
    rates: dict[str, ExchangeRate]
    rule: MarkupRule | None
    max_delta_pct: Decimal = Decimal("0.50")
    vat_basis: Literal["included", "excluded", "unknown"] = "unknown"


class PriceProposal(BaseModel):
    product_id: int | None
    supplier_item_id: str
    current_price: Decimal
    source_price: Decimal
    source_currency: str
    exchange_rate: Decimal | None = None
    exchange_rate_source: str | None = None
    markup_rule_id: str | None = None
    markup_rule_version: str | None = None
    cost_rub: Decimal | None = None
    calculated_price: Decimal | None = None
    proposed_price: Decimal | None = None
    delta_abs: Decimal | None = None
    delta_pct: Decimal | None = None
    match_confidence: Decimal
    status: str
    warnings: list[str] = Field(default_factory=list)


def _blocked(item: SupplierItem, match: MatchRecord, current_price: Decimal, status: str, warning: str) -> PriceProposal:
    return PriceProposal(
        product_id=match.catalog_product_id,
        supplier_item_id=item.supplier_item_id,
        current_price=current_price,
        source_price=item.source_price,
        source_currency=item.currency,
        match_confidence=match.confidence,
        status=status,
        warnings=[warning],
    )


def build_proposal(item: SupplierItem, match: MatchRecord, current_price: Decimal, context: PricingContext) -> PriceProposal:
    if match.status != "exact" or match.catalog_product_id is None:
        return _blocked(item, match, current_price, "blocked_match", "match_not_exact")
    if item.source_price <= 0:
        return _blocked(item, match, current_price, "blocked_source_price", "nonpositive_source_price")
    if item.currency not in {"RUB", "RUR"}:
        return _blocked(item, match, current_price, "blocked_currency", "currency_not_approved")
    rate = context.rates.get(item.currency)
    if rate is None or rate.rub_per_unit <= 0:
        return _blocked(item, match, current_price, "blocked_currency", "missing_or_invalid_exchange_rate")
    if rate.rub_per_unit != Decimal(1):
        return _blocked(item, match, current_price, "blocked_currency", "currency_parity_not_approved")
    if context.vat_basis == "unknown":
        return _blocked(item, match, current_price, "blocked_vat_basis", "vat_basis_unknown")
    if context.rule is None or not context.rule.approved:
        return _blocked(item, match, current_price, "blocked_missing_markup", "markup_policy_not_approved")
    rule = context.rule
    if rule.multiplier <= 0:
        return _blocked(item, match, current_price, "blocked_markup", "invalid_markup_rule")
    cost = item.source_price * rate.rub_per_unit
    calculated = cost * rule.multiplier
    proposed = calculated
    delta_abs = proposed - current_price
    delta_pct = delta_abs / current_price if current_price > 0 else None
    warnings: list[str] = []
    status = "ready_for_review"
    if delta_pct is None:
        status = "blocked_current_price"
        warnings.append("nonpositive_current_price")
    elif abs(delta_pct) > context.max_delta_pct:
        status = "blocked_delta"
        warnings.append("delta_exceeds_limit")
    return PriceProposal(
        product_id=match.catalog_product_id,
        supplier_item_id=item.supplier_item_id,
        current_price=current_price,
        source_price=item.source_price,
        source_currency=item.currency,
        exchange_rate=rate.rub_per_unit,
        exchange_rate_source=rate.source,
        markup_rule_id=rule.id,
        markup_rule_version=rule.version,
        cost_rub=cost,
        calculated_price=calculated,
        proposed_price=proposed,
        delta_abs=delta_abs,
        delta_pct=delta_pct,
        match_confidence=match.confidence,
        status=status,
        warnings=warnings,
    )
