from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .pricing import ExchangeRate, MarkupRule, PricingContext


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SupplierScope(StrictModel):
    catalog_sku_prefix: str = Field(min_length=1, max_length=32)


class SourceConfig(StrictModel):
    type: str | None = None
    url: str | None = None
    credential_ref: str | None = None
    raw_retention_days: int | None = Field(default=None, ge=1)
    min_offer_count: int = Field(ge=1)
    max_offer_count: int = Field(ge=1)
    max_response_bytes: int = Field(ge=1024)

    @model_validator(mode="after")
    def validate_limits(self) -> SourceConfig:
        if self.min_offer_count > self.max_offer_count:
            raise ValueError("min_offer_count must not exceed max_offer_count")
        return self


class SupplierConfig(StrictModel):
    id: str = Field(min_length=1, max_length=64)
    scope: SupplierScope
    source: SourceConfig


class FuzzyNameConfig(StrictModel):
    enabled: bool


class MatchingConfig(StrictModel):
    order: list[str]
    auto_price_eligible_statuses: list[str]
    fuzzy_name: FuzzyNameConfig


class RateConfig(StrictModel):
    rub_per_unit: float
    source: str


class MarkupRuleConfig(StrictModel):
    id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    multiplier: Decimal = Field(gt=0)


class MarkupPolicyConfig(StrictModel):
    approved: bool
    rules: list[MarkupRuleConfig]


class RoundingConfig(StrictModel):
    mode: str
    increment_rub: float | None


class PricingSafetyConfig(StrictModel):
    reject_nonpositive_source_price: bool
    reject_unknown_currency: bool
    reject_unknown_vat_basis: bool
    reject_non_exact_match: bool
    reject_missing_markup: bool
    max_delta_pct: float
    minimum_margin_pct: float | None


class PricingConfig(StrictModel):
    base_currency: str = "RUB"
    vat_basis: Literal["included", "excluded", "unknown"]
    vat_policy_approved: bool
    exchange_rates: dict[str, RateConfig] = Field(default_factory=dict)
    markup_policy: MarkupPolicyConfig
    rounding: RoundingConfig | None = None
    safety: PricingSafetyConfig | None = None

    @model_validator(mode="after")
    def validate_policy_approval(self) -> PricingConfig:
        if self.vat_policy_approved and self.vat_basis == "unknown":
            raise ValueError("approved VAT policy cannot have unknown basis")
        if not self.markup_policy.approved:
            return self
        if not self.vat_policy_approved or self.vat_basis != "included":
            raise ValueError("approved simple markup requires approved VAT-included basis")
        if self.base_currency != "RUB":
            raise ValueError("approved simple markup requires RUB base currency")
        unsupported_currencies = sorted(set(self.exchange_rates) - {"RUB", "RUR"})
        if unsupported_currencies:
            raise ValueError(
                "approved simple markup supports only RUB/RUR currencies: "
                + ", ".join(unsupported_currencies)
            )
        if not self.exchange_rates:
            raise ValueError("approved simple markup requires an explicit currency parity")
        if any(Decimal(str(rate.rub_per_unit)) != Decimal(1) for rate in self.exchange_rates.values()):
            raise ValueError("approved simple markup requires RUB/RUR parity rate 1")
        if len(self.markup_policy.rules) != 1:
            raise ValueError("approved simple markup policy requires exactly one rule")
        if self.markup_policy.rules[0].multiplier != Decimal("1.10"):
            raise ValueError("approved simple markup multiplier must be 1.10")
        if self.rounding is not None and (self.rounding.mode != "exact" or self.rounding.increment_rub is not None):
            raise ValueError("approved simple markup must use exact rounding with no increment")
        return self


class MissingProductPolicy(StrictModel):
    action: str
    consecutive_missing_runs: int = Field(ge=1)


class StockConfig(StrictModel):
    source_field: str
    missing_product_policy: MissingProductPolicy


class PublicationConfig(StrictModel):
    enabled: bool
    require_preview_approval: bool = True
    require_backup: bool = True
    require_three_readbacks: bool = True
    rollback_required: bool = True


class RegistryEnrichmentConfig(StrictModel):
    enabled: bool = False
    required_for_catalog_ingestion: bool = False
    scope: Literal["PP-878"] = "PP-878"
    primary_evidence_required: bool = True
    category_name: str = "Реестровое оборудование"

    @model_validator(mode="after")
    def validate_non_blocking(self) -> RegistryEnrichmentConfig:
        if self.required_for_catalog_ingestion:
            raise ValueError("registry enrichment must not block catalog ingestion")
        if not self.primary_evidence_required:
            raise ValueError("registry enrichment must require primary evidence")
        return self


class PilotConfig(StrictModel):
    supplier: SupplierConfig
    matching: MatchingConfig | None = None
    pricing: PricingConfig
    stock: StockConfig | None = None
    registry_enrichment: RegistryEnrichmentConfig = Field(default_factory=RegistryEnrichmentConfig)
    publication: PublicationConfig

    @model_validator(mode="after")
    def enforce_read_only_pilot(self) -> PilotConfig:
        if self.publication.enabled:
            raise ValueError("publication must remain disabled in the read-only pilot")
        return self


def load_pilot_config(path: str | Path) -> PilotConfig:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("pilot configuration must be a YAML mapping")
    return PilotConfig.model_validate(payload)


def pricing_context_from_config(pricing: PricingConfig, *, observed_at: str) -> PricingContext:
    rates = {
        currency: ExchangeRate(
            currency=currency,
            rub_per_unit=Decimal(str(rate.rub_per_unit)),
            source=rate.source,
            observed_at=observed_at,
        )
        for currency, rate in pricing.exchange_rates.items()
    }
    rule = None
    if pricing.markup_policy.approved:
        configured_rule = pricing.markup_policy.rules[0]
        rule = MarkupRule(
            id=configured_rule.id,
            version=configured_rule.version,
            approved=True,
            multiplier=configured_rule.multiplier,
        )
    max_delta_pct = Decimal(str(pricing.safety.max_delta_pct)) if pricing.safety is not None else Decimal("0.50")
    return PricingContext(
        rates=rates,
        rule=rule,
        max_delta_pct=max_delta_pct,
        vat_basis=pricing.vat_basis,
    )
