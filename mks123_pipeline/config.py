from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .integrity import read_evidence
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
    rub_per_unit: Decimal | None = None
    source: Literal["base_currency_parity", "supplier_feed"]
    min_rub_per_unit: Decimal | None = Field(default=None, gt=0)
    max_rub_per_unit: Decimal | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_rate_source(self) -> RateConfig:
        if self.source == "supplier_feed":
            if self.rub_per_unit is not None:
                raise ValueError("supplier-feed rate must come from the accepted snapshot")
            if self.min_rub_per_unit is None or self.max_rub_per_unit is None:
                raise ValueError("supplier-feed rate requires explicit min/max bounds")
            if self.min_rub_per_unit > self.max_rub_per_unit:
                raise ValueError("supplier-feed rate minimum exceeds maximum")
            return self
        if self.rub_per_unit is None:
            raise ValueError("fixed exchange rate requires rub_per_unit")
        if self.min_rub_per_unit is not None or self.max_rub_per_unit is not None:
            raise ValueError("fixed exchange rate cannot declare supplier-feed bounds")
        return self


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
        unsupported_currencies = sorted(set(self.exchange_rates) - {"RUB", "RUR", "USD"})
        if unsupported_currencies:
            raise ValueError(
                "approved simple markup supports only RUB/RUR and Netlab supplier-feed USD: "
                + ", ".join(unsupported_currencies)
            )
        if not self.exchange_rates:
            raise ValueError("approved simple markup requires an explicit currency parity")
        for currency, rate in self.exchange_rates.items():
            if currency in {"RUB", "RUR"}:
                if rate.source != "base_currency_parity" or rate.rub_per_unit != Decimal(1):
                    raise ValueError("approved simple markup requires RUB/RUR parity rate 1")
            elif currency == "USD" and rate.source != "supplier_feed":
                raise ValueError("approved USD pricing requires a supplier-feed rate")
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
        supplier_feed_currencies = {
            currency
            for currency, rate in self.pricing.exchange_rates.items()
            if rate.source == "supplier_feed"
        }
        if supplier_feed_currencies and (
            self.supplier.id != "netlab" or supplier_feed_currencies != {"USD"}
        ):
            raise ValueError("supplier-feed FX is approved only for Netlab USD")
        if self.supplier.id == "netlab":
            source = self.supplier.source
            rate = self.pricing.exchange_rates.get("USD")
            if (
                self.supplier.scope.catalog_sku_prefix != "31"
                or source.type != "supplier_xml_zip"
                or source.url != "https://www.netlab.ru/products/pricexml4.zip"
                or source.min_offer_count < 60_000
                or source.max_offer_count > 100_000
                or source.max_response_bytes > 128 * 1024 * 1024
                or set(self.pricing.exchange_rates) != {"USD"}
                or rate is None
                or rate.source != "supplier_feed"
                or rate.min_rub_per_unit != Decimal(40)
                or rate.max_rub_per_unit != Decimal(200)
            ):
                raise ValueError("Netlab acquisition safety contract is fixed and cannot be weakened")
        return self


def load_pilot_config(path: str | Path) -> PilotConfig:
    payload = yaml.safe_load(read_evidence(Path(path)).data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("pilot configuration must be a YAML mapping")
    return PilotConfig.model_validate(payload)


def pricing_context_from_config(
    pricing: PricingConfig,
    *,
    observed_at: str,
    supplier_id: str | None = None,
    supplier_rates: dict[str, Decimal] | None = None,
    source_sha256: str | None = None,
) -> PricingContext:
    rates: dict[str, ExchangeRate] = {}
    for currency, rate in pricing.exchange_rates.items():
        if rate.source == "supplier_feed":
            if supplier_id != "netlab" or supplier_rates is None or source_sha256 is None:
                raise ValueError("supplier-feed rate requires Netlab snapshot identity")
            value = supplier_rates.get(currency)
            if value is None:
                raise ValueError(f"accepted supplier snapshot does not declare {currency} rate")
            assert rate.min_rub_per_unit is not None and rate.max_rub_per_unit is not None
            if value < rate.min_rub_per_unit or value > rate.max_rub_per_unit:
                raise ValueError(f"supplier-feed {currency} rate is outside approved bounds")
            rates[currency] = ExchangeRate(
                currency=currency,
                rub_per_unit=value,
                source="supplier_feed",
                observed_at=observed_at,
                approved=True,
                supplier_id=supplier_id,
                source_sha256=source_sha256,
            )
        else:
            assert rate.rub_per_unit is not None
            rates[currency] = ExchangeRate(
                currency=currency,
                rub_per_unit=rate.rub_per_unit,
                source=rate.source,
                observed_at=observed_at,
                approved=True,
            )
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
