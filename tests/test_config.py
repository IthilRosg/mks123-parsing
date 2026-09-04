from decimal import Decimal
from pathlib import Path

import pytest

from mks123_pipeline.config import load_pilot_config, pricing_context_from_config


def test_load_pilot_config_validates_read_only_limits(tmp_path: Path) -> None:
    path = tmp_path / "pilot.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1500, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    config = load_pilot_config(path)
    assert config.supplier.source.min_offer_count == 1500
    assert config.pricing.vat_basis == "unknown"
    assert config.publication.enabled is False


def test_load_pilot_config_rejects_publication_enabled(tmp_path: Path) -> None:
    path = tmp_path / "pilot.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1500, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
publication: {enabled: true}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="publication must remain disabled"):
        load_pilot_config(path)


def test_registry_enrichment_defaults_to_optional_non_blocking(tmp_path: Path) -> None:
    path = tmp_path / "pilot.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1500, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    config = load_pilot_config(path)
    assert config.registry_enrichment.enabled is False
    assert config.registry_enrichment.required_for_catalog_ingestion is False
    assert config.registry_enrichment.scope == "PP-878"
    assert config.registry_enrichment.primary_evidence_required is True


def test_registry_enrichment_cannot_block_catalog_ingestion(tmp_path: Path) -> None:
    path = tmp_path / "pilot.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1500, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
registry_enrichment:
  enabled: true
  required_for_catalog_ingestion: true
  scope: PP-878
  primary_evidence_required: true
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not block catalog ingestion"):
        load_pilot_config(path)


def test_registry_enrichment_requires_primary_evidence(tmp_path: Path) -> None:
    path = tmp_path / "pilot.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1500, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
registry_enrichment:
  enabled: true
  required_for_catalog_ingestion: false
  scope: PP-878
  primary_evidence_required: false
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must require primary evidence"):
        load_pilot_config(path)


def test_load_pilot_config_accepts_non_electrozone_supplier_scope(tmp_path: Path) -> None:
    path = tmp_path / "supplier-b.yaml"
    path.write_text(
        """supplier:
  id: supplier-b
  scope: {catalog_sku_prefix: "31"}
  source: {type: structured_feed, min_offer_count: 1, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    config = load_pilot_config(path)
    assert config.supplier.id == "supplier-b"
    assert config.supplier.scope.catalog_sku_prefix == "31"
    assert config.registry_enrichment.required_for_catalog_ingestion is False


def test_load_pilot_config_rejects_empty_supplier_sku_prefix(tmp_path: Path) -> None:
    path = tmp_path / "empty-prefix.yaml"
    path.write_text(
        """supplier:
  id: supplier-b
  scope: {catalog_sku_prefix: ""}
  source: {type: structured_feed, min_offer_count: 1, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  vat_basis: unknown
  vat_policy_approved: false
  markup_policy: {approved: false, rules: []}
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_pilot_config(path)


def test_pricing_context_uses_approved_simple_supplier_price_plus_ten_policy(tmp_path: Path) -> None:
    path = tmp_path / "approved-pricing.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  base_currency: RUB
  vat_basis: included
  vat_policy_approved: true
  exchange_rates:
    RUR: {rub_per_unit: 1, source: base_currency_parity}
  markup_policy:
    approved: true
    rules:
      - {id: supplier-price-plus-10, version: "2026-09-03", multiplier: 1.10}
  rounding: {mode: exact, increment_rub: null}
  safety:
    reject_nonpositive_source_price: true
    reject_unknown_currency: true
    reject_unknown_vat_basis: true
    reject_non_exact_match: true
    reject_missing_markup: true
    max_delta_pct: 0.50
    minimum_margin_pct: null
publication: {enabled: false}
""",
        encoding="utf-8",
    )

    pricing = pricing_context_from_config(load_pilot_config(path).pricing, observed_at="2026-09-03T10:00:00Z")

    assert pricing.vat_basis == "included"
    assert pricing.rates["RUR"].rub_per_unit == 1
    assert pricing.rule is not None
    assert pricing.rule.id == "supplier-price-plus-10"
    assert pricing.rule.version == "2026-09-03"
    assert pricing.rule.multiplier == Decimal("1.10")
    assert "rounding_increment" not in pricing.rule.model_dump()


def test_approved_pricing_rejects_non_parity_rur_rate(tmp_path: Path) -> None:
    path = tmp_path / "invalid-parity.yaml"
    path.write_text(
        """supplier:
  id: electrozone
  scope: {catalog_sku_prefix: "11"}
  source: {min_offer_count: 1, max_offer_count: 100000, max_response_bytes: 67108864}
pricing:
  base_currency: RUB
  vat_basis: included
  vat_policy_approved: true
  exchange_rates:
    RUR: {rub_per_unit: 2, source: invalid}
  markup_policy:
    approved: true
    rules:
      - {id: supplier-price-plus-10, version: "2026-09-03", multiplier: 1.10}
  rounding: {mode: exact, increment_rub: null}
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="parity"):
        load_pilot_config(path)


@pytest.mark.parametrize("config_name", ["pilot.yaml", "netlab.yaml", "vetcom.yaml"])
def test_all_supplier_configs_enable_the_same_read_only_simple_pricing_policy(config_name: str) -> None:
    project = Path(__file__).parents[1]
    config = load_pilot_config(project / "config" / config_name)
    pricing = pricing_context_from_config(config.pricing, observed_at="2026-09-03T10:00:00Z")

    assert config.publication.enabled is False
    assert pricing.vat_basis == "included"
    assert pricing.rule is not None
    assert pricing.rule.multiplier == Decimal("1.10")
    assert "rounding_increment" not in pricing.rule.model_dump()
