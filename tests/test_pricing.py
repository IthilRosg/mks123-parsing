from decimal import Decimal

import pytest

from mks123_pipeline.matcher import MatchRecord
from mks123_pipeline.models import SupplierItem
from mks123_pipeline.pricing import (
    ExchangeRate,
    MarkupRule,
    PricingContext,
    build_proposal,
)


def item(price: str = "100") -> SupplierItem:
    return SupplierItem(
        supplier_item_id="1", supplier_sku="1", catalog_sku="111",
        name="Item", source_price=Decimal(price), currency="RUR", available=True,
        fetched_at="2026-09-01T00:00:00Z", raw_hash="a" * 64,
    )


def exact_match() -> MatchRecord:
    return MatchRecord(
        supplier_item_id="1", catalog_sku="111", catalog_product_id=7,
        status="exact", confidence=Decimal(1), matched_by="sku",
    )


def test_simple_policy_applies_ten_percent_without_extra_adjustments_or_rounding() -> None:
    context = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-03")},
        rule=MarkupRule(
            id="supplier-price-plus-10",
            version="2026-09-03",
            approved=True,
            multiplier=Decimal("1.10"),
        ),
        max_delta_pct=Decimal("1.00"),
        vat_basis="included",
    )
    proposal = build_proposal(item("100.55"), exact_match(), current_price=Decimal(100), context=context)
    assert proposal.cost_rub == Decimal("100.55")
    assert proposal.calculated_price == Decimal("110.6050")
    assert proposal.proposed_price == Decimal("110.6050")
    assert proposal.status == "ready_for_review"


def test_simple_policy_rejects_extra_price_adjustment_fields() -> None:
    with pytest.raises(ValueError, match="rounding_increment"):
        MarkupRule(
            id="supplier-price-plus-10",
            version="2026-09-03",
            approved=True,
            multiplier=Decimal("1.10"),
            rounding_increment=Decimal(1),
        )


def test_missing_markup_rule_blocks_proposal_without_inventing_price() -> None:
    context = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-01")},
        rule=None,
        vat_basis="included",
    )
    proposal = build_proposal(item(), exact_match(), current_price=Decimal(125), context=context)
    assert proposal.status == "blocked_missing_markup"
    assert proposal.proposed_price is None


def test_conflicting_match_blocks_proposal() -> None:
    match = exact_match().model_copy(update={"status": "conflict"})
    context = PricingContext(rates={}, rule=None)
    proposal = build_proposal(item(), match, current_price=Decimal(125), context=context)
    assert proposal.status == "blocked_match"


def test_unknown_vat_basis_blocks_even_with_a_markup_rule() -> None:
    context = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-01")},
        rule=MarkupRule(id="pilot", version="draft", multiplier=Decimal("1.20")),
    )
    proposal = build_proposal(item(), exact_match(), current_price=Decimal(125), context=context)
    assert proposal.status == "blocked_vat_basis"
    assert proposal.proposed_price is None
    assert proposal.warnings == ["vat_basis_unknown"]


def test_unapproved_markup_rule_is_blocked_at_pricing_boundary() -> None:
    context = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-01")},
        rule=MarkupRule(id="draft", version="draft-1", approved=False, multiplier=Decimal("1.20")),
        vat_basis="included",
    )
    proposal = build_proposal(item(), exact_match(), current_price=Decimal(125), context=context)
    assert proposal.status == "blocked_missing_markup"
    assert proposal.proposed_price is None
    assert proposal.warnings == ["markup_policy_not_approved"]


def test_delta_limit_uses_unrounded_ratio() -> None:
    context = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-03")},
        rule=MarkupRule(id="supplier-price-plus-10", version="2026-09-03", approved=True, multiplier=Decimal("1.10")),
        max_delta_pct=Decimal("0.10"),
        vat_basis="included",
    )
    proposal = build_proposal(item("100.005"), exact_match(), current_price=Decimal(100), context=context)
    assert proposal.status == "blocked_delta"
    assert proposal.delta_pct is not None
    assert proposal.delta_pct > Decimal("0.10")


def test_non_rub_price_is_blocked_without_fx_policy() -> None:
    context = PricingContext(
        rates={"USD": ExchangeRate(currency="USD", rub_per_unit=Decimal(2), source="unapproved", observed_at="2026-09-03")},
        rule=MarkupRule(id="supplier-price-plus-10", version="2026-09-03", approved=True, multiplier=Decimal("1.10")),
        vat_basis="included",
    )
    proposal = build_proposal(item().model_copy(update={"currency": "USD"}), exact_match(), current_price=Decimal(125), context=context)
    assert proposal.status == "blocked_currency"
    assert proposal.proposed_price is None
    assert proposal.warnings == ["currency_not_approved"]


def test_non_netlab_supplier_cannot_use_supplier_feed_fx_primitive() -> None:
    context = PricingContext(
        rates={
            "USD": ExchangeRate(
                currency="USD",
                rub_per_unit=Decimal("86.89"),
                source="supplier_feed",
                observed_at="2026-09-04 09:04",
                approved=True,
                supplier_id="electrozone",
                source_sha256="b" * 64,
            )
        },
        rule=MarkupRule(
            id="supplier-price-plus-10",
            version="2026-09-03",
            approved=True,
            multiplier=Decimal("1.10"),
        ),
        vat_basis="included",
    )
    electrozone_item = item("270").model_copy(update={"currency": "USD"})

    proposal = build_proposal(
        electrozone_item,
        exact_match(),
        current_price=Decimal(25000),
        context=context,
    )

    assert proposal.status == "blocked_currency"
    assert proposal.proposed_price is None
    assert proposal.warnings == ["currency_not_approved"]


def test_netlab_usd_uses_approved_rate_bound_to_supplier_snapshot() -> None:
    source_sha256 = "b" * 64
    context = PricingContext(
        rates={
            "USD": ExchangeRate(
                currency="USD",
                rub_per_unit=Decimal("86.89"),
                source="supplier_feed",
                observed_at="2026-09-04 09:04",
                approved=True,
                supplier_id="netlab",
                source_sha256=source_sha256,
            )
        },
        rule=MarkupRule(
            id="supplier-price-plus-10",
            version="2026-09-03",
            approved=True,
            multiplier=Decimal("1.10"),
        ),
        vat_basis="included",
    )
    netlab_item = item("270").model_copy(update={"supplier": "netlab", "currency": "USD"})

    proposal = build_proposal(
        netlab_item,
        exact_match(),
        current_price=Decimal(25000),
        context=context,
    )

    assert proposal.cost_rub == Decimal("23460.30")
    assert proposal.calculated_price == Decimal("25806.3300")
    assert proposal.proposed_price == Decimal("25806.3300")
    assert proposal.exchange_rate == Decimal("86.89")
    assert proposal.exchange_rate_source == "supplier_feed"
    assert proposal.status == "ready_for_review"


    with pytest.raises(ValueError, match="rate map key"):
        PricingContext(
            rates={
                "USD": ExchangeRate(
                    currency="EUR",
                    rub_per_unit=Decimal("86.89"),
                    source="supplier_feed",
                    observed_at="2026-09-04 13:04",
                    approved=True,
                    supplier_id="netlab",
                    source_sha256="a" * 64,
                )
            },
            rule=None,
        )
