from __future__ import annotations

import pytest

from mks123_pipeline.manufacturer_evidence import (
    EvidenceStatus,
    ManufacturerIdentity,
    build_exact_queries,
    classify_candidates,
    has_exact_product_page_signal,
    load_domain_registry,
    registry_domains,
)


def identity() -> ManufacturerIdentity:
    return ManufacturerIdentity(manufacturer="TP-Link", model="TL-SF1005D", mpn="TL-SF1005D")


def test_exact_official_candidate_is_review_only_source_evidence() -> None:
    result = classify_candidates(
        identity(),
        [
            {
                "title": "TP-Link TL-SF1005D official specifications",
                "url": "https://www.tp-link.com/en/home-networking/5-port-switch/tl-sf1005d/",
                "description": "TL-SF1005D 5-Port 10/100Mbps Desktop Switch",
            }
        ],
        official_domains={"tp-link.com"},
    )
    assert result.status is EvidenceStatus.OFFICIAL_IDENTITY_CANDIDATE
    assert result.candidates[0].exact_model is True
    assert result.auto_publish is False


def test_official_family_page_is_not_exact_evidence() -> None:
    result = classify_candidates(
        identity(),
        [{"title": "TP-Link switches", "url": "https://www.tp-link.com/en/products/switches/", "description": "Network switches"}],
        official_domains={"tp-link.com"},
    )
    assert result.status is EvidenceStatus.OFFICIAL_FAMILY_ONLY
    assert result.auto_publish is False


def test_retailer_result_is_secondary_only() -> None:
    result = classify_candidates(
        identity(),
        [{"title": "TP-Link TL-SF1005D switch", "url": "https://shop.example.test/tl-sf1005d", "description": "5 ports"}],
        official_domains={"tp-link.com"},
    )
    assert result.status is EvidenceStatus.SECONDARY_ONLY
    assert result.auto_publish is False


def test_model_boundary_does_not_match_similar_model() -> None:
    result = classify_candidates(
        identity(),
        [{"title": "TP-Link TL-SF1005D2 switch", "url": "https://www.tp-link.com/tl-sf1005d2", "description": "other revision"}],
        official_domains={"tp-link.com"},
    )
    assert result.status is EvidenceStatus.OFFICIAL_FAMILY_ONLY
    assert result.candidates[0].exact_model is False


def test_no_result_is_unconfirmed() -> None:
    result = classify_candidates(identity(), [], official_domains={"tp-link.com"})
    assert result.status is EvidenceStatus.UNCONFIRMED
    assert result.auto_publish is False


def test_query_plan_preserves_typed_identifiers() -> None:
    queries = build_exact_queries(ManufacturerIdentity("Gembird", "CCP-USB2-AMBM-10", "CCP-USB2-AMBM-10", "8716309041980"))
    assert queries == [
        '"Gembird" "CCP-USB2-AMBM-10"',
        '"CCP-USB2-AMBM-10" "8716309041980"',
    ]


def test_exact_product_page_signal_requires_url_or_title_model() -> None:
    assert has_exact_product_page_signal("https://example.com/products/tl-sf1005d", "<title>TP-Link TL-SF1005D</title>", "TL-SF1005D") is True
    assert has_exact_product_page_signal("https://example.com/", "<title>TP-Link official site</title><p>TL-SF1005D</p>", "TL-SF1005D") is False
    assert has_exact_product_page_signal("https://example.com/", "<title>TP-Link TL-SF1005D</title>", "TL-SF1005D") is False
    assert has_exact_product_page_signal("https://example.com/search/tl-sf1005d", "<title>Search</title>", "TL-SF1005D") is False
    assert has_exact_product_page_signal("https://example.com/products/TL%2DSF1005D", "<title>TP-Link TL-SF1005D</title>", "TL-SF1005D") is True
    assert has_exact_product_page_signal("https://example.com/products/TL-SF1005D.V2", "<title>TP-Link TL-SF1005D.V2</title>", "TL-SF1005D") is False


def test_domain_registry_never_trusts_candidate_entry() -> None:
    registry = load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "Gembird", "aliases": ["GMB"], "domains": ["gembird.com"], "trust_status": "candidate", "basis": "unit"}]})
    assert registry_domains(registry, "Gembird", trusted_only=True) == set()
    assert registry_domains(registry, "GMB", trusted_only=False) == {"gembird.com"}


def test_domain_registry_rejects_duplicate_or_invalid_entries() -> None:
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [
            {"manufacturer": "A", "domains": ["a.example.com"], "trust_status": "verified", "basis": "operator_approved:unit"},
            {"manufacturer": "a", "domains": ["b.example.com"], "trust_status": "candidate", "basis": "unit"},
        ]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "A", "domains": [], "trust_status": "verified", "basis": "operator_approved:unit"}]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "A", "domains": ["127.0.0.1"], "trust_status": "candidate", "basis": "unit"}]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "A", "domains": ["co.uk"], "trust_status": "candidate", "basis": "unit"}]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "A", "domains": ["github.io"], "trust_status": "candidate", "basis": "unit"}]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [{"manufacturer": "A", "domains": ["www.a.example.com"], "trust_status": "candidate", "basis": "unit"}]})
    with pytest.raises(ValueError):
        load_domain_registry({"registry_version": "manufacturer-domains-v1", "entries": [
            {"manufacturer": "A", "domains": ["a.example.com"], "trust_status": "verified", "basis": "operator_approved:unit"},
            {"manufacturer": "B", "domains": ["sub.a.example.com"], "trust_status": "candidate", "basis": "unit"},
        ]})


def test_identity_rejects_empty_typed_identifiers() -> None:
    with pytest.raises(ValueError):
        ManufacturerIdentity("", "MODEL")
    with pytest.raises(ValueError):
        ManufacturerIdentity("Vendor", " ")


def test_identity_flags_do_not_use_url_or_script_text() -> None:
    result = classify_candidates(identity(), [{"title": "catalog", "url": "https://www.tp-link.com/products/TL-SF1005D", "description": ""}], official_domains={"tp-link.com"})
    assert result.candidates[0].exact_model is False
    spoofed = "<script>document.write('<title>TP-Link TL-SF1005D</title>')</script>"
    assert has_exact_product_page_signal("https://example.com/products/TL-SF1005D", spoofed, "TL-SF1005D") is False
    assert has_exact_product_page_signal("https://example.com/products/TL-SF1005D", "<titlex>TP-Link TL-SF1005D</titlex>", "TL-SF1005D") is False
    assert has_exact_product_page_signal("https://example.com/products/TL-SF1005D", "<h1 hidden>TP-Link TL-SF1005D</h1>", "TL-SF1005D") is False
