from __future__ import annotations

import base64
import hashlib

from mks123_pipeline.manufacturer_evidence import has_exact_product_page_signal
from mks123_pipeline.manufacturer_fields import resolve_fetch_item

HTML = """
<html><head><title>TP-Link TL-SF1005D</title></head><body>
<main>
<table>
<tr><th>Модель</th><td>TL-SF1005D</td></tr>
<tr><th>Артикул / MPN</th><td>TL-SF1005D</td></tr>
<tr><th>Габариты</th><td>103.5 × 70 × 22 мм</td></tr>
<tr><th>Вес</th><td>0.25 кг</td></tr>
<tr><th>Совместимость</th><td>TL-SF1005D</td></tr>
<tr><td><a href="/downloads/driver.zip">Драйвер</a> <a href="/downloads/manual.pdf">Инструкция</a></td></tr>
</table>
</main>
</body></html>
"""


def exact_entry(body: str = HTML, **overrides: object) -> dict:
    entry = {
        "url": "https://www.tp-link.com/products/TL-SF1005D",
        "status": "ok",
        "http_status": 200,
        "content_type": "text/html",
        "too_large": False,
        "redirect_location": None,
        "error": None,
        "match_status": "declared_source_exact",
        "manufacturer_match": True,
        "exact_model": True,
        "exact_mpn": True,
        "product_page_signal": True,
        "retrieved_at": "2026-09-09T19:00:00+00:00",
        "body_text": body,
    }
    entry.update(overrides)
    raw_body = entry["body_text"].encode("utf-8")
    entry.setdefault("body_b64", base64.b64encode(raw_body).decode("ascii"))
    entry.setdefault("body_sha256", hashlib.sha256(raw_body).hexdigest())
    entry.setdefault("body_text_sha256", hashlib.sha256(raw_body).hexdigest())
    return entry


def item_with(*entries: dict) -> dict:
    return {
        "catalog_sku": "31121684",
        "name": "TP-Link TL-SF1005D",
        "identity": {"manufacturer": "TP-Link", "model": "TL-SF1005D", "mpn": "TL-SF1005D"},
        "fetched": list(entries),
    }


def test_resolve_exact_page_returns_field_level_proposal_candidates() -> None:
    result = resolve_fetch_item(item_with(exact_entry()), verified_domains={"tp-link.com"})
    fields = {candidate["field"]: candidate["value"] for candidate in result["proposal_candidates"]}
    assert fields["dimensions"] == "103.5 × 70 × 22 мм"
    assert fields["weight"] == "0.25 кг"
    assert fields["compatibility"] == "TL-SF1005D"
    assert fields["driver_url"].endswith("/downloads/driver.zip")
    assert fields["manual_url"].endswith("/downloads/manual.pdf")
    assert all(candidate["source_url"].startswith("https://www.tp-link.com/") for candidate in result["proposal_candidates"])
    assert all(candidate["body_sha256"] == hashlib.sha256(HTML.encode("utf-8")).hexdigest() for candidate in result["proposal_candidates"])
    assert result["auto_apply"] is False
    assert result["status"] == "proposal_candidates"


def test_resolve_recomputes_flags_and_rejects_forged_exact_entry() -> None:
    body = HTML.replace("<title>TP-Link TL-SF1005D</title>", "<title>TP-Link official site</title>")
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert result["proposal_candidates"] == []
    assert result["status"] == "no_exact_source"
    assert result["auto_apply"] is False


def test_resolve_rejects_ambiguous_values_for_same_field() -> None:
    second_body = HTML.replace("0.25 кг", "0.30 кг")
    second = exact_entry(body=second_body)
    result = resolve_fetch_item(item_with(exact_entry(), second), verified_domains={"tp-link.com"})
    assert not any(candidate["field"] == "weight" for candidate in result["proposal_candidates"])
    assert any("weight" in exception for exception in result["exceptions"])
    assert result["status"] == "proposal_candidates"


def test_resolve_rejects_external_document_links() -> None:
    body = HTML.replace('/downloads/manual.pdf', 'https://evil.example/manual.pdf')
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert not any(candidate["field"] == "manual_url" for candidate in result["proposal_candidates"])
    assert any("manual_url" in exception for exception in result["exceptions"])


def test_resolve_rejects_tampered_raw_body_and_text_hash() -> None:
    result = resolve_fetch_item(item_with(exact_entry(body_b64=base64.b64encode(b"different").decode("ascii"))), verified_domains={"tp-link.com"})
    assert result["proposal_candidates"] == []
    assert any("raw source body hash" in exception or "raw source body and body_text differ" in exception for exception in result["exceptions"])


def test_resolve_requires_separate_model_and_mpn_rows() -> None:
    body = HTML.replace('<tr><th>Модель</th><td>TL-SF1005D</td></tr>\n<tr><th>Артикул / MPN</th><td>TL-SF1005D</td></tr>', '<tr><th>Модель / MPN</th><td>TL-SF1005D</td></tr>')
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert result["proposal_candidates"] == []


def test_resolve_accepts_model_only_identity_when_mpn_absent() -> None:
    item = item_with(exact_entry())
    item["identity"]["mpn"] = None
    result = resolve_fetch_item(item, verified_domains={"tp-link.com"})
    assert result["status"] == "proposal_candidates"
    assert result["proposal_candidates"]


def test_resolve_requires_model_and_mpn_in_same_visible_table() -> None:
    body = HTML.replace('<tr><th>Артикул / MPN</th><td>TL-SF1005D</td></tr>\n', '</table><table><tr><th>Артикул / MPN</th><td>TL-SF1005D</td></tr></table><table>\n', 1)
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert result["proposal_candidates"] == []
    assert result["status"] == "no_exact_source"


def test_resolve_ignores_hidden_spec_rows() -> None:
    body = HTML.replace('<tr><th>Вес</th><td>0.25 кг</td></tr>', '<tr hidden><th>Вес</th><td>0.25 кг</td></tr>')
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert not any(candidate["field"] == "weight" for candidate in result["proposal_candidates"])
    assert any("weight" in exception for exception in result["exceptions"])


def test_resolve_fails_closed_on_unverified_stylesheet_visibility() -> None:
    body = '<style>.stealth{display:none}</style>' + HTML.replace('<main>', '<main><table class="stealth"><tr><th>Вес</th><td>999 кг</td></tr></table>', 1)
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert result["proposal_candidates"] == []
    assert has_exact_product_page_signal("https://tp-link.com/products/TL-SF1005D", body, "TL-SF1005D") is False


def test_resolve_ignores_hidden_cell_and_script_text() -> None:
    body = HTML.replace('<th>Вес</th><td>0.25 кг</td>', '<th hidden>Вес</th><td>0.25 кг</td>').replace('<th>Габариты</th><td>103.5 × 70 × 22 мм</td>', '<th>Габариты</th><td><script>999 × 999 × 999 мм</script>103.5 × 70 × 22 мм</td>')
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert not any(candidate["field"] == "weight" for candidate in result["proposal_candidates"])
    assert not any("999" in candidate["value"] for candidate in result["proposal_candidates"])
    assert any("weight" in exception for exception in result["exceptions"])


def test_extract_rejects_packaging_context_and_unsafe_document_links() -> None:
    body = HTML.replace('<table>', '<table><caption>Packaging dimensions</caption>', 1).replace('/downloads/manual.pdf', '/downloads/manual.exe')
    result = resolve_fetch_item(item_with(exact_entry(body=body)), verified_domains={"tp-link.com"})
    assert not any(candidate["field"] in {"dimensions", "manual_url"} for candidate in result["proposal_candidates"])
    assert result["exceptions"]
