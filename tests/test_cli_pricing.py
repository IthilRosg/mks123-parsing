import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def test_cli_passes_approved_simple_pricing_policy_to_read_only_runner(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        "<offer id=\"1\"><name>One</name><price>100</price><currencyId>RUR</currencyId></offer>"
        "</offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "101,,111,,,,125,1,1,,\n",
        encoding="utf-8",
    )
    config = tmp_path / "policy.yaml"
    config.write_text(
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
    project = Path(__file__).parents[1]
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project)

    result = subprocess.run(
        [
            sys.executable,
            "run_pilot.py",
            "--source", str(source),
            "--catalog", str(catalog),
            "--output", str(tmp_path / "run"),
            "--fetched-at", "2026-09-03T10:00:00Z",
            "--config", str(config),
        ],
        cwd=project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["proposals"] == {"ready_for_review": 1}
    assert summary["vat_basis"] == "included"
    assert summary["markup_policy"] == "supplier-price-plus-10@2026-09-03"
    assert summary["production_writes"] == 0
    with (tmp_path / "run/proposals/proposals.csv").open(encoding="utf-8-sig", newline="") as handle:
        proposal = next(csv.DictReader(handle))
    assert proposal["calculated_price"] == "110.00"
    assert proposal["proposed_price"] == "110.00"
