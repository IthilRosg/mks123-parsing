import csv
import hashlib
import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.config import load_pilot_config, pricing_context_from_config
from mks123_pipeline.runner import run_pilot


def _write_netlab_metadata(
    source: Path,
    *,
    fetched_at: str,
    feed_catalog_date: str = "2026-09-04 09:04",
    item_count: int = 1,
    usd_rate: str = "86.89",
) -> Path:
    data = source.read_bytes()
    metadata = {
        "supplier": "netlab",
        "feed_kind": "price",
        "source": "direct_https",
        "source_url": "https://www.netlab.ru/products/pricexml4.zip",
        "fetched_at_utc": fetched_at,
        "local_file": source.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "content_type": "application/zip",
        "http_status": 200,
        "etag": None,
        "last_modified": None,
        "feed_catalog_date": feed_catalog_date,
        "item_count": item_count,
        "currency_rates": {"USD": usd_rate},
        "credentials_persisted": False,
        "publication_enabled": False,
        "production_writes": 0,
        "max_feed_age_hours": 24,
        "feed_age_seconds": 10860.0,
    }
    path = source.with_suffix(".metadata.json")
    path.write_text(json.dumps(metadata, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return path


@pytest.mark.skipif(os.name == "nt", reason="sealed-run CLI requires POSIX directory freeze")
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
    assert Decimal(proposal["calculated_price"]) == Decimal("110.00")
    assert Decimal(proposal["proposed_price"]) == Decimal("110.00")


def test_runner_binds_netlab_supplier_feed_rate_to_read_only_proposal(tmp_path: Path) -> None:
    source = tmp_path / "pricexml4.zip"
    xml = (
        "<xml_catalog date=\"2026-09-04 09:04\"><shop>"
        "<currencies><currency id=\"USD\" rate=\"86.89\"/></currencies>"
        "<categories><category id=\"1\">Network</category></categories><offers>"
        "<offer id=\"1000463\" available=\"true\"><name>Cable</name><priceE>270</priceE>"
        "<currencyId>USD</currencyId><categoryId>1</categoryId><count>4</count>"
        "</offer></offers></shop></xml_catalog>"
    )
    with ZipFile(source, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("Price.xml", xml)
    source_metadata = _write_netlab_metadata(
        source,
        fetched_at="2026-09-04T09:05:00Z",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "101,,311000463,,Cable,,25000,1,1,1,Network\n",
        encoding="utf-8",
    )
    config = tmp_path / "netlab.yaml"
    config.write_text(
        """supplier:
  id: netlab
  scope: {catalog_sku_prefix: "31"}
  source:
    type: supplier_xml_zip
    url: "https://www.netlab.ru/products/pricexml4.zip"
    min_offer_count: 60000
    max_offer_count: 100000
    max_response_bytes: 134217728
pricing:
  base_currency: RUB
  vat_basis: included
  vat_policy_approved: true
  exchange_rates:
    USD: {source: supplier_feed, min_rub_per_unit: 40, max_rub_per_unit: 200}
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
    loaded = load_pilot_config(config)
    summary = run_pilot(
        source,
        catalog,
        tmp_path / "netlab-run",
        fetched_at="2026-09-04T09:05:00Z",
        min_source_items=1,
        max_source_items=10,
        max_source_bytes=64 * 1024,
        adapter=NetlabAdapter(),
        pricing_resolver=lambda snapshot: pricing_context_from_config(
            loaded.pricing,
            observed_at=snapshot.catalog_date or "",
            supplier_id="netlab",
            supplier_rates=snapshot.currencies,
            source_sha256=snapshot.source_sha256,
        ),
        config_path=config,
        source_metadata_path=source_metadata,
    )

    assert summary["proposals"] == {"ready_for_review": 1}
    assert summary["production_writes"] == 0
    with (tmp_path / "netlab-run/proposals/proposals.csv").open(
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        proposal = next(csv.DictReader(handle))
    assert proposal["exchange_rate"] == "86.89"
    assert proposal["exchange_rate_source"] == "supplier_feed"
    assert Decimal(proposal["calculated_price"]) == Decimal("25806.3300")
    manifest = json.loads(
        (tmp_path / "netlab-run/run-manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["policy"]["rates"]["USD"]["currency"] == "USD"
    assert manifest["policy"]["rates"]["USD"]["source_sha256"] == manifest["inputs"]["source"]["sha256"]


def test_direct_netlab_run_rejects_standalone_price_xml_without_acquisition_metadata(tmp_path: Path) -> None:
    source = tmp_path / "Price.xml"
    source.write_text(
        '<xml_catalog date="2026-09-04 09:04"><shop><currencies>'
        '<currency id="USD" rate="86.89"/></currencies><offers>'
        '<offer id="1" available="true"><name>One</name><priceE>1</priceE>'
        '<currencyId>USD</currencyId></offer></offers></shop></xml_catalog>',
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "101,,311,,One,,100,1,1,,\n",
        encoding="utf-8",
    )
    config = tmp_path / "netlab.yaml"
    config.write_text("supplier: netlab\n", encoding="utf-8")

    with pytest.raises(ValueError, match="accepted immutable.*ZIP.*acquisition metadata"):
        run_pilot(
            source,
            catalog,
            tmp_path / "run",
            fetched_at="2026-09-04T09:05:00Z",
            adapter=NetlabAdapter(),
            config_path=config,
        )
