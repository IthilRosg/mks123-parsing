import csv
import hashlib
import json
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import duckdb

from mks123_pipeline.adapters import NetlabAdapter
from mks123_pipeline.config import load_pilot_config, pricing_context_from_config
from mks123_pipeline.db_digest import database_content_sha256
from mks123_pipeline.integrity import build_run_seal
from mks123_pipeline.runner import run_pilot
from mks123_pipeline.verifier import (
    _canonical_run_id_matches,
    _code_identity_hash_matches,
    _rate_source_hash_matches,
    verify_run,
)

CATALOG_HEADER = "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"


def _write_netlab_metadata(
    source: Path,
    *,
    fetched_at: str,
    item_count: int,
    feed_catalog_date: str = "2026-09-04 09:04",
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


def _make_run(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source = tmp_path / "supplier.yml"
    source.write_text(
        "<yml_catalog date=\"2026-09-01 10:00\"><shop>"
        "<currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>100</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(CATALOG_HEADER + "101,,111,,,,125,1,1,,\n", encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text("supplier: test\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_pilot(source, catalog, run_dir, fetched_at="2026-09-03T10:00:00Z", config_path=config)
    return run_dir, source, catalog, config


def _make_netlab_run(tmp_path: Path, *, item_count: int) -> tuple[Path, Path, Path, Path]:
    source_xml = (
        b'<xml_catalog date="2026-09-04 09:04"><shop>'
        b'<currencies><currency id="USD" rate="86.89"/></currencies>'
        b'<categories><category id="1">Network</category></categories><offers>'
        + b"".join(
            (
                f'<offer id="{item_id}" available="true"><name>Cable {item_id}</name>'
                f"<priceE>270</priceE><currencyId>USD</currencyId><categoryId>1</categoryId><count>4</count>"
                "</offer>"
            ).encode()
            for item_id in range(1000463, 1000463 + item_count)
        )
        + b"</offers></shop></xml_catalog>"
    )
    archive = BytesIO()
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("Price.xml", source_xml)
    source = tmp_path / "accepted.zip"
    source.write_bytes(archive.getvalue())
    source_metadata = _write_netlab_metadata(
        source,
        fetched_at="2026-09-04T09:05:00Z",
        item_count=item_count,
    )
    catalog = tmp_path / "catalog.csv"
    catalog_rows = ["101,,311000463,,Cable 1000463,,25000,1,1,1,Network"]
    if item_count >= 60000:
        catalog_rows.append("102,,319999999,,Other cable,,100,1,1,1,Network")
    catalog.write_text(CATALOG_HEADER + "\n".join(catalog_rows) + "\n", encoding="utf-8")
    config_path = tmp_path / "netlab.yaml"
    config_path.write_text(
        """supplier:
  id: netlab
  scope: {catalog_sku_prefix: "31"}
  source: {type: supplier_xml_zip, url: "https://www.netlab.ru/products/pricexml4.zip", min_offer_count: 60000, max_offer_count: 100000, max_response_bytes: 134217728}
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
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    config = load_pilot_config(config_path)
    run_dir = tmp_path / "netlab-run"
    run_pilot(
        source,
        catalog,
        run_dir,
        fetched_at="2026-09-04T09:05:00Z",
        min_source_items=item_count,
        max_source_items=100000,
        max_source_bytes=128 * 1024 * 1024,
        adapter=NetlabAdapter(),
        pricing_resolver=lambda snapshot: pricing_context_from_config(
            config.pricing,
            observed_at=snapshot.catalog_date or "",
            supplier_id="netlab",
            supplier_rates=snapshot.currencies,
            source_sha256=snapshot.source_sha256,
        ),
        config_path=config_path,
        source_metadata_path=source_metadata,
    )
    return run_dir, source, catalog, config_path


def test_generic_verifier_passes_self_contained_run(tmp_path: Path) -> None:
    run_dir, source, catalog, config = _make_run(tmp_path)

    result = verify_run(run_dir, source=source, catalog=catalog, config=config)

    assert result["status"] == "PASS"
    assert result["checks_total"] >= 10
    assert all(check["passed"] for check in result["checks"].values())


def test_generic_verifier_rejects_changed_external_input(tmp_path: Path) -> None:
    run_dir, source, catalog, config = _make_run(tmp_path)
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    result = verify_run(run_dir, source=source, catalog=catalog, config=config)

    assert result["status"] == "FAIL"
    assert result["checks"]["external_source_hash"]["passed"] is False
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["inputs"]["source"]["bundle_path"] == "inputs/source.yml"


def test_generic_verifier_cli_returns_pass_for_valid_run(tmp_path: Path) -> None:
    run_dir, source, catalog, config = _make_run(tmp_path)
    project = Path(__file__).parents[1]

    completed = subprocess.run(
        [
            sys.executable,
            "verify_run.py",
            "--run",
            str(run_dir),
            "--source",
            str(source),
            "--catalog",
            str(catalog),
            "--config",
            str(config),
        ],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["status"] == "PASS"


def test_rate_source_hash_must_equal_captured_source_hash() -> None:
    source_hash = "a" * 64
    manifest = {
        "supplier": "netlab",
        "inputs": {"source": {"sha256": source_hash}},
        "policy": {
            "rates": {
                "USD": {
                    "currency": "USD",
                    "source": "supplier_feed",
                    "source_sha256": "b" * 64,
                    "supplier_id": "netlab",
                }
            }
        },
    }

    assert _rate_source_hash_matches(manifest) is False
    manifest["policy"]["rates"]["USD"]["source_sha256"] = source_hash
    assert _rate_source_hash_matches(manifest) is True
    manifest["policy"]["rates"]["USD"]["currency"] = "EUR"
    assert _rate_source_hash_matches(manifest) is False


def test_code_identity_digest_must_match_listed_code_files() -> None:
    files = {
        "mks123_pipeline/pricing.py": {"sha256": "a" * 64, "size": 123},
        "mks123_pipeline/verifier.py": {"sha256": "b" * 64, "size": 456},
    }
    runtime = {
        "implementation": "CPython",
        "python_version": "3.11.0",
        "cache_tag": "cpython-311",
        "dependencies": {"pydantic": "2.13.5"},
    }
    payload = (
        json.dumps(
            {"files": files, "runtime": runtime},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    identity = {
        "schema_version": "1",
        "files": files,
        "runtime": runtime,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    assert _code_identity_hash_matches(identity) is True
    identity["sha256"] = "c" * 64
    assert _code_identity_hash_matches(identity) is False


def test_canonical_run_id_must_bind_source_catalog_policy_and_code() -> None:
    source_hash = "a" * 64
    catalog_hash = "b" * 64
    policy_hash = "c" * 64
    code_hash = "d" * 64
    config_hash = "e" * 64
    expected = (
        f"netlab-{source_hash[:12]}-catalog-{catalog_hash[:12]}-"
        f"config-{config_hash[:12]}-policy-{policy_hash[:12]}-code-{code_hash[:12]}"
    )
    manifest = {
        "supplier": "netlab",
        "run_id": expected,
        "canonical_run_id": expected,
        "inputs": {
            "source": {"sha256": source_hash},
            "catalog": {"sha256": catalog_hash},
            "config": {"sha256": config_hash},
        },
        "policy": {"hash": policy_hash},
        "code_identity": {"sha256": code_hash},
    }

    assert _canonical_run_id_matches(manifest) is True
    manifest["canonical_run_id"] = expected.replace("code-dddddddddddd", "code-eeeeeeeeeeee")
    assert _canonical_run_id_matches(manifest) is False


def test_verifier_recomputes_netlab_proposal_formula_from_captured_zip(tmp_path: Path) -> None:
    xml = (
        b'<xml_catalog date="2026-09-04 09:04"><shop>'
        b'<currencies><currency id="USD" rate="86.89"/></currencies>'
        b'<categories><category id="1">Network</category></categories><offers>'
        b'<offer id="1000463" available="true"><name>Cable</name><priceE>270</priceE>'
        b'<currencyId>USD</currencyId><categoryId>1</categoryId><count>4</count>'
        b'</offer></offers></shop></xml_catalog>'
    )
    archive = BytesIO()
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("Price.xml", xml)
    source = tmp_path / "accepted.zip"
    source.write_bytes(archive.getvalue())
    source_metadata = _write_netlab_metadata(
        source,
        fetched_at="2026-09-04T09:05:00Z",
        item_count=1,
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(CATALOG_HEADER + "101,,311000463,,Cable,,25000,1,1,1,Network\n", encoding="utf-8")
    config_path = tmp_path / "netlab.yaml"
    config_path.write_text(
        """supplier:
  id: netlab
  scope: {catalog_sku_prefix: "31"}
  source: {type: supplier_xml_zip, url: "https://www.netlab.ru/products/pricexml4.zip", min_offer_count: 60000, max_offer_count: 100000, max_response_bytes: 134217728}
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
publication: {enabled: false}
""",
        encoding="utf-8",
    )
    config = load_pilot_config(config_path)
    run_dir = tmp_path / "netlab-run"
    run_pilot(
        source,
        catalog,
        run_dir,
        fetched_at="2026-09-04T09:05:00Z",
        adapter=NetlabAdapter(),
        min_source_items=1,
        config_path=config_path,
        pricing_resolver=lambda snapshot: pricing_context_from_config(
            config.pricing,
            observed_at=snapshot.catalog_date or "",
            supplier_id="netlab",
            supplier_rates=snapshot.currencies,
            source_sha256=snapshot.source_sha256,
        ),
        source_metadata_path=source_metadata,
    )
    proposal_path = run_dir / "proposals/proposals.csv"
    rows = list(csv.DictReader(proposal_path.read_text(encoding="utf-8-sig").splitlines()))
    rows[0]["proposed_price"] = "1"
    proposal_path.chmod(0o600)
    with proposal_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    seal_path = run_dir / "seal.json"
    seal_path.chmod(0o600)
    seal_path.unlink()
    build_run_seal(run_dir)

    result = verify_run(run_dir)

    assert result["status"] == "FAIL"
    assert result["checks"]["netlab_pricing_semantics"]["passed"] is False


def test_verifier_rejects_unknown_feed_completeness_status(tmp_path: Path) -> None:
    run_dir, _, _, _ = _make_run(tmp_path)
    summary_path = run_dir / "reports/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["feed_completeness"]["status"] = "unexpected"
    summary_path.chmod(0o600)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["summary"]["feed_completeness"] = summary["feed_completeness"]
    manifest_path.chmod(0o600)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    seal_path = run_dir / "seal.json"
    seal_path.chmod(0o600)
    seal_path.unlink()
    build_run_seal(run_dir)

    result = verify_run(run_dir)

    assert result["status"] == "FAIL"
    assert result["checks"]["missing_action_gate"]["passed"] is False


def test_verifier_rejects_netlab_feed_below_configured_minimum(tmp_path: Path) -> None:
    run_dir, _, _, _ = _make_netlab_run(tmp_path, item_count=1)

    result = verify_run(run_dir)

    assert result["status"] == "FAIL"
    assert result["checks"]["netlab_pricing_semantics"]["passed"] is False
    assert "minimum" in result["checks"]["netlab_pricing_semantics"]["detail"]


def _replace_first_csv_value(path: Path, column: str, value: str) -> None:
    path.chmod(0o600)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    assert fieldnames is not None
    assert rows
    rows[0][column] = value
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_verifier_rejects_netlab_semantic_forgery(tmp_path: Path) -> None:
    run_dir, _, _, _ = _make_netlab_run(tmp_path, item_count=60000)
    _replace_first_csv_value(run_dir / "matches/matches.csv", "catalog_product_id", "102")
    _replace_first_csv_value(run_dir / "proposals/proposals.csv", "product_id", "102")

    database_path = run_dir / "pilot.duckdb"
    database_path.chmod(0o600)
    with duckdb.connect(str(database_path)) as db:
        db.execute("update matches set catalog_product_id = '102' where supplier_item_id = '1000463'")
        db.execute("update proposals set product_id = '102' where supplier_item_id = '1000463'")
    database_digest = database_content_sha256(database_path)

    summary_path = run_dir / "reports/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["duckdb_content_sha256"] = database_digest
    summary_path.chmod(0o600)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["summary"]["duckdb_content_sha256"] = database_digest
    manifest_path.chmod(0o600)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    seal_path = run_dir / "seal.json"
    seal_path.chmod(0o600)
    seal_path.unlink()
    build_run_seal(run_dir)

    result = verify_run(run_dir)

    assert result["status"] == "FAIL"
    assert result["checks"]["netlab_artifact_reconciliation"]["passed"] is False
