import csv
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from threading import Barrier

import duckdb
import pytest

from mks123_pipeline import runner
from mks123_pipeline.models import SupplierItem, SupplierSnapshot
from mks123_pipeline.pricing import ExchangeRate, MarkupRule, PricingContext
from mks123_pipeline.runner import run_pilot


def test_existing_output_directory_is_never_deleted(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        run_pilot(tmp_path / "missing.yml", tmp_path / "missing.csv", output, fetched_at="2026-09-01T00:00:00Z")
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_run_pilot_rejects_glob_metacharacters_before_staging_cleanup(tmp_path: Path) -> None:
    sentinel = tmp_path / ".[ab].stage-sentinel"
    sentinel.mkdir()
    with pytest.raises(ValueError, match="run name"):
        run_pilot(
            tmp_path / "missing.yml",
            tmp_path / "missing.csv",
            tmp_path / "[ab]",
            fetched_at="2026-09-01T00:00:00Z",
        )
    assert sentinel.is_dir()


def test_run_pilot_enforces_source_byte_limit_before_creating_output(tmp_path: Path) -> None:
    source = tmp_path / "oversize.yml"
    source.write_text("<yml_catalog>" + ("x" * 5000) + "</yml_catalog>", encoding="utf-8")
    output = tmp_path / "run"
    with pytest.raises(ValueError, match="byte limit"):
        run_pilot(
            source,
            tmp_path / "catalog.csv",
            output,
            fetched_at="2026-09-01T00:00:00Z",
            max_source_bytes=1024,
        )
    assert not output.exists()


def test_concurrent_runs_publish_one_complete_provenance_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources: list[Path] = []
    for label, item_id in (("AAA", "1"), ("BBB", "2")):
        source = tmp_path / f"source-{label}.yml"
        source.write_text(
            "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
            f'<offer id="{item_id}"><name>{label}</name><price>1</price><currencyId>RUR</currencyId></offer>'
            "</offers></shop></yml_catalog>",
            encoding="utf-8",
        )
        sources.append(source)
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n",
        encoding="utf-8",
    )
    output = tmp_path / "shared-run"
    barrier = Barrier(2)
    original_exists = Path.exists

    def synchronized_exists(self: Path) -> bool:
        if self == output:
            barrier.wait(timeout=10)
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", synchronized_exists)

    def worker(source: Path):
        try:
            return ("success", run_pilot(source, catalog, output, fetched_at="2026-09-01T00:00:00Z"))
        except FileExistsError as exc:
            return (type(exc).__name__, str(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(worker, sources))

    assert sorted(result[0] for result in results) == ["FileExistsError", "success"]
    stored_summary = json.loads((output / "reports/summary.json").read_text(encoding="utf-8"))
    normalized = json.loads((output / "normalized/items.jsonl").read_text(encoding="utf-8").strip())
    selected = sources[0] if normalized["name"] == "AAA" else sources[1]
    assert stored_summary["source_file"] == selected.name
    assert stored_summary["source_sha256"] == hashlib.sha256(selected.read_bytes()).hexdigest()


def test_catalog_hash_uses_exact_bytes_loaded_for_matching(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        "<yml_catalog><shop><currencies><currency id=\"RUR\" rate=\"1\"/></currencies><offers>"
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId></offer>'
        "</offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    header = "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
    original_bytes = (header + "101,,111,,,,1,0,1,,\n").encode()
    replacement_bytes = (header + "202,,111,,,,1,0,1,,\n").encode()
    catalog.write_bytes(original_bytes)
    original_load_catalog = runner._load_catalog

    def mutate_after_load(path: Path, *, sku_prefix: str = "11"):
        loaded = original_load_catalog(path, sku_prefix=sku_prefix)
        catalog.write_bytes(replacement_bytes)
        return loaded

    monkeypatch.setattr(runner, "_load_catalog", mutate_after_load)
    summary = run_pilot(source, catalog, tmp_path / "run", fetched_at="2026-09-01T00:00:00Z")

    assert summary["catalog_sha256"] == hashlib.sha256(original_bytes).hexdigest()
    matches = list(csv.DictReader((tmp_path / "run/matches/matches.csv").open(encoding="utf-8-sig", newline="")))
    assert matches[0]["catalog_product_id"] == "101"


def test_run_pilot_writes_auditable_read_only_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        """<yml_catalog date="2026-08-13 17:10"><shop><currencies><currency id="RUR" rate="1"/></currencies><categories><category id="10">Ноутбуки</category></categories><offers>
<offer id="404042" available="true"><price>100</price><currencyId>RUR</currencyId><categoryId>10</categoryId><name>One</name><vendor>Tecno</vendor><vendorCode>M1</vendorCode><barcode>111</barcode></offer>
<offer id="404043" available="false"><price>200</price><currencyId>RUR</currencyId><categoryId>10</categoryId><name>=1+1</name><vendor>Tecno</vendor><vendorCode>M2</vendorCode></offer>
</offers></shop></yml_catalog>""",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    with catalog.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["product_id", "model", "sku", "ean", "name", "manufacturer", "price", "quantity", "status", "category_ids", "categories"])
        writer.writeheader()
        writer.writerow({"product_id": 7, "model": "M1", "sku": "11404042", "ean": "111", "name": "One", "manufacturer": "Tecno", "price": "125", "quantity": 1, "status": 1, "category_ids": "10", "categories": "Ноутбуки"})
        writer.writerow({"product_id": 8, "model": "OLD", "sku": "11999999", "ean": "", "name": "Old", "manufacturer": "Tecno", "price": "50", "quantity": 0, "status": 1, "category_ids": "11", "categories": "Старые"})

    summary = run_pilot(source, catalog, tmp_path / "run", fetched_at="2026-09-01T06:44:44Z")

    assert summary["source_items"] == 2
    assert summary["catalog_scope_items"] == 2
    assert summary["matches"] == {"exact": 1, "unmatched": 1}
    assert summary["catalog_missing_supplier"] == 1
    assert summary["proposals"] == {"blocked_match": 1, "blocked_vat_basis": 1}
    assert summary["exact_source_price_vs_current"] == {"equal": 0, "source_higher": 0, "source_lower": 1}
    assert summary["exact_availability_vs_catalog"] == {"agree_in_stock": 1, "agree_out_of_stock": 0, "source_in_catalog_out": 0, "source_out_catalog_in": 0}
    assert summary["source_identity"] == {"with_ean": 1, "with_mpn": 2, "with_image": 0}
    assert summary["category_mapping"] == {
        "source_categories": 1,
        "source_only_products": 1,
        "strong_candidate_categories": 0,
        "review_candidate_categories": 0,
        "ambiguous_categories": 1,
        "unmapped_categories": 0,
        "source_only_with_candidate": 0,
        "publication_eligible": 0,
    }
    assert summary["production_writes"] == 0
    stored = json.loads((tmp_path / "run/reports/summary.json").read_text(encoding="utf-8"))
    assert stored == summary
    with (tmp_path / "run/matches/source_only.csv").open(encoding="utf-8-sig", newline="") as handle:
        source_only = list(csv.DictReader(handle))
    assert [row["supplier_item_id"] for row in source_only] == ["404043"]
    assert source_only[0]["name"] == "'=1+1"
    jsonl_rows = [json.loads(line) for line in (tmp_path / "run/normalized/items.jsonl").read_text(encoding="utf-8").splitlines()]
    assert jsonl_rows[1]["name"] == "=1+1"
    with (tmp_path / "run/matches/review_queue.csv").open(encoding="utf-8-sig", newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    with (tmp_path / "run/proposals/product-category-proposals.csv").open(encoding="utf-8-sig", newline="") as handle:
        product_categories = list(csv.DictReader(handle))
    assert product_categories[0]["proposal_status"] == "blocked_ambiguous_category"
    with duckdb.connect(str(tmp_path / "run/pilot.duckdb"), read_only=True) as db:
        assert db.execute("select count(*) from normalized_items").fetchone()[0] == 2
        assert db.execute("select count(*) from matches").fetchone()[0] == 2
        assert db.execute("select count(*) from proposals").fetchone()[0] == 2
    seal = json.loads((tmp_path / "run/seal.json").read_text(encoding="utf-8"))
    actual_files = {
        path.relative_to(tmp_path / "run").as_posix()
        for path in (tmp_path / "run").rglob("*")
        if path.is_file() and path.name != "seal.json"
    }
    assert set(seal["files"]) == actual_files


def test_crashed_run_reservation_is_released_and_staging_is_recovered(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(
        '<yml_catalog date="2026-08-13 17:10"><shop><currencies><currency id="RUR" rate="1"/></currencies><offers>'
        '<offer id="1"><name>One</name><price>1</price><currencyId>RUR</currencyId>'
        "</offer></offers></shop></yml_catalog>",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n",
        encoding="utf-8",
    )
    output = tmp_path / "run"
    marker = tmp_path / "started.marker"
    project = Path(__file__).parents[1]
    child_code = """
import sys
import time
from pathlib import Path

from mks123_pipeline import runner

root = Path(sys.argv[1])
marker = Path(sys.argv[2])
output = root / "run"

def blocked_build(*args, **kwargs):
    marker.write_text("started", encoding="ascii")
    while True:
        time.sleep(0.1)

runner._build_pilot = blocked_build
runner.run_pilot(root / "source.yml", root / "catalog.csv", output, fetched_at="2026-08-13T17:10:00Z")
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(project)
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(tmp_path), str(marker)],
        cwd=project,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5.0
        while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), child.communicate(timeout=2.0)
    finally:
        child.terminate()
        child.communicate(timeout=5.0)

    stale_stages = list(tmp_path.glob(".run.stage-*"))
    assert stale_stages
    assert not output.exists()

    summary = run_pilot(
        source,
        catalog,
        output,
        fetched_at="2026-08-13T17:10:00Z",
        min_source_items=1,
    )

    assert summary["source_items"] == 1
    assert output.is_dir()
    assert list(tmp_path.glob(".run.stage-*")) == []


def test_run_pilot_accepts_a_supplier_neutral_adapter_and_catalog_scope(tmp_path: Path) -> None:
    source = tmp_path / "supplier-b.dat"
    source.write_bytes(b"supplier-b immutable source")
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "77,MODEL-1,31-1,123,Widget,Acme,100,2,1,10,Equipment\n",
        encoding="utf-8",
    )

    class SupplierBAdapter:
        supplier_id = "supplier-b"
        catalog_sku_prefix = "31"

        def parse(
            self,
            source_path: Path,
            *,
            fetched_at: str,
            min_items: int,
            max_items: int,
            max_bytes: int,
        ) -> SupplierSnapshot:
            assert source_path.read_bytes() == source.read_bytes()
            assert source_path.name == "source.dat"
            assert min_items == 1
            assert max_items == 100_000
            assert max_bytes == 64 * 1024 * 1024
            return SupplierSnapshot(
                catalog_date="2026-09-02",
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                currencies={"RUR": Decimal(1)},
                categories={},
                items=[SupplierItem(
                    supplier=self.supplier_id,
                    supplier_item_id="1",
                    catalog_sku="31-1",
                    supplier_sku="1",
                    manufacturer="Acme",
                    model="MODEL-1",
                    mpn="MODEL-1",
                    ean="123",
                    name="Widget",
                    source_price=Decimal(100),
                    currency="RUR",
                    available=True,
                    source_url="https://supplier-b.example/items/1",
                    description="Widget description",
                    attributes={"class": "equipment"},
                    fetched_at=fetched_at,
                    raw_hash=hashlib.sha256(b"supplier-b-item-1").hexdigest(),
                )],
            )

    summary = run_pilot(
        source,
        catalog,
        tmp_path / "run",
        fetched_at="2026-09-02T10:00:00Z",
        adapter=SupplierBAdapter(),
    )

    assert summary["supplier"] == "supplier-b"
    assert summary["catalog_scope_items"] == 1
    assert summary["matches"] == {"exact": 1}
    assert summary["production_writes"] == 0


def test_run_pilot_emits_simple_plus_ten_percent_price_preview_when_policy_is_approved(tmp_path: Path) -> None:
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
    pricing = PricingContext(
        rates={"RUR": ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source="supplier-feed", observed_at="2026-09-03")},
        rule=MarkupRule(id="supplier-price-plus-10", version="2026-09-03", approved=True, multiplier=Decimal("1.10")),
        vat_basis="included",
    )

    summary = run_pilot(
        source,
        catalog,
        tmp_path / "run",
        fetched_at="2026-09-03T10:00:00Z",
        pricing=pricing,
    )

    assert summary["proposals"] == {"ready_for_review": 1}
    assert summary["vat_basis"] == "included"
    assert summary["markup_policy"] == "supplier-price-plus-10@2026-09-03"
    assert summary["production_writes"] == 0
    with (tmp_path / "run/proposals/proposals.csv").open(encoding="utf-8-sig", newline="") as handle:
        proposal = next(csv.DictReader(handle))
    assert proposal["calculated_price"] == "110.00"
    assert proposal["proposed_price"] == "110.00"


def test_runner_rejects_adapter_snapshot_with_wrong_supplier_identity(tmp_path: Path) -> None:
    source = tmp_path / "supplier-b.dat"
    source.write_bytes(b"supplier-b immutable source")
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "77,MODEL-1,31-1,123,Widget,Acme,100,2,1,10,Equipment\n",
        encoding="utf-8",
    )

    class WrongSnapshotAdapter:
        supplier_id = "supplier-b"
        catalog_sku_prefix = "31"

        def parse(self, source_path: Path, *, fetched_at: str, min_items: int, max_items: int, max_bytes: int) -> SupplierSnapshot:
            return SupplierSnapshot(
                source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
                currencies={"RUR": Decimal(1)},
                categories={},
                items=[SupplierItem(
                    supplier="other-supplier",
                    supplier_item_id="1",
                    catalog_sku="31-1",
                    supplier_sku="1",
                    name="Widget",
                    source_price=Decimal(100),
                    currency="RUR",
                    available=True,
                    fetched_at=fetched_at,
                    raw_hash="a" * 64,
                )],
            )

    with pytest.raises(ValueError, match="supplier identity"):
        run_pilot(
            source,
            catalog,
            tmp_path / "run",
            fetched_at="2026-09-02T10:00:00Z",
            adapter=WrongSnapshotAdapter(),
        )


def test_abandoned_readonly_stage_is_removed_safely(tmp_path: Path) -> None:
    output_dir = tmp_path / "safe-run"
    staging = tmp_path / ".safe-run.stage-old"
    staging.mkdir()
    artifact = staging / "seal.json"
    artifact.write_text("stale", encoding="utf-8")
    os.chmod(artifact, stat.S_IREAD)

    runner._remove_abandoned_staging(output_dir)

    assert not staging.exists()
