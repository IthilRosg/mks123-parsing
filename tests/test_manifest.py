import hashlib
import json
from pathlib import Path

from mks123_pipeline.runner import run_pilot

CATALOG_HEADER = "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"


def test_run_contains_self_contained_input_manifest(tmp_path: Path) -> None:
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
    summary = run_pilot(
        source,
        catalog,
        run_dir,
        fetched_at="2026-09-03T10:00:00Z",
        config_path=config,
    )

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["run_id"] == manifest["canonical_run_id"]
    assert manifest["run_id"].startswith("electrozone-")
    assert manifest["supplier"] == "electrozone"
    assert manifest["inputs"]["source"]["bundle_path"] == "inputs/source.yml"
    assert manifest["inputs"]["catalog"]["bundle_path"] == "inputs/catalog.csv"
    assert manifest["inputs"]["config"]["bundle_path"] == "inputs/config.yaml"
    assert manifest["diagnostics"] == {
        "source_path": "inputs/source.yml",
        "catalog_path": "inputs/catalog.csv",
        "config_path": "inputs/config.yaml",
    }
    assert manifest["inputs"]["source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert manifest["inputs"]["catalog"]["sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert manifest["inputs"]["config"]["sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert manifest["policy"]["vat_basis"] == "unknown"
    code_files = manifest["code_identity"]["files"]
    assert "mks123_pipeline/config.py" in code_files
    assert "mks123_pipeline/legacy_xml.py" in code_files
    assert "mks123_pipeline/verifier.py" in code_files
    assert "fsspec" in manifest["code_identity"]["runtime"]["dependencies"]
    code_hash = manifest["code_identity"]["sha256"]
    assert f"-code-{code_hash[:12]}" in manifest["canonical_run_id"]
    assert manifest["summary"]["source_items"] == summary["source_items"]
    seal = json.loads((run_dir / "seal.json").read_text(encoding="utf-8"))
    assert "run-manifest.json" in seal["files"]
    assert "inputs/source.yml" in seal["files"]
    assert "inputs/catalog.csv" in seal["files"]
    assert "inputs/config.yaml" in seal["files"]
