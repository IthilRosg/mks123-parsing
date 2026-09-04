import json
import subprocess
import sys
from pathlib import Path

from mks123_pipeline.runner import run_pilot
from mks123_pipeline.verifier import verify_run

CATALOG_HEADER = "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"


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
