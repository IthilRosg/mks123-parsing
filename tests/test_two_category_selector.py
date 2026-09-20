from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from mks123_pipeline import integrity
from mks123_pipeline import netlab_staging_apply as staging_apply
from mks123_pipeline.netlab_staging_apply import (
    StagingApplyError,
    validate_candidate_bundle,
    validate_candidate_operation_set,
)
from mks123_pipeline.two_category_selector import (
    CategorySelectorError,
    build_category_tree_snapshot,
    select_two_category_items,
)
from scripts import run_netlab_transfer as transfer_script


def _run_transfer(argv: list[str]) -> int:
    args = list(argv)
    if "--expected-run-seal-sha256" not in args and "--run-manifest" in args:
        manifest_path = Path(args[args.index("--run-manifest") + 1])
        try:
            seal = integrity.load_sealed_run(manifest_path.parent, read_content=False)
        except (OSError, RuntimeError, ValueError):
            pass
        else:
            args.extend(["--expected-run-seal-sha256", seal.seal_evidence.sha256])
    return transfer_script.main(args)


run_transfer = _run_transfer

SOURCE_FIELDS = ["supplier_item_id", "catalog_sku", "category_path"]
MATCH_FIELDS = [
    "supplier_item_id",
    "catalog_sku",
    "catalog_product_id",
    "status",
    "confidence",
    "matched_by",
    "warnings",
]
CATEGORY_MAPPING_FIELDS = [
    "source_category_path",
    "source_total",
    "source_only_products",
    "exact_support",
    "suggested_category_ids",
    "suggested_categories",
    "dominant_support",
    "dominance_pct",
    "alternatives",
    "mapping_status",
    "publication_eligible",
]
PRODUCT_PROPOSAL_FIELDS = [
    "supplier_item_id",
    "catalog_sku",
    "name",
    "source_category_path",
    "suggested_category_ids",
    "suggested_categories",
    "mapping_status",
    "proposal_status",
    "publication_eligible",
]
FULL_SOURCE_FIELDS = [
    "supplier",
    "supplier_item_id",
    "catalog_sku",
    "supplier_sku",
    "manufacturer",
    "model",
    "mpn",
    "ean",
    "identity_warnings",
    "name",
    "category_id",
    "category_path",
    "source_price",
    "old_price",
    "currency",
    "quantity",
    "available",
    "store",
    "pickup",
    "delivery",
    "source_url",
    "image_urls",
    "description",
    "description_html",
    "properties",
    "content_provenance",
    "sales_notes",
    "manufacturer_warranty",
    "warranty_days",
    "vat",
    "weight",
    "dimensions",
    "attributes",
    "fetched_at",
    "raw_hash",
]


def _fresh_timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


CATEGORY_SQL = """\
CREATE TABLE `oc_category` (
  `category_id` int NOT NULL AUTO_INCREMENT,
  `image` varchar(255) DEFAULT NULL,
  `oct_image` varchar(255) DEFAULT NULL,
  `parent_id` int NOT NULL DEFAULT '0',
  `top` tinyint(1) NOT NULL,
  `column` int NOT NULL,
  `sort_order` int NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL,
  `page_group_links` text NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `noindex` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM;
CREATE TABLE `oc_category_description` (
  `category_id` int NOT NULL,
  `language_id` int NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `meta_title` varchar(255) NOT NULL,
  `meta_description` varchar(255) NOT NULL,
  `meta_keyword` varchar(255) NOT NULL,
  `meta_h1` varchar(255) DEFAULT NULL
) ENGINE=MyISAM;
INSERT INTO `oc_category` VALUES
(456,'','',0,1,1,-16,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1),
(457,'','',456,0,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1),
(537,'','',0,1,1,-9,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1),
(538,'','',537,0,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1),
(999,'','',0,1,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1);
INSERT INTO `oc_category_description` VALUES
(456,1,'Ноутбуки и компьютеры','','','','',''),
(457,1,'Ноутбуки','','','','',''),
(537,1,'Смартфоны,ТВ и электроника','','','','',''),
(538,1,'Смартфоны','','','','',''),
(999,1,'Другие','','','','','');
"""


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _full_row(item_id: str, sku: str, category_path: str, name: str) -> dict[str, str]:
    values = {field: "" for field in FULL_SOURCE_FIELDS}
    values.update(
        {
            "supplier": "netlab",
            "supplier_item_id": item_id,
            "catalog_sku": sku,
            "supplier_sku": item_id,
            "manufacturer": "Vendor",
            "model": "Model-1",
            "mpn": "MPN-1",
            "identity_warnings": "[]",
            "name": name,
            "category_id": "100",
            "category_path": category_path,
            "source_price": "10.25",
            "currency": "USD",
            "quantity": "3",
            "available": "True",
            "source_url": f"http://serv.netlab.ru/descr.asp?id={item_id}",
            "image_urls": "[\"https://nlimg.netlab.ru/image.jpg\"]",
            "description": "Plain <b>description</b>",
            "description_html": "Plain <b>description</b>",
            "properties": "[]",
            "content_provenance": "{}",
            "attributes": "{}",
            "fetched_at": _fresh_timestamp(),
            "raw_hash": "a" * 64,
        }
    )
    return values


def _write_manifest(tmp_path: Path, bundle: Path) -> Path:
    run_root = tmp_path / "sealed-run"
    run_root.mkdir()
    sealed_bundle = run_root / "source.zip"
    sealed_bundle.write_bytes(bundle.read_bytes())
    manifest = run_root / "run-manifest.json"
    selection_paths = {
        "normalized_source": tmp_path / "items.csv",
        "matches": tmp_path / "matches.csv",
        "category_mapping_proposals": tmp_path / "category-mapping-proposals.csv",
        "product_category_proposals": tmp_path / "product-category-proposals.csv",
        "category_snapshot": tmp_path / "site.sql",
    }
    sealed_selection_paths: dict[str, Path] = {}
    for role, path in selection_paths.items():
        sealed_path = run_root / path.name
        sealed_path.write_bytes(path.read_bytes())
        sealed_selection_paths[role] = sealed_path
    selection_inputs = {
        role: {
            "paths": [str(path.resolve())],
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for role, path in sealed_selection_paths.items()
        if path.is_file()
    }
    manifest.write_text(
        json.dumps(
            {
                "run_id": "source-run",
                "supplier": "netlab",
                "fetched_at": _fresh_timestamp(),
                "source_catalog_date": "2026-09-09 00:04",
                "code_identity": {"files": {"shadow.py": {"sha256": "a" * 64, "size": 1}}},
                "inputs": {
                    "source": {
                        "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                        "bundle_path": bundle.name,
                    }
                },
                "selection_inputs": selection_inputs,
                "policy": {"rates": {"USD": {"rub_per_unit": "86.19"}}},
            }
        ),
        encoding="utf-8",
    )
    integrity.build_run_seal(run_root)
    return manifest


def _write_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    snapshot = tmp_path / "site.sql"
    snapshot.write_text(CATEGORY_SQL, encoding="utf-8")
    source = tmp_path / "items.csv"
    _write_csv(
        source,
        FULL_SOURCE_FIELDS,
        [
            _full_row("1", "3111", '["Laptops"]', "Laptop"),
            _full_row("2", "3112", '["Phones"]', "Phone"),
            _full_row("3", "3113", '["Other"]', "Other"),
        ],
    )
    matches = tmp_path / "matches.csv"
    _write_csv(
        matches,
        MATCH_FIELDS,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "10",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            },
            {
                "supplier_item_id": "2",
                "catalog_sku": "3112",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            },
            {
                "supplier_item_id": "3",
                "catalog_sku": "3113",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            },
        ],
    )
    category_mapping = tmp_path / "category-mapping-proposals.csv"
    _write_csv(
        category_mapping,
        CATEGORY_MAPPING_FIELDS,
        [
            {
                "source_category_path": '["Laptops"]',
                "source_total": "3",
                "source_only_products": "0",
                "exact_support": "3",
                "suggested_category_ids": "457",
                "suggested_categories": "Ноутбуки",
                "dominant_support": "3",
                "dominance_pct": "100.0",
                "alternatives": "[{\"categories\": \"Ноутбуки\", \"category_ids\": \"457\", \"support\": 3}]",
                "mapping_status": "strong_candidate",
                "publication_eligible": "False",
            },
            {
                "source_category_path": '["Phones"]',
                "source_total": "3",
                "source_only_products": "1",
                "exact_support": "3",
                "suggested_category_ids": "538",
                "suggested_categories": "Смартфоны",
                "dominant_support": "3",
                "dominance_pct": "100.0",
                "alternatives": "[{\"categories\": \"Смартфоны\", \"category_ids\": \"538\", \"support\": 3}]",
                "mapping_status": "strong_candidate",
                "publication_eligible": "False",
            },
            {
                "source_category_path": '["Other"]',
                "source_total": "3",
                "source_only_products": "1",
                "exact_support": "3",
                "suggested_category_ids": "999",
                "suggested_categories": "Другие",
                "dominant_support": "3",
                "dominance_pct": "100.0",
                "alternatives": "[{\"categories\": \"Другие\", \"category_ids\": \"999\", \"support\": 3}]",
                "mapping_status": "strong_candidate",
                "publication_eligible": "False",
            },
        ],
    )
    product_proposals = tmp_path / "product-category-proposals.csv"
    _write_csv(
        product_proposals,
        PRODUCT_PROPOSAL_FIELDS,
        [
            {
                "supplier_item_id": "2",
                "catalog_sku": "3112",
                "name": "Phone",
                "source_category_path": '["Phones"]',
                "suggested_category_ids": "538",
                "suggested_categories": "Смартфоны",
                "mapping_status": "strong_candidate",
                "proposal_status": "review_only",
                "publication_eligible": "False",
            },
            {
                "supplier_item_id": "3",
                "catalog_sku": "3113",
                "name": "Other",
                "source_category_path": '["Other"]',
                "suggested_category_ids": "999",
                "suggested_categories": "Другие",
                "mapping_status": "strong_candidate",
                "proposal_status": "review_only",
                "publication_eligible": "False",
            },
        ],
    )
    return source, matches, category_mapping, product_proposals, snapshot


def _build_scoped_candidate(tmp_path: Path) -> Path:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    bundle = tmp_path / "source.zip"
    bundle.write_bytes(b"synthetic source bundle")
    manifest = _write_manifest(tmp_path, bundle)
    output = tmp_path / "candidate"
    assert run_transfer(
        [
            "--source",
            str(source),
            "--matches",
            str(matches),
            "--run-manifest",
            str(manifest),
            "--output-root",
            str(output),
            "--allow-incomplete-feed-staging",
            "--render-staging-sql",
            "--category-mapping-proposals",
            str(category_mapping),
            "--product-category-proposals",
            str(product_proposals),
            "--category-snapshot",
            str(snapshot),
        ]
    ) == 0
    return output


def _make_candidate_fixture_mutable(output: Path) -> None:
    for path in output.rglob("*"):
        if path.is_file() and not path.is_symlink():
            path.chmod(0o666)


def _refresh_candidate_manifest(output: Path) -> None:
    manifest_path = output / "CANDIDATE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        payload = (output / entry["path"]).read_bytes()
        entry["size"] = len(payload)
        entry["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest["candidate_id"] = transfer_script._candidate_identity(manifest)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _rewrite_selection_bindings(output: Path, mutate: callable) -> None:
    selection_path = output / "SELECTION_MANIFEST.jsonl"
    selection_rows = [json.loads(line) for line in selection_path.read_text(encoding="utf-8").splitlines()]
    records_path = output / "RECORDS.jsonl"
    records = [json.loads(line) for line in records_path.read_text(encoding="utf-8").splitlines()]
    for row in selection_rows:
        if row["supplier_item_id"] == "1":
            mutate(row)
    selection_bytes = b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        for row in selection_rows
    )
    selection_path.write_bytes(selection_bytes)
    selection_sha256 = hashlib.sha256(selection_bytes).hexdigest()
    for record in records:
        record["selection_manifest_sha256"] = selection_sha256
        if record["supplier_item_id"] == "1":
            mutate(record["selection_binding"])
    records_path.write_bytes(
        b"".join((json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8") for record in records)
    )
    for name in ("CATEGORY_SELECTION.json", "SUMMARY.json"):
        path = output / name
        value = json.loads(path.read_text(encoding="utf-8"))
        if name == "CATEGORY_SELECTION.json":
            value["selection_manifest_sha256"] = selection_sha256
        else:
            value["category_selection"]["selection_manifest_sha256"] = selection_sha256
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = output / "CANDIDATE_MANIFEST.json"
    candidate_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidate_manifest["selector"]["selection_manifest_sha256"] = selection_sha256
    manifest_path.write_text(
        json.dumps(candidate_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _refresh_candidate_manifest(output)


def test_selector_keeps_only_allowlisted_strong_mappings_and_conserves_counts(
    tmp_path: Path,
) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)

    result = select_two_category_items(
        source,
        matches,
        category_mapping,
        product_proposals,
        snapshot,
    )

    assert result.selected_supplier_item_ids == frozenset({"1", "2"})
    assert result.selected_root_counts == {"456": 1, "537": 1}
    assert result.source_rows_scanned == 3
    assert result.selected_count == 2
    assert result.exclusion_counts["target_outside_allowlist"] == 1
    assert sum(result.exclusion_counts.values()) + result.selected_count == result.source_rows_scanned
    assert {row["target_category_id"] for row in result.selection_manifest} == {457, 538}


def test_selector_rejects_inconsistent_exact_confidence(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    rows = list(csv.DictReader(matches.open(newline="", encoding="utf-8")))
    rows[0]["confidence"] = "0"
    _write_csv(matches, MATCH_FIELDS, rows)
    with pytest.raises(CategorySelectorError, match="exact match"):
        select_two_category_items(source, matches, category_mapping, product_proposals, snapshot)


def test_selector_rejects_non_dominant_strong_mapping(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    rows = list(csv.DictReader(category_mapping.open(encoding="utf-8", newline="")))
    rows[0]["dominance_pct"] = "99.0"
    _write_csv(category_mapping, CATEGORY_MAPPING_FIELDS, rows)
    with pytest.raises(CategorySelectorError, match="strong_candidate"):
        select_two_category_items(source, matches, category_mapping, product_proposals, snapshot)


def test_selector_rejects_publication_eligible_proposal(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    rows = list(csv.DictReader(category_mapping.open(encoding="utf-8", newline="")))
    rows[0]["publication_eligible"] = "True"
    _write_csv(category_mapping, CATEGORY_MAPPING_FIELDS, rows)

    with pytest.raises(CategorySelectorError, match="publication_eligible"):
        select_two_category_items(source, matches, category_mapping, product_proposals, snapshot)


def test_selector_rejects_exact_match_with_warning(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    rows = list(csv.DictReader(matches.open(encoding="utf-8", newline="")))
    rows[0]["warnings"] = '["model_mismatch"]'
    _write_csv(matches, MATCH_FIELDS, rows)

    with pytest.raises(CategorySelectorError, match="exact match warnings"):
        select_two_category_items(
            source,
            matches,
            category_mapping,
            product_proposals,
            snapshot,
        )


def test_selector_rejects_unmatched_match_with_product_id(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    rows = list(csv.DictReader(matches.open(encoding="utf-8", newline="")))
    rows[1]["catalog_product_id"] = "42"
    _write_csv(matches, MATCH_FIELDS, rows)

    with pytest.raises(CategorySelectorError, match="unmatched match"):
        select_two_category_items(
            source,
            matches,
            category_mapping,
            product_proposals,
            snapshot,
        )


def test_selector_rejects_extra_source_column(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    _write_csv(
        source,
        [*FULL_SOURCE_FIELDS, "unsupported_extra"],
        [{**_full_row("1", "3111", '["Laptops"]', "Laptop"), "unsupported_extra": "x"}],
    )

    with pytest.raises(CategorySelectorError, match="unsupported header"):
        select_two_category_items(source, matches, category_mapping, product_proposals, snapshot)


def test_snapshot_rejects_reordered_table_ddl(tmp_path: Path) -> None:
    snapshot = tmp_path / "site.sql"
    reordered = CATEGORY_SQL.replace(
        "  `category_id` int NOT NULL AUTO_INCREMENT,\n  `image` varchar(255) DEFAULT NULL,",
        "  `image` varchar(255) DEFAULT NULL,\n  `category_id` int NOT NULL AUTO_INCREMENT,",
    )
    snapshot.write_text(reordered, encoding="utf-8")

    with pytest.raises(CategorySelectorError, match="DDL"):
        build_category_tree_snapshot(snapshot)


def test_snapshot_rejects_explicit_column_list(tmp_path: Path) -> None:
    snapshot = tmp_path / "site.sql"
    snapshot.write_text(
        CATEGORY_SQL.replace(
            "INSERT INTO `oc_category` VALUES",
            "INSERT INTO `oc_category` (`category_id`, `name`) VALUES",
        ),
        encoding="utf-8",
    )

    with pytest.raises(CategorySelectorError, match="column list"):
        build_category_tree_snapshot(snapshot)


def test_candidate_failure_does_not_leave_partial_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    bundle = tmp_path / "source.zip"
    bundle.write_bytes(b"synthetic source bundle")
    manifest = _write_manifest(tmp_path, bundle)
    output = tmp_path / "candidate"

    def fail_identity(*args: object, **kwargs: object) -> dict[str, object]:
        raise transfer_script.TransferError("forced identity failure")

    monkeypatch.setattr(transfer_script, "_input_identity", fail_identity)
    assert run_transfer(
        [
            "--source",
            str(source),
            "--matches",
            str(matches),
            "--run-manifest",
            str(manifest),
            "--output-root",
            str(output),
            "--allow-incomplete-feed-staging",
            "--render-staging-sql",
            "--category-mapping-proposals",
            str(category_mapping),
            "--product-category-proposals",
            str(product_proposals),
            "--category-snapshot",
            str(snapshot),
        ]
    ) == 2
    assert not output.exists()


def test_candidate_cleanup_error_preserves_original_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    run_manifest = tmp_path / "run-manifest.json"
    for path in (source, matches, run_manifest):
        path.write_bytes(b"x")
    policy = SimpleNamespace(
        selection_manifest_sha256=None,
        selected_supplier_item_ids=None,
        source_artifact_path=None,
        run_manifest_sha256=None,
        run_manifest_provenance=None,
    )
    plan = SimpleNamespace(
        policy=policy,
        source_path=source,
        matches_path=matches,
        source_artifact_sha256="a" * 64,
        matches_artifact_sha256="b" * 64,
    )

    monkeypatch.setattr(transfer_script, "_input_identity", lambda *_args, **_kwargs: {})
    def fail_writer(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("original writer failure")

    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise OSError("cleanup failure")

    monkeypatch.setattr(transfer_script, "_write_candidate_contents", fail_writer)
    monkeypatch.setattr(transfer_script.shutil, "rmtree", fail_cleanup)
    with pytest.raises(RuntimeError, match="original writer failure"):
        transfer_script._write_candidate(
            tmp_path / "candidate",
            plan,
            render_staging_sql=False,
            run_manifest_path=run_manifest,
        )


def test_manifest_and_input_identity_reject_symlinks(tmp_path: Path) -> None:
    real_bundle = tmp_path / "source.zip"
    real_bundle.write_bytes(b"synthetic source bundle")
    bundle_link = tmp_path / "source-link.zip"
    try:
        bundle_link.symlink_to(real_bundle)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")
    manifest = _write_manifest(tmp_path, bundle_link)

    with pytest.raises(transfer_script.TransferError, match="symlink"):
        transfer_script._manifest_policy(manifest)
    with pytest.raises(transfer_script.TransferError, match="regular file"):
        transfer_script._input_identity(
            bundle_link,
            expected_sha256=hashlib.sha256(real_bundle.read_bytes()).hexdigest(),
        )


def test_cli_writes_scope_bound_candidate_manifest(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    _write_csv(
        source,
        FULL_SOURCE_FIELDS,
        [
            _full_row("1", "3111", '["Laptops"]', "Laptop"),
            _full_row("2", "3112", '["Phones"]', "Phone"),
            _full_row("3", "3113", '["Other"]', "Other"),
        ],
    )
    bundle = tmp_path / "source.zip"
    bundle.write_bytes(b"synthetic source bundle")
    manifest = _write_manifest(tmp_path, bundle)
    output = tmp_path / "candidate"

    assert run_transfer(
        [
            "--source",
            str(source),
            "--matches",
            str(matches),
            "--run-manifest",
            str(manifest),
            "--output-root",
            str(output),
            "--allow-incomplete-feed-staging",
            "--render-staging-sql",
            "--category-mapping-proposals",
            str(category_mapping),
            "--product-category-proposals",
            str(product_proposals),
            "--category-snapshot",
            str(snapshot),
        ]
    ) == 0

    candidate_manifest = json.loads((output / "CANDIDATE_MANIFEST.json").read_text(encoding="utf-8"))
    selection_summary = json.loads((output / "CATEGORY_SELECTION.json").read_text(encoding="utf-8"))
    summary = json.loads((output / "SUMMARY.json").read_text(encoding="utf-8"))
    records = [json.loads(line) for line in (output / "RECORDS.jsonl").read_text(encoding="utf-8").splitlines()]
    assert candidate_manifest["schema_version"] == 2
    assert summary["source_path"] == str(tmp_path / "sealed-run" / "items.csv")
    assert not any(path.name.startswith(".netlab-inputs-") for path in tmp_path.iterdir())
    assert candidate_manifest["run_manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert candidate_manifest["selector"]["counts"]["selected_total"] == 2
    assert candidate_manifest["selector"]["transfer_counts"] == {
        "selected_rows": 2,
        "written_records": 2,
        "transfer_exceptions": 0,
    }
    assert summary["category_selection"]["counts"]["selected_total"] == 2
    assert candidate_manifest["selector"]["counts"]["selected_root_counts"] == {"456": 1, "537": 1}
    assert selection_summary["selection_manifest_sha256"] == candidate_manifest["selector"]["selection_manifest_sha256"]
    assert selection_summary["selection_manifest_sha256"] == hashlib.sha256(
        (output / "SELECTION_MANIFEST.jsonl").read_bytes()
    ).hexdigest()
    assert {record["selection_manifest_sha256"] for record in records} == {
        selection_summary["selection_manifest_sha256"]
    }
    assert len(records) == 2
    assert all("selection_binding" in record for record in records)
    assert {record["selection_binding"]["target_category_id"] for record in records} == {457, 538}
    validate_candidate_operation_set(
        (output / "APPLY_STAGING.sql").read_text(encoding="utf-8"),
        records,
    )
    validate_candidate_bundle(
        output / "APPLY_STAGING.sql",
        trusted_run_manifest=manifest,
        expected_trusted_run_seal_sha256=integrity.load_sealed_run(
            manifest.parent, read_content=False
        ).seal_evidence.sha256,
    )
    assert {entry["path"] for entry in candidate_manifest["files"]} >= {
        "CATEGORY_SELECTION.json",
        "SELECTION_MANIFEST.jsonl",
        "APPLY_STAGING.sql",
    }
    assert candidate_manifest["inputs"]["category_snapshot"]["sha256"] == hashlib.sha256(
        snapshot.read_bytes()
    ).hexdigest()


def test_scoped_sql_writes_selected_category_relations(tmp_path: Path) -> None:
    output = _build_scoped_candidate(tmp_path)

    sql = (output / "APPLY_STAGING.sql").read_text(encoding="utf-8")

    assert "INSERT INTO `oc_product_to_category`" in sql
    assert "457" in sql
    assert "538" in sql
    assert (
        "SELECT 10, 457 WHERE @netlab_transfer_product_rows=1 "
        "AND @netlab_transfer_description_rows=1"
    ) in sql


def test_candidate_validation_rechecks_source_freshness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _build_scoped_candidate(tmp_path)
    stale_now = datetime.now(UTC) + timedelta(hours=25)
    monkeypatch.setattr(staging_apply, "_utc_now", lambda: stale_now, raising=False)

    with pytest.raises(StagingApplyError, match="older than 24 hours|freshness"):
        validate_candidate_bundle(
            output / "APPLY_STAGING.sql",
            trusted_run_manifest=tmp_path / "sealed-run" / "run-manifest.json",
            expected_trusted_run_seal_sha256=integrity.load_sealed_run(
                tmp_path / "sealed-run", read_content=False
            ).seal_evidence.sha256,
        )


def test_verifier_requires_trusted_selector_input_seal(tmp_path: Path) -> None:
    output = _build_scoped_candidate(tmp_path)
    _make_candidate_fixture_mutable(output)
    manifest_path = output / "CANDIDATE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["inputs"]["normalized_source"]["sha256"] = "b" * 64
    manifest["candidate_id"] = transfer_script._candidate_identity(manifest)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(StagingApplyError, match="seal|immutable"):
        validate_candidate_bundle(
            output / "APPLY_STAGING.sql",
            trusted_run_manifest=tmp_path / "sealed-run" / "run-manifest.json",
            expected_trusted_run_seal_sha256=integrity.load_sealed_run(
                tmp_path / "sealed-run", read_content=False
            ).seal_evidence.sha256,
        )


def test_verifier_rejects_identical_input_outside_trusted_seal(tmp_path: Path) -> None:
    output = _build_scoped_candidate(tmp_path)
    _make_candidate_fixture_mutable(output)
    manifest_path = output / "CANDIDATE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    outside = tmp_path / "outside-items.csv"
    outside.write_bytes((tmp_path / "sealed-run" / "items.csv").read_bytes())
    manifest["inputs"]["normalized_source"]["paths"] = [str(outside.resolve())]
    manifest["candidate_id"] = transfer_script._candidate_identity(manifest)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(StagingApplyError, match="sealed|trusted|verified immutable"):
        validate_candidate_bundle(
            output / "APPLY_STAGING.sql",
            trusted_run_manifest=tmp_path / "sealed-run" / "run-manifest.json",
            expected_trusted_run_seal_sha256=integrity.load_sealed_run(
                tmp_path / "sealed-run", read_content=False
            ).seal_evidence.sha256,
        )


def test_verifier_reconstructs_selection_from_bound_inputs(tmp_path: Path) -> None:
    output = _build_scoped_candidate(tmp_path)
    _make_candidate_fixture_mutable(output)
    _rewrite_selection_bindings(
        output,
        lambda row: row.__setitem__("source_row_sha256", "f" * 64),
    )

    with pytest.raises(StagingApplyError, match="seal|immutable"):
        validate_candidate_bundle(
            output / "APPLY_STAGING.sql",
            trusted_run_manifest=tmp_path / "sealed-run" / "run-manifest.json",
            expected_trusted_run_seal_sha256=integrity.load_sealed_run(
                tmp_path / "sealed-run", read_content=False
            ).seal_evidence.sha256,
        )


def test_verifier_rejects_target_outside_claimed_root_descendants(tmp_path: Path) -> None:
    output = _build_scoped_candidate(tmp_path)
    _make_candidate_fixture_mutable(output)
    _rewrite_selection_bindings(
        output,
        lambda row: row.__setitem__("target_category_id", 999),
    )

    with pytest.raises(StagingApplyError, match="seal|immutable"):
        validate_candidate_bundle(
            output / "APPLY_STAGING.sql",
            trusted_run_manifest=tmp_path / "sealed-run" / "run-manifest.json",
            expected_trusted_run_seal_sha256=integrity.load_sealed_run(
                tmp_path / "sealed-run", read_content=False
            ).seal_evidence.sha256,
        )


def test_selector_rejects_duplicate_conflicting_product_proposal(tmp_path: Path) -> None:
    source, matches, category_mapping, product_proposals, snapshot = _write_fixture(tmp_path)
    with product_proposals.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PRODUCT_PROPOSAL_FIELDS)
        writer.writerow(
            {
                "supplier_item_id": "2",
                "catalog_sku": "3112",
                "name": "Phone",
                "source_category_path": '["Phones"]',
                "suggested_category_ids": "457",
                "suggested_categories": "Ноутбуки",
                "mapping_status": "strong_candidate",
                "proposal_status": "review_only",
                "publication_eligible": "False",
            }
        )

    with pytest.raises(CategorySelectorError, match="duplicate|conflicting"):
        select_two_category_items(
            source,
            matches,
            category_mapping,
            product_proposals,
            snapshot,
        )


def test_snapshot_ignores_unrelated_orphan_category(tmp_path: Path) -> None:
    snapshot = tmp_path / "site.sql"
    orphan = "(1000,'','',888,0,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1),"
    snapshot.write_text(CATEGORY_SQL.replace("(999,'','',0,1,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1);", orphan + "(999,'','',0,1,1,0,1,'','2022-01-01 00:00:00','2022-01-01 00:00:00',1);"), encoding="utf-8")

    result = build_category_tree_snapshot(snapshot)

    assert result.descendant_ids == (456, 457, 537, 538)


def test_category_snapshot_requires_literal_root_names(tmp_path: Path) -> None:
    snapshot = tmp_path / "site.sql"
    snapshot.write_text(CATEGORY_SQL.replace("Ноутбуки и компьютеры", "Wrong root"), encoding="utf-8")

    with pytest.raises(CategorySelectorError, match="root.*name"):
        build_category_tree_snapshot(snapshot)
