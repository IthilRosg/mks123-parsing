from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mks123_pipeline import integrity
from mks123_pipeline.netlab_staging_apply import validate_candidate_operation_set
from mks123_pipeline.netlab_transfer import (
    TransferConfig,
    TransferError,
    _sanitize_description_html,
    _source_attribute_rows,
    build_transfer_plan,
    render_sql,
    validate_source_freshness,
)
from scripts import run_netlab_transfer as transfer_script
from scripts.run_netlab_transfer import (
    _load_attribute_mapping,
    _path_variants_from_resolved,
    _record_json,
)


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

HEADER = [
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


def _write_source(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _row(item_id: str, sku: str, *, name: str = "Netlab item") -> dict[str, object]:
    values = {field: "" for field in HEADER}
    values.update(
        supplier="netlab",
        supplier_item_id=item_id,
        catalog_sku=sku,
        supplier_sku=item_id,
        manufacturer="Vendor",
        model="Model-1",
        mpn="MPN-1",
        ean="",
        identity_warnings="[]",
        name=name,
        category_id="100",
        category_path='["Parent", "Child"]',
        source_price="10.25",
        currency="USD",
        quantity="3",
        available="True",
        source_url=f"http://serv.netlab.ru/descr.asp?id={item_id}",
        image_urls='["https://nlimg.netlab.ru/image.jpg"]',
        description="Plain <b>description</b>",
        description_html="Plain <b>description</b>",
        properties='[{"property_id":"p1","property_name":"Color","value":"Black"}]',
        content_provenance='{"source":"GoodsProperties.zip"}',
        warranty_days="365",
        vat="included",
        weight="1.2",
        dimensions="10.0 x 20.0 x 30.0",
        attributes='{"@id":"' + item_id + '"}',
        fetched_at="2026-09-08T21:12:34+00:00",
        raw_hash="a" * 64,
    )
    return values


def test_source_attribute_rows_maps_only_nonmissing_source_fields() -> None:
    properties = json.dumps([
        {"property_name": "<b>Основные характеристики</b>", "value": "-", "missing": True},
        {"property_name": "Производитель", "value": "CBR", "missing": False},
        {"property_name": "Описание", "value": "short", "missing": False},
        {"property_name": "Цвет", "value": "черный", "missing": False},
        {"property_name": "Пустое", "value": "-", "missing": True},
    ])

    rows, unmapped = _source_attribute_rows(
        properties,
        {"Производитель": 9422, "Цвет": 7304, "Пустое": 9999},
    )

    assert rows == ((9422, "CBR"), (7304, "черный"))
    assert unmapped == ()


def test_source_attribute_rows_reports_unmapped_without_guessing() -> None:
    properties = json.dumps([
        {"property_name": "Совместимые устройства", "value": "Printer X", "missing": False},
    ])

    rows, unmapped = _source_attribute_rows(properties, {"Модель": 9423})

    assert rows == ()
    assert unmapped == ("Совместимые устройства",)


def test_source_attribute_rows_keeps_definition_missing_fields_in_provenance() -> None:
    properties = json.dumps([
        {"property_id": "unknown", "definition_missing": True, "value": "opaque source value"},
        {"property_name": "Модель", "value": "Model X", "missing": False},
    ])

    rows, unmapped = _source_attribute_rows(properties, {"Модель": 9423})

    assert rows == ((9423, "Model X"),)
    assert unmapped == ()


def _write_matches(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "supplier_item_id",
                "catalog_sku",
                "catalog_product_id",
                "status",
                "confidence",
                "matched_by",
                "warnings",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def test_render_sql_writes_mapped_attributes_only_when_mapping_enabled(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(matches, [{"supplier_item_id": "1", "catalog_sku": "3111", "catalog_product_id": "", "status": "unmatched", "confidence": "0", "matched_by": "", "warnings": "[]"}])
    config = TransferConfig(
        usd_rub_rate="86.19",
        allow_staging_apply=True,
        attribute_mapping={"Color": 7304},
        attribute_mapping_sha256="a" * 64,
        attribute_mapping_path="/tmp/attribute-mapping.json",
        attribute_mapping_artifact_sha256="b" * 64,
        attribute_mapping_database="mks123_stage_rehearsal_20260914",
        attribute_mapping_language_id=1,
        attribute_mapping_scope_skus=frozenset({"3111"}),
    )

    plan = build_transfer_plan(source, matches, config=config)
    sql = render_sql(plan, mode="apply_staging", transferred_at="2026-09-10 23:30:00")

    assert "oc_product_attribute" in sql
    assert "7304" in sql
    assert "426c61636b" in sql


def test_attribute_mapping_requires_complete_provenance(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(matches, [{"supplier_item_id": "1", "catalog_sku": "3111", "catalog_product_id": "", "status": "unmatched", "confidence": "0", "matched_by": "", "warnings": "[]"}])
    with pytest.raises(TransferError, match="all provenance fields"):
        build_transfer_plan(
            source,
            matches,
            config=TransferConfig(allow_staging_apply=True, attribute_mapping={"Color": 7304}),
        )


def test_attribute_mapping_rejects_boolean_or_duplicate_target_ids(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(matches, [{"supplier_item_id": "1", "catalog_sku": "3111", "catalog_product_id": "", "status": "unmatched", "confidence": "0", "matched_by": "", "warnings": "[]"}])
    common = {
        "allow_staging_apply": True,
        "attribute_mapping_sha256": "a" * 64,
        "attribute_mapping_path": "/tmp/attribute-mapping.json",
        "attribute_mapping_artifact_sha256": "b" * 64,
        "attribute_mapping_database": "mks123_stage_rehearsal_20260914",
        "attribute_mapping_language_id": 1,
        "attribute_mapping_scope_skus": frozenset({"3111"}),
    }
    with pytest.raises(TransferError, match="invalid"):
        build_transfer_plan(source, matches, config=TransferConfig(attribute_mapping={"Color": True}, **common))
    with pytest.raises(TransferError, match="reuses target ID"):
        build_transfer_plan(source, matches, config=TransferConfig(attribute_mapping={"Color": 7304, "Shade": 7304}, **common))


def test_attribute_mapping_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "mapping.json"
    path.write_text('{"attributes":{"Color":7304,"Color":9999}}', encoding="utf-8")
    with pytest.raises(TransferError, match="duplicate object key"):
        _load_attribute_mapping(path)


def test_plan_separates_exact_updates_and_unmatched_creates(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111"), _row("2", "3112")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
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
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19", markup_multiplier="1.1"),
    )

    assert plan.update_count == 1
    assert plan.create_count == 1
    assert plan.relations_created == 0
    assert plan.updates[0].target_product_id == 42
    assert plan.creates[0].target_sku == "3112"
    assert plan.creates[0].verification_status == "transferred_unverified"


def test_default_config_cannot_render_mutating_sql(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19"),
    )

    with pytest.raises(TransferError, match="apply_staging"):
        render_sql(plan, mode="preview")


def test_non_default_language_is_semantically_bound(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )
    config = TransferConfig(
        usd_rub_rate="86.19",
        allow_staging_apply=True,
        language_id=7,
        transferred_at="2026-09-10 23:30:00",
    )
    plan = build_transfer_plan(source, matches, config=config)
    sql = render_sql(plan, mode="apply_staging")
    record = _record_json(plan.updates[0], run_id=plan.run_id, transferred_at=config.transferred_at)
    record.update(
        source_artifact_path=str(plan.source_path),
        source_artifact_sha256=plan.source_artifact_sha256,
        matches_artifact_sha256=plan.matches_artifact_sha256,
    )

    validate_candidate_operation_set(sql, [record])
    assert "`language_id`=7" in sql


def test_sql_contains_provenance_and_no_compatibility_relation(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )
    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(
            usd_rub_rate="86.19", markup_multiplier="1.1", allow_staging_apply=True
        ),
    )

    sql = render_sql(plan, mode="apply_staging")

    assert "oc_netlab_transfer_audit" in sql
    assert "source_kind" in sql
    assert "7472616e736665727265645f756e7665726966696564" in sql
    assert "product_related" not in sql
    assert "product_compatibility" not in sql
    assert "INSERT INTO `oc_product_to_category`" not in sql


def test_duplicate_source_sku_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111"), _row("2", "3111")])
    _write_matches(matches, [])

    with pytest.raises(TransferError, match="duplicate"):
        build_transfer_plan(source, matches, config=TransferConfig())


def test_conflict_and_ambiguous_rows_are_not_written(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111"), _row("2", "3112")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "conflict",
                "confidence": "0.5",
                "matched_by": "sku",
                "warnings": '["model_mismatch"]',
            },
            {
                "supplier_item_id": "2",
                "catalog_sku": "3112",
                "catalog_product_id": "43",
                "status": "ambiguous",
                "confidence": "0.5",
                "matched_by": "ean",
                "warnings": '["duplicate_ean"]',
            },
        ],
    )

    plan = build_transfer_plan(source, matches, config=TransferConfig())

    assert plan.update_count == 0
    assert plan.create_count == 0
    assert {item.reason for item in plan.exceptions} == {"conflict", "ambiguous"}


def test_target_schema_limit_is_quarantined_per_item(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    oversized = _row("1", "3111")
    oversized["name"] = "Я" * 256
    valid = _row("2", "3112")
    _write_source(source, [oversized, valid])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": item_id,
                "catalog_sku": sku,
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
            for item_id, sku in (("1", "3111"), ("2", "3112"))
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19"),
    )

    assert plan.create_count == 1
    assert plan.creates[0].target_sku == "3112"
    assert [(item.catalog_sku, item.reason) for item in plan.exceptions] == [
        ("3111", "target_schema_limit")
    ]


def test_utf8_bom_headers_are_supported(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )
    matches.write_bytes(b"\xef\xbb\xbf" + matches.read_bytes())

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19"),
    )

    assert plan.create_count == 1


def test_description_is_sanitized_but_raw_source_is_retained(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111")
    row["description_html"] = '<b>Keep</b><script>alert("x")</script><img src="x">'
    _write_source(source, [row])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19"),
    )

    payload = plan.updates[0].target_payload
    assert payload["description"] == "<b>Keep</b>"
    assert '<script>' in json.loads(plan.updates[0].source.source_snapshot_json)["description_html"]


def test_sanitizer_keeps_text_after_void_dropped_tag(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111")
    row["description_html"] = '<p>before</p><img src="x"><p>after</p>'
    _write_source(source, [row])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(source, matches, config=TransferConfig(usd_rub_rate="86.19"))

    assert plan.updates[0].target_payload["description"] == "<p>before</p><p>after</p>"


def test_sanitizer_does_not_nest_void_drop_tags() -> None:
    assert _sanitize_description_html(
        "<object><img src='x'></object><p>safe</p>"
    ) == "<p>safe</p>"


def test_model_schema_limit_is_quarantined_per_item(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    oversized = _row("1", "3111")
    oversized["model"] = "M" * 65
    valid = _row("2", "3112")
    _write_source(source, [oversized, valid])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": item_id,
                "catalog_sku": sku,
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
            for item_id, sku in (("1", "3111"), ("2", "3112"))
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19"),
    )

    assert plan.create_count == 1
    assert plan.creates[0].target_sku == "3112"
    assert [(item.catalog_sku, item.reason) for item in plan.exceptions] == [
        ("3111", "target_schema_limit")
    ]


def test_audit_schema_limits_are_quarantined_per_item(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111")
    row["fetched_at"] = "A" * 65
    _write_source(source, [row])
    _write_matches(
        matches,
        [{
            "supplier_item_id": "1",
            "catalog_sku": "3111",
            "catalog_product_id": "42",
            "status": "exact",
            "confidence": "1.00",
            "matched_by": "sku",
            "warnings": "[]",
        }],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19", allow_staging_apply=True),
    )

    assert plan.update_count == 0
    assert plan.exceptions[0].reason == "target_schema_limit"
    assert "fetched_at" in plan.exceptions[0].detail


def test_target_text_limits_use_database_character_semantics(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111", name="Ж" * 255)
    row["model"] = "Ж" * 64
    row["mpn"] = "Ж" * 64
    _write_source(source, [row])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(source, matches, config=TransferConfig(usd_rub_rate="86.19"))

    assert plan.create_count == 1
    assert len(plan.creates[0].target_payload["name"]) == 255
    assert len(plan.creates[0].target_payload["model"]) == 64
    assert len(plan.creates[0].target_payload["mpn"]) == 64


def test_target_text_rejects_utf8mb4_only_characters(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111", name="A" * 250 + "😀")
    _write_source(source, [row])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(source, matches, config=TransferConfig(usd_rub_rate="86.19"))

    assert plan.create_count == 0
    assert [(item.catalog_sku, item.reason) for item in plan.exceptions] == [
        ("3111", "target_schema_limit")
    ]


def test_empty_update_description_is_preserved_in_sql(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    row = _row("1", "3111")
    row["description"] = ""
    row["description_html"] = ""
    _write_source(source, [row])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19", allow_staging_apply=True),
    )
    sql = render_sql(plan, mode="apply_staging")

    assert "`description`=" not in sql
    assert "UPDATE `oc_product_description` SET `name`=" in sql
    assert (
        "AND EXISTS (SELECT 1 FROM `oc_product` AS p WHERE p.`product_id`=42 "
        "AND p.`sku`=CONVERT(0x33313131 USING utf8mb4));"
    ) in sql


def test_cli_run_id_binds_selection_policy(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    bundle = tmp_path / "source.zip"
    run_root = tmp_path / "sealed-run"
    run_root.mkdir()
    sealed_bundle = run_root / "source.zip"
    manifest = run_root / "run-manifest.json"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )
    bundle.write_bytes(b"synthetic source bundle")
    sealed_bundle.write_bytes(bundle.read_bytes())
    manifest.write_text(
        json.dumps(
            {
                "run_id": "source-run",
                "supplier": "netlab",
                "inputs": {
                    "source": {
                        "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                        "bundle_path": bundle.name,
                    }
                },
                "policy": {"rates": {"USD": {"rub_per_unit": "86.19"}}},
            }
        ),
        encoding="utf-8",
    )
    integrity.build_run_seal(run_root)

    assert run_transfer(
        [
            "--source",
            str(source),
            "--matches",
            str(matches),
            "--run-manifest",
            str(manifest),
            "--output-root",
            str(tmp_path / "candidate-updates"),
            "--updates-limit",
            "1",
            "--creates-limit",
            "0",
            "--allow-incomplete-feed-staging",
            "--render-staging-sql",
        ]
    ) == 0
    assert run_transfer(
        [
            "--source",
            str(source),
            "--matches",
            str(matches),
            "--run-manifest",
            str(manifest),
            "--output-root",
            str(tmp_path / "candidate-empty"),
            "--updates-limit",
            "0",
            "--creates-limit",
            "0",
            "--allow-incomplete-feed-staging",
            "--render-staging-sql",
        ]
    ) == 0

    first = json.loads((tmp_path / "candidate-updates" / "SUMMARY.json").read_text(encoding="utf-8"))
    second = json.loads((tmp_path / "candidate-empty" / "SUMMARY.json").read_text(encoding="utf-8"))
    assert first["run_id"] != second["run_id"]


def test_cli_rejects_explicit_run_id_not_bound_to_selection(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    bundle = tmp_path / "source.zip"
    manifest = tmp_path / "run-manifest.json"
    _write_source(source, [_row("1", "3111")])
    _write_matches(matches, [{"supplier_item_id": "1", "catalog_sku": "3111", "catalog_product_id": "42", "status": "exact", "confidence": "1.00", "matched_by": "sku", "warnings": "[]"}])
    bundle.write_bytes(b"synthetic source bundle")
    manifest.write_text(json.dumps({"run_id": "source-run", "supplier": "netlab", "inputs": {"source": {"sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(), "bundle_path": bundle.name}}, "policy": {"rates": {"USD": {"rub_per_unit": "86.19"}}}}), encoding="utf-8")

    assert run_transfer([
        "--source", str(source), "--matches", str(matches), "--run-manifest", str(manifest),
        "--output-root", str(tmp_path / "candidate"), "--updates-limit", "1", "--creates-limit", "0",
        "--allow-incomplete-feed-staging", "--render-staging-sql", "--run-id", "arbitrary-run",
    ]) == 2


def test_path_variants_are_bidirectional_for_wsl_paths() -> None:
    variants = _path_variants_from_resolved("/mnt/d/ServerBackups/netlab/source.zip")

    assert "/mnt/d/ServerBackups/netlab/source.zip" in variants
    assert "D:\\ServerBackups\\netlab\\source.zip" in variants


def test_selection_manifest_ids_must_match_explicit_selection(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )

    with pytest.raises(TransferError, match="selection manifest IDs"):
        build_transfer_plan(
            source,
            matches,
            config=TransferConfig(
                usd_rub_rate="86.19",
                selected_supplier_item_ids=frozenset({"1"}),
                selection_manifest_sha256="a" * 64,
                selection_manifest_supplier_item_ids=frozenset({"2"}),
            ),
        )


def test_none_and_empty_selection_have_distinct_run_identity(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )

    all_plan = build_transfer_plan(source, matches, config=TransferConfig(usd_rub_rate="86.19"))
    empty_plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19", selected_supplier_item_ids=frozenset()),
    )

    assert all_plan.run_id != empty_plan.run_id


def test_rendered_dml_has_matched_row_guard_before_audit(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "42",
                "status": "exact",
                "confidence": "1.00",
                "matched_by": "sku",
                "warnings": "[]",
            }
        ],
    )
    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(usd_rub_rate="86.19", allow_staging_apply=True),
    )
    sql = render_sql(plan, mode="apply_staging")

    assert "ROW_COUNT()" not in sql
    assert "SET @netlab_transfer_product_rows = (SELECT COUNT(*) FROM `oc_product`" in sql
    assert "SET @netlab_transfer_description_rows = (SELECT COUNT(*) FROM `oc_product_description`" in sql
    assert "@netlab_transfer_product_rows" in sql
    assert "@netlab_transfer_description_rows" in sql
    assert "`target_product_id` INT NOT NULL" in sql
    assert "IF(@netlab_transfer_product_rows=1 AND @netlab_transfer_description_rows=1" in sql


def test_incomplete_feed_needs_explicit_staging_override(tmp_path: Path) -> None:
    source = tmp_path / "items.csv"
    matches = tmp_path / "matches.csv"
    _write_source(source, [_row("1", "3111")])
    _write_matches(
        matches,
        [
            {
                "supplier_item_id": "1",
                "catalog_sku": "3111",
                "catalog_product_id": "",
                "status": "unmatched",
                "confidence": "0",
                "matched_by": "",
                "warnings": "[]",
            }
        ],
    )

    with pytest.raises(TransferError, match="incomplete feed"):
        build_transfer_plan(
            source,
            matches,
            config=TransferConfig(feed_complete=False, allow_staging_apply=True),
        )

    plan = build_transfer_plan(
        source,
        matches,
        config=TransferConfig(
            feed_complete=False,
            allow_staging_apply=True,
            allow_incomplete_feed_for_staging=True,
            usd_rub_rate="86.19",
        ),
    )
    assert plan.create_count == 1
    assert plan.feed_override == "staging_only_incomplete_feed"


def test_source_freshness_rejects_stale_and_future_values() -> None:
    now = datetime(2026, 9, 10, 23, 30, tzinfo=UTC)

    with pytest.raises(TransferError, match="older than 24 hours"):
        validate_source_freshness("2026-09-09T23:29:59+00:00", now=now)
    with pytest.raises(TransferError, match="future"):
        validate_source_freshness("2026-09-10T23:46:00+00:00", now=now)
    with pytest.raises(TransferError, match="ISO-8601"):
        validate_source_freshness("not-a-timestamp", now=now)

    accepted = validate_source_freshness("2026-09-09T23:30:00+00:00", now=now)
    assert accepted == datetime(2026, 9, 9, 23, 30, tzinfo=UTC)
    local = validate_source_freshness("2026-09-11 02:30:00", now=now)
    assert local == now
