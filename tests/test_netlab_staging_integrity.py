from __future__ import annotations

import hashlib
import inspect
import json
import os
import queue
import sys
import textwrap
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import mks123_pipeline.netlab_staging_apply as staging_apply
from mks123_pipeline import trusted_run, two_category_selector
from mks123_pipeline.integrity import build_run_seal
from mks123_pipeline.netlab_staging_apply import (
    StagingApplyError,
    StagingTarget,
    _decode_hex_fields,
    _number_value,
    _readback,
    validate_candidate_file,
    validate_candidate_operation_set,
    validate_candidate_sql,
)
from mks123_pipeline.netlab_transfer import (
    MatchRecord,
    SourceItem,
    TransferConfig,
    TransferError,
    TransferPlan,
    TransferRecord,
    _canonical_json,
    _target_payload,
    render_sql,
)
from mks123_pipeline.trusted_run import TrustedRunError, load_trusted_run_manifest
from scripts import run_netlab_transfer as transfer_script


def _price_source_item(source_price: str) -> SourceItem:
    values = {
        "supplier": "netlab",
        "supplier_item_id": "1",
        "catalog_sku": "3111",
        "supplier_sku": "3111",
        "manufacturer": "Vendor",
        "model": "Model-1",
        "mpn": "MPN-1",
        "ean": "",
        "name": "Netlab item",
        "description": "",
        "description_html": "",
        "source_price": source_price,
        "currency": "USD",
        "quantity": "1",
        "available": "True",
        "source_url": "",
        "fetched_at": "2026-09-15T06:27:22+00:00",
        "raw_hash": "a" * 64,
        "category_id": "100",
        "category_path": "[]",
        "image_urls": "[]",
        "properties": "[]",
        "attributes": "{}",
    }
    return SourceItem(values=values, source_snapshot_json="{}", payload_sha256="a" * 64)


def test_target_price_is_quantized_to_staging_decimal_scale() -> None:
    payload = _target_payload(
        _price_source_item("1.23456"),
        TransferConfig(usd_rub_rate="1", markup_multiplier="1"),
    )
    assert payload["price"] == "1.2346"

    with pytest.raises(TransferError, match=r"DECIMAL\(15,4\)"):
        _target_payload(
            _price_source_item("100000000000"),
            TransferConfig(usd_rub_rate="1", markup_multiplier="1"),
        )
    for source_price, rate, multiplier in (
        ("1e999999999", "1", "1"),
        ("1", "1e999999999", "1"),
        ("1", "1", "1e999999999"),
    ):
        with pytest.raises(TransferError, match=r"DECIMAL\(15,4\)"):
            _target_payload(
                _price_source_item(source_price),
                TransferConfig(usd_rub_rate=rate, markup_multiplier=multiplier),
            )


def test_numeric_canonicalization_preserves_integer_zeroes_and_bounds() -> None:
    assert _number_value("1") == ("number", "1")
    assert _number_value("10") == ("number", "10")
    assert _number_value("100") == ("number", "100")
    assert _number_value("100.0100") == ("number", "100.01")
    assert _number_value("-0.00") == ("number", "0")
    with pytest.raises(StagingApplyError, match="canonicalization bounds"):
        _number_value("1e999999999")
    with pytest.raises(StagingApplyError, match="canonicalization bounds"):
        _number_value("1e-999999999")


def test_audit_after_json_preserves_attribute_provenance() -> None:
    record = {
        "target_payload": {"model": "Model-1", "language_id": 1},
        "verification_status": "transferred_unverified",
        "attribute_rows": [{"attribute_id": 7, "text": "Black"}],
        "unmapped_attribute_names": ["Unknown property"],
    }

    payload = json.loads(staging_apply._audit_after_json(record, {"source": "snapshot"}))

    assert payload["attributes"] == {
        "mapped": [{"attribute_id": 7, "text": "Black"}],
        "unmapped_property_names": ["Unknown property"],
    }


def test_update_sql_uses_matched_identity_guards() -> None:
    source = _price_source_item("1.23456")
    match = MatchRecord(
        supplier_item_id="1",
        catalog_sku="3111",
        catalog_product_id=42,
        status="exact",
        confidence="1.00",
        matched_by="sku",
        warnings=(),
    )
    policy = TransferConfig(usd_rub_rate="1", markup_multiplier="1", allow_staging_apply=True)
    record = TransferRecord(
        action="update",
        source=source,
        match=match,
        target_product_id=42,
        target_sku="3111",
        target_payload=_target_payload(source, policy),
        source_properties_json="{}",
        source_images_json="[]",
        source_category_json="[]",
    )
    plan = TransferPlan(
        source_path=Path("source.csv"),
        matches_path=Path("matches.csv"),
        source_artifact_sha256="a" * 64,
        matches_artifact_sha256="b" * 64,
        run_id="run-1",
        policy=policy,
        updates=(record,),
        creates=(),
        exceptions=(),
    )
    sql = render_sql(plan, mode="apply_staging", transferred_at="2026-09-15 06:27:22")
    assert "ROW_COUNT()" not in sql
    assert "SET @netlab_transfer_product_rows = (SELECT COUNT(*) FROM `oc_product`" in sql
    assert "SET @netlab_transfer_description_rows = (SELECT COUNT(*) FROM `oc_product_description`" in sql


def test_build_run_seal_uses_held_directory_fd(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX descriptor-rooted sealing is exercised on Ubuntu")
    root = tmp_path / "held-run"
    root.mkdir()
    (root / "run-manifest.json").write_text('{"supplier":"netlab"}\n', encoding="utf-8")
    root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        build_run_seal(
            Path(f"/proc/self/fd/{root_fd}"),
            canonical_path_root=root,
            run_dir_fd=root_fd,
        )
    finally:
        os.close(root_fd)
    assert (root / "seal.json").is_file()


def test_default_trusted_root_is_platform_fixed() -> None:
    assert trusted_run._default_trusted_run_root("posix") == Path("/var/lib/mks123/trusted-runs")
    assert trusted_run._default_trusted_run_root("nt") == Path("D:/ServerBackups/mks123webserver")


def test_audit_hex_readback_decodes_after_json_column() -> None:
    row = ["0"] * 20
    row[19] = "7b7d"
    assert _decode_hex_fields(row, {19})[19] == "{}"


_AUDIT_TABLE = "`oc_netlab_transfer_audit`"


def _write_trusted_run(root: Path) -> tuple[Path, str]:
    root.mkdir(parents=True)
    manifest = root / "run-manifest.json"
    manifest.write_text(
        json.dumps({"supplier": "netlab", "run_id": root.name}) + "\n",
        encoding="utf-8",
    )
    build_run_seal(root)
    sealed = staging_apply.load_sealed_run(root, read_content=False)
    return manifest, sealed.seal_evidence.sha256


def _candidate_plan(tmp_path: Path) -> SimpleNamespace:
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
        transferred_at=None,
    )
    return SimpleNamespace(
        policy=policy,
        source_path=source,
        matches_path=matches,
        source_artifact_sha256="a" * 64,
        matches_artifact_sha256="b" * 64,
    )




def test_candidate_transfer_time_is_derived_from_trusted_fetched_at() -> None:
    policy = SimpleNamespace(
        transferred_at=None,
        run_manifest_provenance={"fetched_at": "2026-09-14T10:20:02.315153+00:00"},
    )
    assert transfer_script._deterministic_transferred_at(policy) == "2026-09-14 10:20:02"


def test_candidate_transfer_time_requires_trusted_provenance() -> None:
    policy = SimpleNamespace(transferred_at=None, run_manifest_provenance=None)
    with pytest.raises(transfer_script.TransferError, match="deterministic transferred_at"):
        transfer_script._deterministic_transferred_at(policy)


def test_candidate_publication_accepts_explicit_parent_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX descriptor-relative publication is exercised on Ubuntu")
    stage = tmp_path / "stage"
    destination = tmp_path / "candidate"
    stage.mkdir()
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        monkeypatch.setattr(
            transfer_script,
            "_open_directory_fd",
            lambda _path: pytest.fail("publication reopened the parent by pathname"),
        )
        transfer_script._rename_noreplace(stage, destination, directory_fd=parent_fd)
    finally:
        os.close(parent_fd)
    assert destination.is_dir()


def test_candidate_rejects_parent_descriptor_identity_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX descriptor-relative publication is exercised on Ubuntu")
    plan = _candidate_plan(tmp_path)
    parent = tmp_path / "parent"
    parent.mkdir()
    final_root = parent / "candidate"
    other = tmp_path / "other"
    other.mkdir()
    other_fd = os.open(other, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        monkeypatch.setattr(transfer_script, "_input_identity", lambda *_args, **_kwargs: {})
        monkeypatch.setattr(
            transfer_script,
            "_open_directory_fd",
            lambda _path: os.dup(other_fd),
        )
        with pytest.raises(transfer_script.TransferError, match="opening descriptor"):
            transfer_script._write_candidate(
                final_root,
                plan,
                render_staging_sql=False,
                run_manifest_path=tmp_path / "run-manifest.json",
            )
    finally:
        os.close(other_fd)
    assert not final_root.exists()


def test_capture_tree_is_preserved_instead_of_pathname_deleted() -> None:
    source = inspect.getsource(transfer_script.main)
    assert "private capture tree is intentionally preserved" in source
    assert "shutil.rmtree(capture_root)" not in source


def test_candidate_publication_rejects_source_identity_mismatch(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX descriptor-relative publication is exercised on Ubuntu")
    stage = tmp_path / "stage"
    other = tmp_path / "other"
    stage.mkdir()
    other.mkdir()
    parent_fd = os.open(tmp_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        with pytest.raises(transfer_script.TransferError, match="source entry changed"):
            transfer_script._rename_noreplace(
                stage,
                tmp_path / "candidate",
                directory_fd=parent_fd,
                source_identity=transfer_script._directory_entry_identity(parent_fd, other.name),
            )
    finally:
        os.close(parent_fd)
    assert stage.is_dir()
    assert other.is_dir()


def test_candidate_publication_does_not_replace_existing_path(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX no-replace primitive is exercised on Ubuntu")
    stage = tmp_path / "stage"
    destination = tmp_path / "candidate"
    stage.mkdir()
    destination.mkdir()
    (destination / "keep").write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        transfer_script._rename_noreplace(stage, destination)

    assert stage.is_dir()
    assert (destination / "keep").read_bytes() == b"keep"


def test_candidate_preserves_private_stage_after_seal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _candidate_plan(tmp_path)
    final_root = tmp_path / "candidate"
    stage_holder: dict[str, Path] = {}

    monkeypatch.setattr(transfer_script, "_input_identity", lambda *_args, **_kwargs: {})

    def write_candidate(stage: Path, *_args: object, **_kwargs: object) -> None:
        stage_holder["path"] = stage
        (stage / "payload").write_bytes(b"payload")

    monkeypatch.setattr(transfer_script, "_write_candidate_contents", write_candidate)

    def fail_seal(path: Path, **_kwargs: object) -> None:
        assert path == stage_holder["path"]
        assert not final_root.exists()
        raise RuntimeError("seal failure")

    monkeypatch.setattr(transfer_script, "build_run_seal", fail_seal)
    with pytest.raises(RuntimeError, match="seal failure"):
        transfer_script._write_candidate(
            final_root,
            plan,
            render_staging_sql=False,
            run_manifest_path=tmp_path / "run-manifest.json",
        )

    assert not final_root.exists()
    if os.name == "nt":
        assert stage_holder["path"].exists()
    else:
        assert not stage_holder["path"].exists()


def test_candidate_preserves_published_path_after_flush_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _candidate_plan(tmp_path)
    final_root = tmp_path / "candidate"
    stage_holder: dict[str, Path] = {}

    monkeypatch.setattr(transfer_script, "_input_identity", lambda *_args, **_kwargs: {})

    def write_candidate(stage: Path, *_args: object, **_kwargs: object) -> None:
        stage_holder["path"] = stage
        (stage / "payload").write_bytes(b"payload")

    monkeypatch.setattr(transfer_script, "_write_candidate_contents", write_candidate)
    monkeypatch.setattr(transfer_script, "build_run_seal", lambda *_args, **_kwargs: None)

    def fail_parent_flush(path: Path, **_kwargs: object) -> None:
        if path == final_root.parent:
            raise OSError("parent flush failure")

    monkeypatch.setattr(transfer_script, "_flush_directory", fail_parent_flush)
    with pytest.raises(OSError, match="parent flush failure"):
        transfer_script._write_candidate(
            final_root,
            plan,
            render_staging_sql=False,
            run_manifest_path=tmp_path / "run-manifest.json",
        )

    assert final_root.exists()
    assert (final_root / "payload").read_bytes() == b"payload"
    assert not stage_holder["path"].exists()


def test_trusted_run_requires_external_seal_digest(tmp_path: Path) -> None:
    manifest, _ = _write_trusted_run(tmp_path / "approved-run")

    with pytest.raises(TrustedRunError, match="external 64-hex"):
        load_trusted_run_manifest(manifest, expected_seal_sha256="")


def test_trusted_run_rejects_run_outside_fixed_durable_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"untrusted-run-{tmp_path.name}"
    manifest, seal_sha256 = _write_trusted_run(outside)

    with pytest.raises(TrustedRunError, match="outside the fixed durable trust root"):
        load_trusted_run_manifest(manifest, expected_seal_sha256=seal_sha256)


def test_audit_schema_contract_checks_columns_and_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    column_rows = [list(row) for row in staging_apply._AUDIT_COLUMN_CONTRACT]
    index_rows = [list(row) for row in staging_apply._AUDIT_INDEX_CONTRACT]

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "table_collation" in sql:
            return [["InnoDB", "utf8mb4_general_ci"]]
        if "information_schema.columns" in sql:
            return column_rows
        if "information_schema.statistics" in sql:
            return index_rows
        raise AssertionError(sql)

    monkeypatch.setattr(staging_apply, "_query_lines", query_lines)
    staging_apply._validate_audit_table_schema(StagingTarget())

    index_rows[-1][3] = "wrong_column"
    with pytest.raises(StagingApplyError, match="keys"):
        staging_apply._validate_audit_table_schema(StagingTarget())


def test_audit_schema_accepts_mariadb_index_order_with_primary_first(monkeypatch: pytest.MonkeyPatch) -> None:
    column_rows = [list(row) for row in staging_apply._AUDIT_COLUMN_CONTRACT]
    index_rows = [
        ["idx_netlab_transfer_target", "1", "1", "target_product_id", "BTREE"],
        ["PRIMARY", "0", "1", "transfer_id", "BTREE"],
        ["uq_netlab_transfer_run_sku", "0", "1", "run_id", "BTREE"],
        ["uq_netlab_transfer_run_sku", "0", "2", "source_sku", "BTREE"],
    ]

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "table_collation" in sql:
            return [["InnoDB", "utf8mb4_general_ci"]]
        if "information_schema.columns" in sql:
            return column_rows
        if "information_schema.statistics" in sql:
            if "CASE WHEN" in sql:
                return [list(row) for row in staging_apply._AUDIT_INDEX_CONTRACT]
            return index_rows
        raise AssertionError(sql)

    monkeypatch.setattr(staging_apply, "_query_lines", query_lines)
    staging_apply._validate_audit_table_schema(StagingTarget())


def test_audit_schema_rejects_column_collation_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    column_rows = [list(row) for row in staging_apply._AUDIT_COLUMN_CONTRACT]
    column_rows[1][5] = "utf8mb4_bin"
    index_rows = [list(row) for row in staging_apply._AUDIT_INDEX_CONTRACT]

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "table_collation" in sql:
            return [["InnoDB", "utf8mb4_general_ci"]]
        if "information_schema.columns" in sql:
            return column_rows
        if "information_schema.statistics" in sql:
            return index_rows
        raise AssertionError(sql)

    monkeypatch.setattr(staging_apply, "_query_lines", query_lines)
    with pytest.raises(StagingApplyError, match="columns"):
        staging_apply._validate_audit_table_schema(StagingTarget())


def test_database_engine_inventory_is_limited_to_requested_tables(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        queries.append(sql)
        return [["oc_product", "InnoDB"]]

    monkeypatch.setattr(staging_apply, "_query_lines", query_lines)
    assert staging_apply._database_table_engines(StagingTarget(), tables=("oc_product",)) == [("oc_product", "INNODB")]
    assert "`table_name` IN ('oc_product')" in queries[0]


def _valid_candidate_sql() -> str:
    return (
        "SET NAMES utf8mb4;\n"
        f"CREATE TABLE {_AUDIT_TABLE} ({','.join(staging_apply._AUDIT_DDL_PARTS)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;\n"
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);\n"
        "SELECT 'NETLAB_TRANSFER_RELATIONS_CREATED' AS marker, 0 AS value;\n"
        "SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;\n"
        "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;\n"
    )


def _record(*, action: str = "update") -> dict:
    return {
        "run_id": "test-run",
        "transferred_at": "2025-01-02 03:04:05",
        "action": action,
        "supplier_item_id": "item-1",
        "source_sku": "SKU-1",
        "target_sku": "SKU-1",
        "source_kind": "netlab",
        "verification_status": "transferred_unverified",
        "manufacturer_verified": False,
        "source_url": "https://supplier.example/item-1",
        "source_raw_hash": "b" * 64,
        "source_fetched_at": "2025-01-02 03:04:05",
        "source_artifact_path": "items.csv",
        "source_artifact_sha256": "c" * 64,
        "matches_artifact_sha256": "d" * 64,
        "source_snapshot_json": "{\"catalog_sku\":\"SKU-1\"}",
        "properties_json": "{}",
        "image_urls_json": "[]",
        "category_json": "[]",
        "target_product_id": 10 if action == "update" else None,
        "target_payload": {
            "model": "MODEL-1",
            "name": "Expected name",
            "description": "Expected description",
            "quantity": 2,
            "price": "12.34",
            "weight": "1",
            "length": "2",
            "width": "3",
            "height": "4",
            "mpn": "MPN-1",
            "ean": "EAN-1",
        },
    }


def _semantic_fixture() -> tuple[str, dict]:
    payload = _record()["target_payload"] | {
        "manufacturer": "Maker",
        "source_price": "10",
        "source_currency": "USD",
        "source_url": "https://supplier.example/item-1",
        "fetched_at": "2025-01-02 03:04:05",
        "raw_hash": "b" * 64,
        "preserve_fields": [],
    }
    source = SourceItem(
        values={"supplier_item_id": "item-1", "catalog_sku": "SKU-1"},
        source_snapshot_json=_canonical_json({"catalog_sku": "SKU-1"}),
        payload_sha256="a" * 64,
    )
    match = MatchRecord("item-1", "SKU-1", 10, "exact", "1.00", "sku", ())
    transfer_record = TransferRecord(
        action="update",
        source=source,
        match=match,
        target_product_id=10,
        target_sku="SKU-1",
        target_payload=payload,
        source_properties_json="{}",
        source_images_json="[]",
        source_category_json="[]",
    )
    config = TransferConfig(
        allow_staging_apply=True,
        transferred_at="2025-01-02 03:04:05",
        source_artifact_sha256="c" * 64,
    )
    plan = TransferPlan(
        source_path=Path("items.csv"),
        matches_path=Path("matches.csv"),
        source_artifact_sha256="c" * 64,
        matches_artifact_sha256="d" * 64,
        run_id="test-run",
        policy=config,
        updates=(transfer_record,),
        creates=(),
        exceptions=(),
    )
    record = {
        "run_id": "test-run",
        "action": "update",
        "supplier_item_id": "item-1",
        "source_sku": "SKU-1",
        "target_product_id": 10,
        "target_sku": "SKU-1",
        "source_kind": "netlab",
        "verification_status": "transferred_unverified",
        "manufacturer_verified": False,
        "source_raw_hash": payload["raw_hash"],
        "source_url": payload["source_url"],
        "source_fetched_at": payload["fetched_at"],
        "source_artifact_path": "items.csv",
        "source_artifact_sha256": "c" * 64,
        "matches_artifact_sha256": "d" * 64,
        "source_snapshot_json": source.source_snapshot_json,
        "target_payload": payload,
        "properties_json": "{}",
        "image_urls_json": "[]",
        "category_json": "[]",
        "transferred_at": "2025-01-02 03:04:05",
    }
    return render_sql(plan, mode="apply_staging"), record


def test_candidate_semantic_binding_rejects_tampered_model() -> None:
    sql, record = _semantic_fixture()
    validate_candidate_operation_set(sql, [record])
    tampered = sql.replace(
        "CONVERT(0x4d4f44454c2d31 USING utf8mb4)",
        "CONVERT(0x54414d5045524544 USING utf8mb4)",
    )
    with pytest.raises(StagingApplyError, match="operation|semantic|value"):
        validate_candidate_operation_set(tampered, [record])


def test_candidate_semantic_binding_rejects_each_value_class() -> None:
    sql, record = _semantic_fixture()
    mutations = (
        ("12.34", "99.99"),
        ("0x4578706563746564206465736372697074696f6e", "0x54414d5045524544"),
        ("0x6974656d732e637376", "0x6f746865722e637376"),
    )
    for original, replacement in mutations:
        assert original in sql
        with pytest.raises(StagingApplyError, match="operation|semantic|value"):
            validate_candidate_operation_set(sql.replace(original, replacement, 1), [record])


def test_candidate_rejects_database_switch() -> None:
    with pytest.raises(StagingApplyError, match="database|scope"):
        validate_candidate_sql(_valid_candidate_sql() + "USE another_database;\n")


@pytest.mark.parametrize("comment", ["-- hidden", "# hidden"])
def test_candidate_rejects_statement_after_line_comment(comment: str) -> None:
    with pytest.raises(StagingApplyError, match="out-of-scope|scope"):
        validate_candidate_sql(_valid_candidate_sql() + f"{comment}\nDROP TABLE `oc_product`;\n")


def test_candidate_rejects_marker_suffix_expression() -> None:
    sql = _valid_candidate_sql().replace(
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);",
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows, SLEEP(1) "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);",
    )
    with pytest.raises(StagingApplyError, match="marker|scope|expression"):
        validate_candidate_sql(sql)


def test_candidate_rejects_non_literal_update_rhs() -> None:
    sql = _valid_candidate_sql() + (
        "UPDATE `oc_product` SET `model`=UUID() "
        "WHERE `product_id`=1 AND `sku`=CONVERT(0x31 USING utf8mb4);\n"
    )
    with pytest.raises(StagingApplyError, match="UPDATE|expression"):
        validate_candidate_sql(sql)


def test_candidate_rejects_update_outside_record_operation_set() -> None:
    sql = _valid_candidate_sql() + (
        "UPDATE `oc_product` SET `price`=0 "
        "WHERE `product_id`=999 AND `sku`=CONVERT(0x56494354494d using utf8mb4);\n"
    )
    scanner = validate_candidate_sql(sql)
    with pytest.raises(StagingApplyError, match="operation|scope"):
        staging_apply._validate_candidate_operations(scanner, [_record()])


def test_invalid_update_sku_hex_is_a_controlled_candidate_error() -> None:
    code = (
        "UPDATE `oc_product` SET `model`=CONVERT(0x78 USING utf8mb4) "
        "WHERE `product_id`=1 AND `sku`=CONVERT(0xff USING utf8mb4)"
    ).lower()
    with pytest.raises(StagingApplyError, match="UTF-8|literal"):
        staging_apply._operation_signature(code)


def test_candidate_accepts_empty_literal_update_rhs() -> None:
    sql = _valid_candidate_sql() + (
        "UPDATE `oc_product_description` SET `description`='' "
        "WHERE `product_id`=1 AND `language_id`=1 "
        "AND @netlab_transfer_product_rows=1 "
        "AND EXISTS (SELECT 1 FROM `oc_product` AS p "
        "WHERE p.`product_id`=1 AND p.`sku`=CONVERT(0x31 USING utf8mb4));\n"
    )
    validate_candidate_sql(sql)


def test_candidate_rejects_noncanonical_audit_ddl() -> None:
    sql = _valid_candidate_sql().replace(
        "`run_id` VARCHAR(128) NOT NULL",
        "`run_id` VARCHAR(128) NULL",
    )
    with pytest.raises(StagingApplyError, match="DDL|allowlist"):
        validate_candidate_sql(sql)


def test_candidate_rejects_contradictory_publication_marker() -> None:
    sql = _valid_candidate_sql() + (
        "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 1 AS value;\n"
    )
    with pytest.raises(StagingApplyError, match="publication|marker|zero"):
        validate_candidate_sql(sql)


def test_streaming_validator_rejects_database_switch(tmp_path: Path) -> None:
    path = tmp_path / "APPLY_STAGING.sql"
    path.write_text(_valid_candidate_sql() + "USE another_database;\n", encoding="utf-8")
    with pytest.raises(StagingApplyError, match="out-of-scope"):
        validate_candidate_file(path)


def test_streaming_validator_does_not_count_markers_inside_literals_or_comments(
    tmp_path: Path,
) -> None:
    sql = """
    SET NAMES utf8mb4;
    /* `oc_netlab_transfer_audit`;
       SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker;
       SELECT 'NETLAB_TRANSFER_RELATIONS_CREATED' AS marker, 0 AS value;
       SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;
       SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;
    */
    """
    path = tmp_path / "candidate.sql"
    path.write_text(sql, encoding="utf-8")

    with pytest.raises(StagingApplyError, match="missing required marker"):
        validate_candidate_file(path)


def test_candidate_rejects_multiline_insert_values() -> None:
    sql = _valid_candidate_sql().replace(
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);",
        "INSERT INTO `oc_product` (`model`) VALUES ('x'), ('y');\n"
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);",
    )
    with pytest.raises(StagingApplyError, match="INSERT|shape"):
        validate_candidate_sql(sql)


def test_streaming_validator_accepts_utf8_character_split_at_chunk_boundary(tmp_path: Path) -> None:
    prefix = _valid_candidate_sql() + "/*"
    padding = "A" * (1024 * 1024 - len(prefix.encode("utf-8")) - 1)
    path = tmp_path / "APPLY_STAGING.sql"
    path.write_bytes((prefix + padding + "Ж*/\n").encode("utf-8"))

    validate_candidate_file(path)


def test_readback_rejects_duplicate_product_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _record()

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "SELECT `sku`" in sql:
            return [["SKU-1"], ["SKU-1"]]
        return []

    def count(_target: StagingTarget, sql: str) -> int:
        if "oc_netlab_transfer_audit" in sql:
            return 1
        if "oc_product_to_category" in sql or "oc_product_image" in sql:
            return 0
        if "oc_product`" in sql:
            return 1
        raise AssertionError(sql)

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._query_lines", query_lines)
    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._count", count)

    with pytest.raises(StagingApplyError, match="duplicate|exactly one|SKU"):
        _readback(StagingTarget(), [record], {"products": 1, "categories": 0, "images": 0})


def test_affected_state_digest_batches_large_sku_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    queries: list[str] = []

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        queries.append(sql)
        return []

    monkeypatch.setattr(staging_apply, "_query_lines", query_lines)
    records = [{"target_sku": f"SKU-{index}"} for index in range(1001)]

    staging_apply._affected_state_digest(StagingTarget(), records)

    product_queries = [query for query in queries if "FROM `oc_product`" in query]
    assert len(product_queries) >= 3
    assert max(query.count("'SKU-") for query in product_queries) <= 500


def test_readback_rejects_wrong_description_value(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _record()

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "oc_product_description" in sql:
            return [["10", "1", "Wrong name", "Expected description"]]
        if "SELECT `sku`" in sql:
            return [["SKU-1"]]
        if "FROM `oc_product`" in sql:
            return [["10", "SKU-1", "MODEL-1", "2", "12.34", "1", "2", "3", "4", "MPN-1", "EAN-1"]]
        return []

    def count(_target: StagingTarget, sql: str) -> int:
        if "oc_netlab_transfer_audit" in sql:
            return 1
        if "oc_product_to_category" in sql or "oc_product_image" in sql:
            return 0
        if "oc_product`" in sql:
            return 1
        raise AssertionError(sql)

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._query_lines", query_lines)
    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._count", count)

    with pytest.raises(StagingApplyError, match="description|name|field"):
        _readback(StagingTarget(), [record], {"products": 1, "categories": 0, "images": 0})


def test_apply_rejects_legacy_schema_before_backup_side_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_bytes(b"candidate")
    (tmp_path / "CANDIDATE_MANIFEST.json").write_bytes(b"{}\n")
    (tmp_path / "seal.json").write_bytes(b"{}\n")
    backup_root = tmp_path / "backup"
    monkeypatch.setattr(staging_apply, "validate_staging_target", lambda _target: None)
    monkeypatch.setattr(staging_apply, "_safe_candidate_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_safe_backup_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "validate_candidate_file", lambda _path, **_kwargs: None)
    monkeypatch.setattr(
        staging_apply,
        "validate_candidate_bundle",
        lambda _path, **_kwargs: {"schema_version": 1},
    )

    with pytest.raises(StagingApplyError, match="schema version 2"):
        staging_apply.apply_candidate(
            candidate,
            target=StagingTarget(),
            backup_root=backup_root,
            confirm_staging_only=True,
        )

    assert not backup_root.exists()


def test_candidate_preparation_deadline_fails_closed_before_database() -> None:
    deadline = staging_apply._CandidatePreparationDeadline(expires_at=0.0)

    with pytest.raises(StagingApplyError, match="before database session"):
        deadline.check()


def test_file_identity_checks_preparation_deadline(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.bin"
    candidate.write_bytes(b"x" * (2 * 1024 * 1024))
    calls = 0

    def expire() -> None:
        nonlocal calls
        calls += 1
        raise StagingApplyError("candidate preparation exceeded staging timeout before database session")

    with pytest.raises(StagingApplyError, match="before database session"):
        staging_apply._file_identity(candidate, deadline_check=expire)
    assert calls == 1


def test_candidate_jsonl_checks_preparation_deadline(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_bytes(b"{}\n")

    def expire() -> None:
        raise StagingApplyError("candidate preparation exceeded staging timeout before database session")

    with pytest.raises(StagingApplyError, match="before database session"):
        staging_apply._read_candidate_jsonl(
            path,
            label="records",
            max_bytes=1024,
            deadline_check=expire,
        )


def test_candidate_seal_timeout_is_not_reclassified_as_generic_seal_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_bytes(b"candidate")
    (tmp_path / "CANDIDATE_MANIFEST.json").write_bytes(b"{}\n")
    deadline = staging_apply._CandidatePreparationDeadline(expires_at=0.0)

    def fake_load_sealed_run(*_args: object, deadline_check: object = None, **_kwargs: object) -> object:
        assert callable(deadline_check)
        deadline_check()
        raise AssertionError("deadline callback should have raised")

    monkeypatch.setattr(staging_apply, "load_sealed_run", fake_load_sealed_run)

    with pytest.raises(StagingApplyError, match="candidate preparation exceeded staging timeout"):
        staging_apply.validate_candidate_bundle(
            candidate,
            require_trusted_run_manifest=False,
            deadline_check=deadline.check,
        )


def test_expired_preparation_deadline_blocks_database_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    backup_root = tmp_path / "backup"
    backup_root.mkdir()
    prepare_result = (
        {"candidate_id": "candidate-id"},
        [],
        tmp_path / "candidate-snapshot" / "APPLY_STAGING.sql",
        {"size": 0, "sha256": "0" * 64},
    )
    session_constructed = False

    @contextmanager
    def fake_locked_candidate_handle(*_args: object, **_kwargs: object) -> Iterator[BytesIO]:
        yield BytesIO()

    def fake_prepare(*_args: object, **_kwargs: object) -> tuple[dict, list, Path, dict]:
        return prepare_result

    def expire(_self: object) -> None:
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    def fail_session(*_args: object, **_kwargs: object) -> None:
        nonlocal session_constructed
        session_constructed = True
        raise AssertionError("MariaDB session must not be constructed after preparation timeout")

    monkeypatch.setattr(staging_apply, "validate_staging_target", lambda _target: None)
    monkeypatch.setattr(staging_apply, "_safe_candidate_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_safe_backup_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_prepare_candidate_snapshot", fake_prepare)
    monkeypatch.setattr(staging_apply, "_locked_candidate_handle", fake_locked_candidate_handle)
    monkeypatch.setattr(staging_apply._CandidatePreparationDeadline, "check", expire)
    monkeypatch.setattr(staging_apply, "_LockedMysqlSession", fail_session)

    with pytest.raises(StagingApplyError, match="candidate_preparation_timeout") as raised:
        staging_apply.apply_candidate(
            candidate,
            target=StagingTarget(),
            backup_root=backup_root,
            confirm_staging_only=True,
        )

    assert not session_constructed
    receipt = json.loads(raised.value.args[0])
    assert receipt["stage"] == "candidate_preparation_timeout"
    assert json.loads((backup_root / "APPLY_RESULT.json").read_text())["stage"] == "candidate_preparation_timeout"


def test_trusted_input_identity_checks_preparation_deadline(tmp_path: Path) -> None:
    trusted_root = tmp_path / "trusted-run"
    trusted_root.mkdir()
    source = trusted_root / "source.bin"
    source.write_bytes(b"source bytes")
    identity = {
        "size": source.stat().st_size,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }

    def expire() -> None:
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    with pytest.raises(staging_apply._CandidatePreparationTimeout, match="before database session"):
        staging_apply._trusted_sealed_input_path(
            {"paths": [str(source)]},
            role="source",
            seal_metadata={"run_root": str(trusted_root), "files": {"source.bin": identity}},
            deadline_check=expire,
        )


def test_category_snapshot_reader_checks_preparation_deadline(tmp_path: Path) -> None:
    snapshot = tmp_path / "category-snapshot.sql"
    snapshot.write_bytes(b"snapshot bytes")

    def expire() -> None:
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    with pytest.raises(staging_apply._CandidatePreparationTimeout, match="before database session"):
        two_category_selector._read_snapshot_bytes(snapshot, deadline_check=expire)


def test_candidate_scanner_checks_deadline_inside_chunk() -> None:
    calls = 0

    def expire() -> None:
        nonlocal calls
        calls += 1
        if calls >= 3:
            raise staging_apply._CandidatePreparationTimeout(
                "candidate preparation exceeded staging timeout before database session"
            )

    scanner = staging_apply._SqlCandidateScanner(deadline_check=expire)
    with pytest.raises(staging_apply._CandidatePreparationTimeout, match="before database session"):
        scanner.feed("x" * 8192)
    assert calls == 3


def test_selector_hashing_reader_checks_preparation_deadline() -> None:
    def expire() -> None:
        raise StagingApplyError("candidate preparation exceeded staging timeout before database session")

    reader = two_category_selector._HashingReader(
        BytesIO(b"payload"),
        maximum=1024,
        label="selector input",
        deadline_check=expire,
    )
    with pytest.raises(StagingApplyError, match="before database session"):
        reader.read()


def test_locked_candidate_bundle_checks_deadline_during_enumeration(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    (root / "APPLY_STAGING.sql").write_bytes(b"candidate")
    calls = 0

    def expire() -> None:
        nonlocal calls
        calls += 1
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    with pytest.raises(staging_apply._CandidatePreparationTimeout, match="before database session"), staging_apply._locked_candidate_bundle(
        root,
        deadline_check=expire,
    ):
        raise AssertionError("enumeration should have expired before yielding handles")
    assert calls == 1


def test_preparation_timeout_before_backup_writes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    backup_root = tmp_path / "backup"

    @contextmanager
    def fail_locked_bundle(*_args: object, **_kwargs: object) -> Iterator[dict[str, BytesIO]]:
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )
        yield {}

    monkeypatch.setattr(staging_apply, "validate_staging_target", lambda _target: None)
    monkeypatch.setattr(staging_apply, "_safe_candidate_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_safe_backup_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_locked_candidate_bundle", fail_locked_bundle)

    with pytest.raises(StagingApplyError, match="candidate_preparation_timeout") as raised:
        staging_apply.apply_candidate(
            candidate,
            target=StagingTarget(),
            backup_root=backup_root,
            confirm_staging_only=True,
        )

    receipt = json.loads(raised.value.args[0])
    assert receipt["stage"] == "candidate_preparation_timeout"
    assert json.loads((backup_root / "APPLY_RESULT.json").read_text())["status"] == "REJECTED"


def test_final_locked_snapshot_timeout_keeps_preparation_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_bytes(b"candidate")
    backup_root = tmp_path / "backup"
    prepare_result = (
        {"candidate_id": "candidate-id"},
        [],
        candidate,
        {"size": len(b"candidate"), "sha256": hashlib.sha256(b"candidate").hexdigest()},
    )

    def fake_prepare(*_args: object, **_kwargs: object) -> tuple[dict, list, Path, dict]:
        return prepare_result

    def expire(_self: object) -> None:
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    monkeypatch.setattr(staging_apply, "validate_staging_target", lambda _target: None)
    monkeypatch.setattr(staging_apply, "_safe_candidate_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_safe_backup_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(staging_apply, "_prepare_candidate_snapshot", fake_prepare)
    monkeypatch.setattr(staging_apply._CandidatePreparationDeadline, "check", expire)

    with pytest.raises(StagingApplyError, match="candidate_preparation_timeout") as raised:
        staging_apply.apply_candidate(
            candidate,
            target=StagingTarget(),
            backup_root=backup_root,
            confirm_staging_only=True,
        )

    assert json.loads(raised.value.args[0])["stage"] == "candidate_preparation_timeout"
    assert json.loads((backup_root / "APPLY_RESULT.json").read_text())["stage"] == "candidate_preparation_timeout"


@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_unlock_failure_still_closes_locked_candidate_handle(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
) -> None:
    class FakeHandle:
        def __init__(self) -> None:
            self.closed = False

        def fileno(self) -> int:
            return 123

        def close(self) -> None:
            self.closed = True

    handle = FakeHandle()

    def fail_unlock(*_args: object) -> None:
        raise OSError("unlock failed")

    monkeypatch.setattr(staging_apply.os, "name", platform)
    if platform == "posix":
        monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_UN=8, flock=fail_unlock))
        windows_lock = None
    else:
        monkeypatch.setattr(staging_apply, "_release_windows_candidate_lock", fail_unlock)
        windows_lock = (object(), 1, object())

    errors = staging_apply._close_locked_candidate_handle(
        handle,
        locked=True,
        windows_lock=windows_lock,
    )

    assert handle.closed
    assert len(errors) == 1
    assert "unlock failed" in str(errors[0])


def test_active_preparation_timeout_survives_unlock_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeHandle:
        def __init__(self) -> None:
            self.closed = False

        def fileno(self) -> int:
            return 123

        def close(self) -> None:
            self.closed = True

    handle = FakeHandle()
    lock_calls = 0

    def fail_unlock_only(_fd: int, operation: int) -> None:
        nonlocal lock_calls
        lock_calls += 1
        if operation == 8:
            raise OSError("unlock failed")

    monkeypatch.setattr(staging_apply.os, "name", "posix")
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, flock=fail_unlock_only))
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: handle)
    candidate = tmp_path / "candidate.sql"

    with pytest.raises(staging_apply._CandidatePreparationTimeout, match="before database session"), staging_apply._locked_candidate_handle(
        candidate,
    ):
        raise staging_apply._CandidatePreparationTimeout(
            "candidate preparation exceeded staging timeout before database session"
        )

    assert lock_calls == 2
    assert handle.closed


def test_candidate_manifest_rejects_tampered_bytes(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    source_artifact = tmp_path / "source.zip"
    normalized_source = tmp_path / "items.csv"
    matches_artifact = tmp_path / "matches.csv"
    source_artifact.write_bytes(b"source artifact\n")
    normalized_source.write_bytes(b"normalized source\n")
    matches_artifact.write_bytes(b"matches\n")

    def input_entry(path: Path) -> dict:
        data = path.read_bytes()
        return {
            "paths": [str(path.resolve())],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    files = {
        "APPLY_STAGING.sql": b"SET NAMES utf8mb4;\n",
        "RECORDS.jsonl": b"{\"run_id\": \"run-1\"}\n",
        "SUMMARY.json": b"{\"run_id\": \"run-1\"}\n",
        "EXCEPTIONS.json": b"[]\n",
        "PREVIEW.md": b"preview\n",
    }
    entries = []
    for name, data in files.items():
        path = root / name
        path.write_bytes(data)
        entries.append(
            {
                "path": name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    manifest = {
        "schema_version": 1,
        "candidate_mode": "apply_staging",
        "run_id": "run-1",
        "source_artifact_sha256": input_entry(source_artifact)["sha256"],
        "matches_artifact_sha256": input_entry(matches_artifact)["sha256"],
        "inputs": {
            "source_artifact": input_entry(source_artifact),
            "normalized_source": input_entry(normalized_source),
            "matches": input_entry(matches_artifact),
        },
        "files": entries,
    }
    identity_material = {
        key: manifest[key]
        for key in (
            "schema_version",
            "candidate_mode",
            "run_id",
            "source_artifact_sha256",
            "matches_artifact_sha256",
            "inputs",
            "files",
        )
    }
    manifest["candidate_id"] = hashlib.sha256(
        json.dumps(
            {**identity_material, "files": sorted(entries, key=lambda entry: entry["path"])},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    (root / "CANDIDATE_MANIFEST.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    build_run_seal(root)
    for path in root.iterdir():
        if path.is_file() and path.name != "seal.json":
            path.chmod(0o666)
    candidate = root / "APPLY_STAGING.sql"
    candidate.write_bytes(b"SET NAMES utf8mb4;\n-- tampered\n")

    validator = getattr(staging_apply, "validate_candidate_bundle", None)
    assert validator is not None
    with pytest.raises(StagingApplyError, match="seal|immutable"):
        validator(candidate)


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows lock semantics")
def test_candidate_snapshot_uses_exclusive_windows_lock(tmp_path: Path) -> None:
    import msvcrt

    candidate = tmp_path / "candidate.sql"
    candidate.write_bytes(b"candidate bytes")
    with staging_apply._locked_candidate_handle(candidate):
        competing = candidate.open("r+b")
        try:
            competing.seek(0)
            with pytest.raises(OSError):
                msvcrt.locking(competing.fileno(), msvcrt.LK_NBLCK, 1)
        finally:
            competing.close()


@pytest.mark.parametrize("control_name", ["CANDIDATE_MANIFEST.json", "seal.json"])
def test_locked_candidate_bundle_rejects_replaced_control_file(
    tmp_path: Path,
    control_name: str,
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    manifest_path = root / "CANDIDATE_MANIFEST.json"
    seal_path = root / "seal.json"
    manifest_path.write_bytes(b"{\"files\":[]}\n")
    seal_path.write_bytes(b"seal\n")
    with manifest_path.open("rb") as manifest_handle, seal_path.open("rb") as seal_handle:
        control_identities = {
            "CANDIDATE_MANIFEST.json": staging_apply._handle_identity(manifest_handle),
            "seal.json": staging_apply._handle_identity(seal_handle),
        }
        (root / control_name).write_bytes(b"{\"files\":[],\"tampered\":true}\n")
        with pytest.raises(StagingApplyError, match="manifest|seal|control|identity"):
            staging_apply._verify_locked_candidate_bundle(
                {"files": []},
                {"CANDIDATE_MANIFEST.json": manifest_handle, "seal.json": seal_handle},
                candidate_root=root,
                control_identities=control_identities,
            )


def test_candidate_snapshot_rejects_bytes_changed_after_validation(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    candidate = root / "APPLY_STAGING.sql"
    records = root / "RECORDS.jsonl"
    candidate.write_bytes(b"validated bytes")
    records.write_bytes(b"{}\n")

    def identity(path: Path) -> dict[str, object]:
        data = path.read_bytes()
        return {"path": path.name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    manifest = {"files": [identity(candidate), identity(records)]}
    candidate.write_bytes(b"replaced bytes")
    backup_root = tmp_path / "backup"
    backup_root.mkdir()

    with pytest.raises(StagingApplyError, match="changed during validated snapshot"):
        staging_apply._snapshot_candidate_bundle(
            candidate,
            backup_root,
            manifest,
            source_handles={
                "APPLY_STAGING.sql": BytesIO(b"replaced bytes"),
                "RECORDS.jsonl": BytesIO(b"{}\n"),
            },
        )


def test_candidate_snapshot_rejects_growth_before_writing_over_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    candidate = root / "APPLY_STAGING.sql"
    records = root / "RECORDS.jsonl"
    candidate.write_bytes(b"abcdef")
    records.write_bytes(b"{}\n")
    manifest = {
        "files": [
            {"path": "APPLY_STAGING.sql", "size": 4, "sha256": hashlib.sha256(b"abcd").hexdigest()},
            {"path": "RECORDS.jsonl", "size": records.stat().st_size, "sha256": hashlib.sha256(b"{}\n").hexdigest()},
        ]
    }
    monkeypatch.setattr(staging_apply, "_MAX_CANDIDATE_SQL_BYTES", 4)
    backup_root = tmp_path / "backup"
    backup_root.mkdir()

    with pytest.raises(StagingApplyError, match="bound"):
        staging_apply._snapshot_candidate_bundle(
            candidate,
            backup_root,
            manifest,
            source_handles={
                "APPLY_STAGING.sql": BytesIO(b"replaced bytes"),
                "RECORDS.jsonl": BytesIO(b"{}\n"),
            },
        )

    assert not (backup_root / "candidate-snapshot" / "APPLY_STAGING.sql").exists()


def test_records_loader_binds_parsed_bytes_to_expected_identity(tmp_path: Path) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    records_path = tmp_path / "RECORDS.jsonl"
    candidate.write_bytes(b"candidate")
    records_path.write_bytes(b'{"action":"update","target_sku":"SKU-1"}\n')
    with pytest.raises(StagingApplyError, match="identity|changed"):
        staging_apply._load_records(
            candidate,
            expected_identity={"path": "RECORDS.jsonl", "size": records_path.stat().st_size + 1, "sha256": "0" * 64},
        )


def test_records_loader_rejects_oversized_physical_line(tmp_path: Path) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    records = tmp_path / "RECORDS.jsonl"
    candidate.write_text("-- placeholder", encoding="utf-8")
    records.write_bytes(b"A" * (staging_apply._MAX_RECORD_LINE_BYTES + 1))
    with pytest.raises(StagingApplyError, match="configured bounds"):
        staging_apply._load_records(candidate)


def test_records_loader_rejects_invalid_utf8_as_staging_error(tmp_path: Path) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_text("-- placeholder", encoding="utf-8")
    (tmp_path / "RECORDS.jsonl").write_bytes(b"\xff\n")
    with pytest.raises(StagingApplyError, match="RECORDS"):
        staging_apply._load_records(candidate)


def test_operation_signature_rejects_oversized_numeric_identity() -> None:
    huge_id = "9" * 5_000
    code = (
        "update `oc_product` set `model`=convert(0x78 using utf8mb4) "
        f"where `product_id`={huge_id} and `sku`=convert(0x534b55 using utf8mb4)"
    )
    with pytest.raises(StagingApplyError, match="identity"):
        staging_apply._operation_signature(code)


def test_candidate_file_rejects_total_sql_size_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "APPLY_STAGING.sql"
    path.write_text(_valid_candidate_sql() + "/*padding*/", encoding="utf-8")
    monkeypatch.setattr(staging_apply, "_MAX_CANDIDATE_SQL_BYTES", 32)
    with pytest.raises(StagingApplyError, match="size bound"):
        validate_candidate_file(path)


def test_candidate_sql_validation_rejects_in_place_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_text(_valid_candidate_sql(), encoding="utf-8")
    original_feed = staging_apply._SqlCandidateScanner.feed
    mutated = False

    def feed_and_mutate(scanner: object, data: str, *, final: bool = False) -> object:
        nonlocal mutated
        result = original_feed(scanner, data, final=final)
        if not mutated:
            mutated = True
            candidate.write_bytes(candidate.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(staging_apply._SqlCandidateScanner, "feed", feed_and_mutate)
    with pytest.raises(StagingApplyError, match="changed"):
        staging_apply.validate_candidate_file(candidate)


def test_records_loader_rejects_in_place_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    records_path = tmp_path / "RECORDS.jsonl"
    candidate.write_text("-- placeholder", encoding="utf-8")
    records_path.write_bytes(b'{"action":"update","target_sku":"SKU-1"}\n')
    original_loads = staging_apply.json.loads
    mutated = False

    def loads_and_mutate(value: object, *args: object, **kwargs: object) -> object:
        nonlocal mutated
        result = original_loads(value, *args, **kwargs)
        if not mutated:
            mutated = True
            records_path.write_bytes(records_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(staging_apply.json, "loads", loads_and_mutate)
    with pytest.raises(StagingApplyError, match="changed"):
        staging_apply._load_records(candidate)


def test_execution_rejects_in_place_candidate_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "APPLY_STAGING.sql"
    candidate.write_bytes(b"original")
    expected = staging_apply._file_identity(candidate)

    def fake_run(*_args: object, **_kwargs: object) -> object:
        candidate.write_bytes(b"mutated")
        return type("Result", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply.subprocess.run", fake_run)
    with candidate.open("rb") as handle, pytest.raises(StagingApplyError, match="changed during execution"):
        staging_apply._run_file(
            StagingTarget(),
            candidate,
            source_handle=handle,
            expected_identity=expected,
        )


def test_readback_rejects_unchanged_relation_count_with_changed_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = _record()
    record.pop("source_snapshot_json")

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "oc_product_to_category" in sql:
            return [["10", "999"]]
        if "oc_product_image" in sql:
            return [["10", "image.jpg"]]
        if "oc_product_description" in sql:
            return [["10", "1", "Expected name", "Expected description"]]
        if "FROM `oc_product`" in sql:
            return [["10", "SKU-1", "MODEL-1", "2", "12.34", "1", "2", "3", "4", "MPN-1", "EAN-1", "1", "0"]]
        return []

    def count(_target: StagingTarget, sql: str) -> int:
        if "oc_netlab_transfer_audit" in sql:
            return 1
        if "oc_product_to_category" in sql or "oc_product_image" in sql:
            return 1
        if "oc_product`" in sql:
            return 1
        raise AssertionError(sql)

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._query_lines", query_lines)
    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._count", count)

    before = {
        "products": 1,
        "categories": 1,
        "images": 1,
        "categories_digest": {"rows": 1, "sha256": "before-category"},
        "images_digest": {"rows": 1, "sha256": "before-image"},
    }
    with pytest.raises(StagingApplyError, match="semantic|category|image|content"):
        _readback(StagingTarget(), [record], before)


def test_preflight_rejects_non_innodb_pilot(monkeypatch: pytest.MonkeyPatch) -> None:
    record = _record()

    def query_lines(_target: StagingTarget, sql: str) -> list[list[str]]:
        if "information_schema.tables" in sql and "engine" in sql.casefold():
            return [
                [table, "NONINNODB" if table == "oc_product" else "InnoDB"]
                for table in staging_apply._PILOT_LOCK_TABLES
            ]
        if "information_schema.tables" in sql and "auto_increment" in sql.casefold():
            return [["1"]]
        if "SELECT `product_id`, HEX(`sku`)" in sql:
            return [["10", "SKU-1", "1", "0"]]
        return []

    def count(_target: StagingTarget, sql: str) -> int:
        if "processlist" in sql:
            return 0
        if "table_schema=DATABASE" in sql:
            return 0
        if "oc_product`" in sql:
            return 1
        if "oc_product_description" in sql:
            return 1
        if "oc_product_to_category" in sql or "oc_product_image" in sql:
            return 0
        raise AssertionError(sql)

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._query_lines", query_lines)
    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._count", count)

    before = staging_apply._preflight(StagingTarget(), [record])
    with pytest.raises(StagingApplyError, match="INNODB_REQUIRED"):
        staging_apply._require_transactional_pilot(before)


def test_rollback_verifier_requires_semantic_readback() -> None:
    verifier = getattr(staging_apply, "verify_restored_state", None)
    assert verifier is not None


def test_rollback_verifier_returns_pass_only_after_semantic_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "products": 1,
        "descriptions": 1,
        "audit_table": 0,
        "categories_digest": {"rows": 1, "sha256": "category"},
        "images_digest": {"rows": 1, "sha256": "image"},
    }

    def count(_target: StagingTarget, sql: str) -> int:
        if "oc_product_description" in sql:
            return 1
        if "oc_product`" in sql:
            return 1
        if "table_schema=DATABASE" in sql:
            return 0
        raise AssertionError(sql)

    monkeypatch.setattr("mks123_pipeline.netlab_staging_apply._count", count)
    monkeypatch.setattr(
        "mks123_pipeline.netlab_staging_apply._semantic_digest",
        lambda _target, table, **_kwargs: before["categories_digest"] if table.endswith("category") else before["images_digest"],
    )

    receipt = staging_apply.verify_restored_state(StagingTarget(), before, [])
    assert receipt["status"] == "PASS"
    assert all(receipt["checks"].values())


def test_failure_receipt_writer_is_available(tmp_path: Path) -> None:
    writer = getattr(staging_apply, "write_apply_result", None)
    assert writer is not None
    path = writer(tmp_path, {"status": "FAILED", "stage": "backup"})
    assert path.is_file()
    assert json.loads(path.read_text(encoding="utf-8"))["stage"] == "backup"


def test_file_failure_receipt_keeps_database_error_tail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.sql"
    candidate.write_text("SELECT 1;", encoding="utf-8")
    database_error = "ERROR 1064 (42000): synthetic database syntax error"
    monkeypatch.setattr(
        staging_apply.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stderr=("Q" * 700 + database_error).encode("utf-8"),
            stdout=b"",
        ),
    )

    with pytest.raises(StagingApplyError, match="ERROR 1064"):
        staging_apply._run_file(StagingTarget(), candidate)


def test_success_receipt_failure_uses_innodb_transaction_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = {"status": "PASS"}
    session = SimpleNamespace(assert_alive=lambda: None)
    rollback_calls: list[object] = []
    monkeypatch.setattr(
        staging_apply,
        "_write_pending_apply_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(StagingApplyError("receipt unavailable")),
    )

    def coordinated_restore(*_args: object, **kwargs: object) -> dict[str, str]:
        rollback_calls.append(kwargs["coordination_session"])
        return {"status": "PASS"}

    monkeypatch.setattr(staging_apply, "_restore_with_coordination", coordinated_restore)

    with pytest.raises(StagingApplyError, match="receipt unavailable"):
        staging_apply._finalize_success(
            StagingTarget(),
            tmp_path,
            result,
            {"auto_increment": {}},
            [],
            coordination_session=session,
        )

    assert rollback_calls == [session]
    assert result["rollback"] == "PASS"
    assert result["status"] == "ROLLED_BACK_RECEIPT_FAILURE"



def test_locked_session_preserves_large_query_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    child = textwrap.dedent(
        """
        import os
        import sys
        import time

        for raw_line in sys.stdin.buffer:
            line = raw_line.decode("utf-8", "replace").strip()
            if line == "SELECT 1;":
                for index in range(60000):
                    os.write(1, f"{index}\\t{index + 1}\\n".encode())
                    if index % 128 == 0:
                        time.sleep(0.0002)
            elif line.startswith("SELECT GET_LOCK("):
                os.write(1, b"1\\n")
            elif line.startswith("SELECT RELEASE_LOCK("):
                os.write(1, b"1\\n")
            if line.startswith("SELECT '") and line.endswith("';"):
                marker = line.split("'", 2)[1]
                marker_body = marker.encode()
                for byte in marker_body:
                    os.write(1, bytes([byte]))
                time.sleep(0.05)
                os.write(1, b"\\r")
                time.sleep(0.05)
                os.write(1, b"\\n")
        """
    )
    monkeypatch.setattr(
        staging_apply,
        "_client_command",
        lambda _target, include_database=True: [sys.executable, "-u", "-c", child],
    )

    expected = "".join(f"{index}\t{index + 1}\n" for index in range(60000))
    with staging_apply._LockedMysqlSession(
        StagingTarget(timeout_seconds=30),
        ("oc_product",),
        audit_table_exists=False,
    ) as session:
        assert session.query("SELECT 1") == expected


def test_locked_session_bounds_stalled_stdin_write(monkeypatch: pytest.MonkeyPatch) -> None:
    child = textwrap.dedent(
        """
        import os
        import time

        lock_requested = False
        for raw_line in __import__("sys").stdin.buffer:
            line = raw_line.decode("utf-8", "replace").strip()
            if line.startswith("SELECT GET_LOCK("):
                lock_requested = True
                os.write(1, b"1\\n")
            if line.startswith("SELECT '") and line.endswith("';"):
                marker = line.split("'", 2)[1]
                marker_body = marker.encode()
                for byte in marker_body:
                    os.write(1, bytes([byte]))
                time.sleep(0.05)
                os.write(1, b"\\r")
                time.sleep(0.05)
                os.write(1, b"\\n")
                if lock_requested:
                    while True:
                        time.sleep(60)
        """
    )
    monkeypatch.setattr(
        staging_apply,
        "_client_command",
        lambda _target, include_database=True: [sys.executable, "-u", "-c", child],
    )
    session = staging_apply._LockedMysqlSession(
        StagingTarget(timeout_seconds=1),
        ("oc_product",),
        audit_table_exists=False,
    )
    result: list[BaseException] = []

    def invoke() -> None:
        try:
            with session:
                session.run_candidate(
                    BytesIO(b"x" * (16 * 1024 * 1024)),
                    audit_table_exists=False,
                )
        except staging_apply.StagingApplyError as exc:
            result.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    worker.join(timeout=3)
    stalled = worker.is_alive()
    if stalled:
        process = session.process
        if process is not None:
            process.kill()
            if process.stdin is not None:
                process.stdin.close()
        worker.join(timeout=5)
    assert not stalled
    assert result
    assert isinstance(result[0], StagingApplyError)
    assert "stdin" in str(result[0]) or "SESSION_" in str(result[0])


def test_locked_session_rejects_concurrent_stdin_write() -> None:
    class FakeStdin:
        @staticmethod
        def write(data: bytes) -> int:
            return len(data)

        @staticmethod
        def flush() -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

    lock = threading.Lock()
    lock.acquire()
    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session._transport_abort_reason = None
    session._stdin_write_lock = lock
    session._stdin_write_lock_owner = threading.get_ident()

    try:
        with pytest.raises(StagingApplyError, match="concurrent stdin write"):
            session._write_stdin_bounded(b"SELECT 1;\n", deadline=10**9)
    finally:
        session._stdin_write_lock_owner = None
        lock.release()


def test_locked_session_surfaces_stderr_before_child_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    child = textwrap.dedent(
        """
        import os

        os.write(2, b"ERROR 1064 (42000): synthetic locked-session query failure\\n")
        os._exit(7)
        """
    )
    monkeypatch.setattr(
        staging_apply,
        "_client_command",
        lambda _target, include_database=True: [sys.executable, "-u", "-c", child],
    )

    with (
        pytest.raises(StagingApplyError, match="ERROR 1064"),
        staging_apply._LockedMysqlSession(
            StagingTarget(timeout_seconds=5),
            ("oc_product",),
            audit_table_exists=False,
        ),
    ):
        pass


def test_locked_session_surfaces_stdout_reader_failure() -> None:
    session = object.__new__(staging_apply._LockedMysqlSession)
    session._stream_lock = staging_apply.threading.Lock()
    session._stream_buffers = {"stdout": bytearray(), "stderr": bytearray()}
    session._stream_errors = {"stdout": OSError("stdout closed")}

    with pytest.raises(StagingApplyError, match="stdout reader failed"):
        session._read_new_output()


def test_locked_session_surfaces_stderr_reader_failure() -> None:
    session = object.__new__(staging_apply._LockedMysqlSession)
    session._stream_lock = staging_apply.threading.Lock()
    session._stream_buffers = {"stdout": bytearray(), "stderr": bytearray()}
    session._stream_errors = {"stderr": OSError("stderr closed")}

    with pytest.raises(StagingApplyError, match="stderr reader failed"):
        session._stderr_text()


def test_locked_session_blocks_when_reader_survives_bounded_cleanup() -> None:
    class FakeStream:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeReader:
        def __init__(self) -> None:
            self.join_timeouts: list[float] = []

        def join(self, timeout: float) -> None:
            self.join_timeouts.append(timeout)

        @staticmethod
        def is_alive() -> bool:
            return True

    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

    reader = FakeReader()
    stdout = FakeStream()
    stderr = FakeStream()
    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = stdout
    session.stderr = stderr
    session._stream_readers = {"stdout": reader}
    session._transaction_started = False
    session._lock_acquired = False
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "NOT_ATTEMPTED"

    with pytest.raises(staging_apply.StagingSessionStateError, match="stdout reader did not exit") as exc_info:
        session._close(success=False)

    assert exc_info.value.status == "SESSION_CLEANUP_BLOCKED"
    assert len(reader.join_timeouts) == 2
    assert stdout.closed
    assert stderr.closed


def test_locked_session_reports_late_reader_error_during_cleanup() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = None
    session.stderr = None
    session._stream_readers = {}
    session._stream_errors = {"stderr": OSError("late stderr failure")}
    session._transaction_started = False
    session._lock_acquired = False
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "NOT_ATTEMPTED"

    with pytest.raises(staging_apply.StagingSessionStateError, match="stderr reader failed") as exc_info:
        session._close(success=False)

    assert exc_info.value.status == "SESSION_CLEANUP_BLOCKED"


def test_locked_session_reports_stream_close_failure_during_cleanup() -> None:
    class FakeStream:
        def close(self) -> None:
            raise OSError("stream close failed")

    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = FakeStream()
    session.stderr = None
    session._stream_readers = {}
    session._stream_errors = {}
    session._transaction_started = False
    session._lock_acquired = False
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "NOT_ATTEMPTED"

    with pytest.raises(staging_apply.StagingSessionStateError, match="stdout stream close failed") as exc_info:
        session._close(success=False)

    assert exc_info.value.status == "SESSION_CLEANUP_BLOCKED"


def test_locked_session_aggregates_cleanup_failures() -> None:
    class FakeStream:
        def __init__(self, name: str) -> None:
            self.name = name

        def close(self) -> None:
            raise OSError(f"{self.name} close failed")

    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = FakeStream("stdout")
    session.stderr = FakeStream("stderr")
    session._stream_readers = {}
    session._stream_errors = {
        "stdout": OSError("late stdout failure"),
        "stderr": OSError("late stderr failure"),
    }
    session._transaction_started = False
    session._lock_acquired = False
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "NOT_ATTEMPTED"

    with pytest.raises(staging_apply.StagingSessionStateError) as exc_info:
        session._close(success=False)

    message = str(exc_info.value)
    assert "late stdout failure" in message
    assert "late stderr failure" in message
    assert "stdout close failed" in message
    assert "stderr close failed" in message


def test_locked_session_blocks_when_post_kill_reap_times_out() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        def __init__(self) -> None:
            self.wait_calls = 0
            self.kill_calls = 0

        @staticmethod
        def poll() -> None:
            return None

        def wait(self, timeout: int | None = None) -> int:
            self.wait_calls += 1
            raise staging_apply.subprocess.TimeoutExpired("fake-mariadb", timeout or 0)

        def kill(self) -> None:
            self.kill_calls += 1
            raise OSError("kill blocked")

    process = FakeProcess()
    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = process
    session.stdout = None
    session.stderr = None
    session._stream_readers = {}
    session._stream_errors = {}
    session._transaction_started = False
    session._lock_acquired = False
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "NOT_ATTEMPTED"

    with pytest.raises(staging_apply.StagingSessionStateError, match="did not exit after cleanup") as exc_info:
        session._close(success=False)

    assert exc_info.value.status == "SESSION_CLEANUP_BLOCKED"
    assert "kill blocked" in str(exc_info.value)
    assert process.kill_calls == 1
    assert process.wait_calls == 2


def test_session_marks_commit_ack_loss_as_blocked() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

        @staticmethod
        def kill() -> None:
            return None

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = None
    session.stderr = None
    session._transaction_started = True
    session._lock_acquired = True
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "ACQUIRED"
    session.lock_name = "netlab-staging:test:apply"

    def execute(sql: str) -> str:
        if sql == "COMMIT":
            raise StagingApplyError("commit marker was lost")
        if sql.startswith("SELECT RELEASE_LOCK"):
            return "1\n"
        raise AssertionError(sql)

    session._execute_with_marker = execute
    with pytest.raises(staging_apply.StagingSessionStateError) as exc_info:
        session._close(success=True)

    exc = exc_info.value
    assert exc.status == "COMMIT_AMBIGUOUS_BLOCKED"
    assert exc.commit_state == "UNKNOWN"
    assert exc.lock_state == "RELEASED"


def test_session_marks_post_commit_lock_release_loss_as_blocked() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

        @staticmethod
        def kill() -> None:
            return None

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = None
    session.stderr = None
    session._transaction_started = True
    session._lock_acquired = True
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "ACQUIRED"
    session.lock_name = "netlab-staging:test:apply"

    def execute(sql: str) -> str:
        if sql == "COMMIT":
            return ""
        if sql.startswith("SELECT RELEASE_LOCK"):
            raise StagingApplyError("release marker was lost")
        raise AssertionError(sql)

    session._execute_with_marker = execute
    with pytest.raises(staging_apply.StagingSessionStateError) as exc_info:
        session._close(success=True)

    exc = exc_info.value
    assert exc.status == "COMMITTED_LOCK_RELEASE_BLOCKED"
    assert exc.commit_state == "COMMITTED"
    assert exc.lock_state == "UNKNOWN"


def test_session_blocks_commit_when_process_exits_before_lock_release() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        def __init__(self) -> None:
            self.exited = False
            self.stdin = FakeStdin()

        def poll(self) -> int | None:
            return 0 if self.exited else None

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 0

        @staticmethod
        def kill() -> None:
            return None

    process = FakeProcess()
    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = process
    session.stdout = None
    session.stderr = None
    session._transaction_started = True
    session._lock_acquired = True
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "ACQUIRED"
    session.lock_name = "netlab-staging:test:apply"

    def execute(sql: str) -> str:
        if sql == "COMMIT":
            process.exited = True
            return ""
        raise AssertionError(sql)

    session._execute_with_marker = execute
    with pytest.raises(staging_apply.StagingSessionStateError) as exc_info:
        session._close(success=True)

    exc = exc_info.value
    assert exc.status == "COMMITTED_LOCK_RELEASE_BLOCKED"
    assert exc.commit_state == "COMMITTED"
    assert exc.lock_state == "ACQUIRED"


def test_session_blocks_rollback_when_process_exits_before_cleanup() -> None:
    class FakeStdin:
        def close(self) -> None:
            return None

    class FakeProcess:
        stdin = FakeStdin()

        @staticmethod
        def poll() -> int:
            return 7

        @staticmethod
        def wait(timeout: int | None = None) -> int:
            return 7

    session = object.__new__(staging_apply._LockedMysqlSession)
    session.process = FakeProcess()
    session.stdout = None
    session.stderr = None
    session._stream_readers = {}
    session._stream_errors = {}
    session._transaction_started = True
    session._lock_acquired = True
    session._commit_state = "NOT_ATTEMPTED"
    session._lock_state = "ACQUIRED"

    with pytest.raises(staging_apply.StagingSessionStateError) as exc_info:
        session._close(success=False)

    exc = exc_info.value
    assert exc.status == "ROLLBACK_AMBIGUOUS_BLOCKED"
    assert exc.commit_state == "NOT_ATTEMPTED"
    assert exc.lock_state == "ACQUIRED"
    assert "COORDINATION_LOCK_RELEASE_BLOCKED" in str(exc)


def test_rollback_requires_live_innodb_session() -> None:
    with pytest.raises(StagingApplyError, match="active InnoDB coordination session"):
        staging_apply._restore_with_coordination(
            StagingTarget(),
            {"auto_increment": {}},
            [],
            coordination_session=None,
        )


def test_backup_apply_readback_requires_active_session() -> None:
    before = {"consistency_strategy": "single_transaction", "engines": ["INNODB"]}
    with pytest.raises(StagingApplyError, match="active coordination session"):
        staging_apply._backup_apply_readback(
            StagingTarget(),
            Path("D:/backup-root"),
            Path("D:/candidate/APPLY_STAGING.sql"),
            BytesIO(b"candidate"),
            [],
            before,
            {},
            {},
        )


def test_transaction_rollback_restores_auto_increment_in_same_session() -> None:
    session = object.__new__(staging_apply._LockedMysqlSession)
    session.tables = ["oc_product", "oc_product_description"]
    session.process = object()
    calls: list[str] = []
    session._assert_alive = lambda: None
    session._execute_with_marker = lambda sql: calls.append(sql) or ""

    result = session.rollback_transaction(
        {
            "auto_increment": {
                "oc_product": 17,
                "oc_product_description": None,
            }
        }
    )

    assert result["checks"] == {
        "transaction_rolled_back": True,
        "auto_increment_restored": True,
    }
    assert calls == [
        "ROLLBACK",
        "ALTER TABLE `oc_product` AUTO_INCREMENT = 17",
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "START TRANSACTION",
    ]


def test_locked_mysql_session_keeps_lock_until_query_and_unlock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeStream:
        def __init__(self) -> None:
            self.chunks: queue.Queue[bytes | None] = queue.Queue()
            self.closed = False

        def write(self, data: bytes) -> int:
            self.chunks.put(bytes(data))
            return len(data)

        def flush(self) -> None:
            return None

        def read1(self, _size: int) -> bytes:
            chunk = self.chunks.get()
            return b"" if chunk is None else chunk

        def close(self) -> None:
            if not self.closed:
                self.closed = True
                self.chunks.put(None)

    class FakeStdin:
        def __init__(self, owner: FakeProcess) -> None:
            self.owner = owner
            self.closed = False

        def write(self, data: bytes) -> int:
            self.owner.events.append(data.decode("utf-8"))
            self.owner.wire.append(data.decode("utf-8"))
            return len(data)

        def flush(self) -> None:
            self.owner.emit_markers()

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.stdout = FakeStream()
            self.stderr = FakeStream()
            self.returncode: int | None = None
            self.events: list[str] = []
            self.wire: list[str] = []
            self.stdin = FakeStdin(self)

        def emit_markers(self) -> None:
            assert hasattr(self.stdout, "write")
            for chunk in self.events:
                if "SELECT '" not in chunk:
                    continue
                for part in chunk.split("SELECT '")[1:]:
                    marker = part.split("'", 1)[0]
                    if marker.startswith("__NETLAB_SESSION_"):
                        if "GET_LOCK" in chunk or "RELEASE_LOCK" in chunk:
                            self.stdout.write(b"1\n")
                        self.stdout.write((marker + "\n").encode())  # type: ignore[attr-defined]
            self.stdout.flush()  # type: ignore[attr-defined]
            self.events.clear()

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: int | None = None) -> int:
            self.returncode = 0
            self.stdout.close()
            self.stderr.close()
            return 0

        def kill(self) -> None:
            self.returncode = -9
            self.stdout.close()
            self.stderr.close()

    processes: list[FakeProcess] = []

    def fake_popen(*_args: object, **kwargs: object) -> FakeProcess:
        assert kwargs["stdout"] is staging_apply.subprocess.PIPE
        assert kwargs["stderr"] is staging_apply.subprocess.PIPE
        process = FakeProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(staging_apply.subprocess, "Popen", fake_popen)
    with staging_apply._LockedMysqlSession(
        StagingTarget(),
        ["oc_product"],
        audit_table_exists=True,
    ) as session:
        session.run_candidate(
            BytesIO(
                (
                    "CREATE TABLE `oc_netlab_transfer_audit` ("
                    + ",".join(staging_apply._AUDIT_DDL_PARTS)
                    + ");\nSELECT 'candidate';\n"
                ).encode()
            ),
            audit_table_exists=True,
        )
        session.query("SELECT 42")

    events.extend(processes[0].wire)
    wire = "".join(events)
    assert "LOCK TABLES" not in wire
    assert wire.index("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE") < wire.index("START TRANSACTION")
    assert wire.index("START TRANSACTION") < wire.index("GET_LOCK")
    assert wire.index("GET_LOCK") < wire.index("SELECT 'candidate'")
    assert wire.index("SELECT 'candidate'") < wire.index("SELECT 42")
    assert wire.index("SELECT 42") < wire.index("COMMIT")
    assert wire.index("COMMIT") < wire.index("RELEASE_LOCK")


def test_backup_database_writes_same_session_before_state_metadata(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class Session:
        @staticmethod
        def assert_alive() -> None:
            calls.append("alive")

    before = {
        "products": 1,
        "engines": ["INNODB"],
        "consistency_strategy": "single_transaction",
        "auto_increment": {"oc_product": 4, "oc_product_description": None},
    }
    backup_root = tmp_path / "backup"
    backup_root.mkdir()
    result = staging_apply._backup_database(
        StagingTarget(),
        backup_root,
        before=before,
        coordination_session=Session(),
    )

    assert result == backup_root / "before-state.json"
    assert json.loads(result.read_text(encoding="utf-8")) == before
    assert calls == ["alive", "alive"]


def test_post_commit_receipt_failure_is_blocked_not_pass(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        staging_apply,
        "write_apply_result",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(StagingApplyError("final receipt unavailable")),
    )

    with pytest.raises(StagingApplyError, match="COMMITTED_RECEIPT_BLOCKED") as exc_info:
        staging_apply._finalize_committed_result(
            tmp_path,
            {"status": "COMMIT_PENDING", "pending_result_path": "pending"},
        )

    assert "'PASS'" not in str(exc_info.value)
    failure = json.loads((tmp_path / "APPLY_FAILURE.json").read_text(encoding="utf-8"))
    assert failure["status"] == "COMMITTED_RECEIPT_BLOCKED"


def test_backup_database_rejects_non_transactional_strategy(tmp_path: Path) -> None:
    class Session:
        @staticmethod
        def assert_alive() -> None:
            raise AssertionError("session must not be used")

    with pytest.raises(StagingApplyError, match="INNODB_REQUIRED"):
        staging_apply._backup_database(
            StagingTarget(),
            tmp_path,
            before={"engines": ["NONINNODB"]},
            consistency_strategy="legacy",
            coordination_session=Session(),
        )
