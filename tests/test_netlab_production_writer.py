from __future__ import annotations

from pathlib import Path

import pytest

from mks123_pipeline.netlab_production_writer import (
    build_attribute_packet,
    build_catalog_packet,
    build_media_packet,
    build_publication_packet,
    validate_packet_contract,
)


def test_catalog_packet_has_internal_handler_and_count_guards(tmp_path: Path) -> None:
    source = tmp_path / "catalog.sql"
    source.write_text(
        "SET SESSION sql_mode = 'STRICT_ALL_TABLES';\n"
        "SET NAMES utf8mb4;\n"
        "CREATE TABLE `oc_netlab_transfer_audit` (`transfer_id` BIGINT NOT NULL AUTO_INCREMENT,`run_id` VARCHAR(128) NOT NULL,`supplier_item_id` VARCHAR(64) NOT NULL,`source_sku` VARCHAR(64) NOT NULL,`target_product_id` INT NOT NULL,`action` VARCHAR(16) NOT NULL,`source_kind` VARCHAR(32) NOT NULL,`verification_status` VARCHAR(64) NOT NULL,`manufacturer_verified` TINYINT(1) NOT NULL,`source_url` TEXT NOT NULL,`source_raw_hash` CHAR(64) NOT NULL,`source_fetched_at` VARCHAR(64) NOT NULL,`source_artifact_path` TEXT NOT NULL,`source_artifact_sha256` CHAR(64) NOT NULL,`matches_artifact_sha256` CHAR(64) NOT NULL,`source_snapshot_json` LONGTEXT NOT NULL,`properties_json` LONGTEXT NOT NULL,`image_urls_json` LONGTEXT NOT NULL,`category_json` LONGTEXT NOT NULL,`after_json` LONGTEXT NOT NULL,`transferred_at` DATETIME NOT NULL,PRIMARY KEY (`transfer_id`),UNIQUE KEY `uq_netlab_transfer_run_sku` (`run_id`, `source_sku`),KEY `idx_netlab_transfer_target` (`target_product_id`)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;\n"
        "SET @netlab_transfer_run_id = 'run';\n"
        "INSERT INTO `oc_netlab_transfer_audit` (`run_id`) VALUES ('run');\n"
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`='netlab-production-transfer-20260918-r1';\n"
        "SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;\n"
        "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;\n",
        encoding="utf-8",
    )
    out = tmp_path / "catalog-safe.sql"
    summary = build_catalog_packet(source, out, run_id="run", expected_updates=1, expected_creates=0)
    text = out.read_text(encoding="utf-8")
    assert "DECLARE EXIT HANDLER FOR SQLEXCEPTION" in text
    assert "SIGNAL SQLSTATE '45000'" in text
    assert "IF v_audit_rows <> 1" in text
    assert "IF v_update_rows <> 1" in text
    assert "IF v_create_rows <> 0" in text
    assert text.count("COMMIT;") == 1
    assert text.count("NETLAB_CATALOG_PASS") == 1
    assert "NETLAB_TRANSFER_COMMITTED" not in text
    assert summary["production_writes"] == 0


def test_attribute_media_publication_packets_are_self_enforcing(tmp_path: Path) -> None:
    attr = tmp_path / "attributes.sql"
    attr.write_text(
        "SET NAMES utf8mb4;\nSTART TRANSACTION;\n"
        "INSERT INTO `oc_attribute` VALUES (12853,1,0);\n"
        "INSERT INTO `oc_attribute_description` VALUES (12853,1,'x');\nCOMMIT;\n",
        encoding="utf-8",
    )
    attr_out = tmp_path / "attributes-safe.sql"
    attr_summary = build_attribute_packet(attr, attr_out, expected_rows=1, min_id=12853, max_id=12853)
    attr_text = attr_out.read_text(encoding="utf-8")
    assert "DECLARE EXIT HANDLER FOR SQLEXCEPTION" in attr_text
    assert "SIGNAL SQLSTATE '45000'" in attr_text
    assert attr_text.count("COMMIT;") == 1
    assert attr_summary["production_writes"] == 0

    assignments = tmp_path / "assignments.jsonl"
    assignments.write_text(
        '{"catalog_sku":"S1","target_main_image":"catalog/a.jpg","target_gallery_images":["catalog/b.jpg"]}\n',
        encoding="utf-8",
    )
    media_out = tmp_path / "media-safe.sql"
    media_summary = build_media_packet(assignments, media_out, expected_products=1, expected_gallery=1)
    media_text = media_out.read_text(encoding="utf-8")
    assert "CREATE TEMPORARY TABLE" in media_text
    assert "SIGNAL SQLSTATE '45000'" in media_text
    assert "v_product_rows <> 1" in media_text
    assert "v_gallery_rows <> 1" in media_text
    assert media_text.count("COMMIT;") == 1
    assert media_summary["production_writes"] == 0

    pub_out = tmp_path / "publication-safe.sql"
    pub_summary = build_publication_packet(pub_out, run_id="run", expected_creates=1)
    pub_text = pub_out.read_text(encoding="utf-8")
    assert "SIGNAL SQLSTATE '45000'" in pub_text
    assert "v_published_rows <> 1" in pub_text
    assert pub_text.count("COMMIT;") == 1
    assert pub_summary["production_writes"] == 0


def test_packet_contract_rejects_unconditional_commit_and_dangerous_scope(tmp_path: Path) -> None:
    bad = tmp_path / "bad.sql"
    bad.write_text("START TRANSACTION;\nUPDATE oc_product SET status=1;\nCOMMIT;\n", encoding="utf-8")
    with pytest.raises(ValueError):
        validate_packet_contract(bad, packet_kind="catalog")
