"""Build self-enforcing Netlab production SQL packets.

The packets put every data mutation inside a stored procedure with an EXIT
handler.  The handler rolls back on any SQL exception; expected scope/count
checks SIGNAL before COMMIT.  The caller still must verify the PASS marker.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CATALOG_TAIL = (
    "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`='netlab-production-transfer-20260918-r1';\n",
    "SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;\n",
    "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;\n",
)


def _ident(value: str, label: str) -> str:
    if not isinstance(value, str) or not _IDENT.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _sql(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _summary(path: Path, *, kind: str, **counts: int | str) -> dict[str, object]:
    return {
        "schema": "netlab-production-self-enforcing-packet-v1",
        "packet_kind": kind,
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "production_writes": 0,
        "publication_enabled": False,
        **counts,
    }


def _procedure_prefix(name: str, pass_marker: str, fail_marker: str) -> list[str]:
    return [
        f"DROP PROCEDURE IF EXISTS `{name}`;\n",
        "DELIMITER $$\n",
        f"CREATE PROCEDURE `{name}`()\n",
        "SQL SECURITY INVOKER\n",
        "BEGIN\n",
        "  DECLARE v_bad BIGINT DEFAULT 0;\n",
        "  DECLARE v_audit_rows BIGINT DEFAULT 0;\n",
        "  DECLARE v_update_rows BIGINT DEFAULT 0;\n",
        "  DECLARE v_create_rows BIGINT DEFAULT 0;\n",
        "  DECLARE v_product_rows BIGINT DEFAULT 0;\n",
        "  DECLARE v_gallery_rows BIGINT DEFAULT 0;\n",
        "  DECLARE v_published_rows BIGINT DEFAULT 0;\n",
        "  DECLARE EXIT HANDLER FOR SQLEXCEPTION\n",
        "  BEGIN\n",
        "    ROLLBACK;\n",
        f"    SELECT '{fail_marker}' AS marker;\n",
        "  END;\n",
    ]


def _procedure_suffix(name: str) -> list[str]:
    return [
        "END$$\n",
        "DELIMITER ;\n",
        f"CALL `{name}`();\n",
        f"DROP PROCEDURE IF EXISTS `{name}`;\n",
    ]


def _write_catalog_schema_preflight(out: object) -> None:
    lines = [
        (
            "  SELECT COUNT(*) INTO v_bad FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
            "AND table_type='BASE TABLE' AND engine='InnoDB' AND table_collation='utf8mb4_general_ci';\n"
        ),
        "  IF v_bad <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit table engine/collation mismatch'; END IF;\n",
        (
            "  SELECT COUNT(*) INTO v_bad FROM information_schema.columns "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' AND ("
            "(column_name='transfer_id' AND data_type='bigint' AND is_nullable='NO' AND extra='auto_increment') OR "
            "(column_name='run_id' AND data_type='varchar' AND character_maximum_length=128 AND is_nullable='NO') OR "
            "(column_name='supplier_item_id' AND data_type='varchar' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='source_sku' AND data_type='varchar' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='target_product_id' AND data_type='int' AND is_nullable='NO') OR "
            "(column_name='action' AND data_type='varchar' AND character_maximum_length=16 AND is_nullable='NO') OR "
            "(column_name='source_kind' AND data_type='varchar' AND character_maximum_length=32 AND is_nullable='NO') OR "
            "(column_name='verification_status' AND data_type='varchar' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='manufacturer_verified' AND data_type='tinyint' AND numeric_precision=3 AND is_nullable='NO') OR "
            "(column_name='source_url' AND data_type='text' AND is_nullable='NO') OR "
            "(column_name='source_raw_hash' AND data_type='char' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='source_fetched_at' AND data_type='varchar' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='source_artifact_path' AND data_type='text' AND is_nullable='NO') OR "
            "(column_name='source_artifact_sha256' AND data_type='char' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='matches_artifact_sha256' AND data_type='char' AND character_maximum_length=64 AND is_nullable='NO') OR "
            "(column_name='source_snapshot_json' AND data_type='longtext' AND is_nullable='NO') OR "
            "(column_name='properties_json' AND data_type='longtext' AND is_nullable='NO') OR "
            "(column_name='image_urls_json' AND data_type='longtext' AND is_nullable='NO') OR "
            "(column_name='category_json' AND data_type='longtext' AND is_nullable='NO') OR "
            "(column_name='after_json' AND data_type='longtext' AND is_nullable='NO') OR "
            "(column_name='transferred_at' AND data_type='datetime' AND is_nullable='NO'));\n"
        ),
        "  IF v_bad <> 21 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit table columns mismatch'; END IF;\n",
        (
            "  SELECT COUNT(*) INTO v_bad FROM information_schema.statistics "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
            "AND index_name='PRIMARY' AND non_unique=0 AND seq_in_index=1 AND column_name='transfer_id';\n"
        ),
        "  IF v_bad <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit primary key mismatch'; END IF;\n",
        (
            "  SELECT COUNT(*) INTO v_bad FROM information_schema.statistics "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
            "AND index_name='uq_netlab_transfer_run_sku' AND non_unique=0;\n"
        ),
        "  IF v_bad <> 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit unique key mismatch'; END IF;\n",
        (
            "  SELECT COUNT(*) INTO v_bad FROM information_schema.statistics "
            "WHERE table_schema=DATABASE() AND table_name='oc_netlab_transfer_audit' "
            "AND index_name='idx_netlab_transfer_target' AND non_unique=1 AND column_name='target_product_id';\n"
        ),
        "  IF v_bad <> 1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='audit target index mismatch'; END IF;\n",
    ]
    for line in lines:
        out.write(line)  # type: ignore[attr-defined]


def build_catalog_packet(
    source: Path,
    output: Path,
    *,
    run_id: str,
    expected_updates: int,
    expected_creates: int,
) -> dict[str, object]:
    _ident("netlab_catalog_" + run_id.replace("-", "_"), "catalog procedure name")
    if expected_updates < 0 or expected_creates < 0:
        raise ValueError("expected catalog counts must be non-negative")
    procedure = "netlab_catalog_" + re.sub(r"[^A-Za-z0-9_]", "_", run_id)
    expected_audit = expected_updates + expected_creates
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open("r", encoding="utf-8", newline="") as src, output.open(
        "w", encoding="utf-8", newline="\n"
    ) as dst:
        first, second, ddl = src.readline(), src.readline(), src.readline()
        if not first.startswith("SET SESSION sql_mode") or not second.startswith("SET NAMES"):
            raise ValueError("catalog header mismatch")
        if not ddl.startswith("CREATE TABLE `oc_netlab_transfer_audit` "):
            raise ValueError("catalog audit DDL missing")
        dst.write(first)
        dst.write(second)
        dst.write(ddl.replace("CREATE TABLE `oc_netlab_transfer_audit` ", "CREATE TABLE IF NOT EXISTS `oc_netlab_transfer_audit` ", 1))
        dst.write("\n")
        dst.writelines(_procedure_prefix(procedure, "NETLAB_CATALOG_PASS", "NETLAB_CATALOG_FAILED"))
        _write_catalog_schema_preflight(dst)
        dst.write(f"  SELECT COUNT(*) INTO v_bad FROM `oc_netlab_transfer_audit` WHERE `run_id`={_sql(run_id)};\n")
        dst.write("  IF v_bad <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='catalog run_id already exists'; END IF;\n")
        dst.write("  START TRANSACTION;\n")
        tail: list[str] = []
        for line in src:
            tail.append(line)
            if len(tail) > 3:
                body = tail.pop(0)
                if body.strip() != "START TRANSACTION;":
                    dst.write(body)
        if tuple(line.replace("\r\n", "\n") for line in tail) != _CATALOG_TAIL:
            raise ValueError("catalog terminal markers mismatch")
        dst.write(f"  SELECT COUNT(*) INTO v_audit_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`={_sql(run_id)};\n")
        dst.write(f"  SELECT COUNT(*) INTO v_update_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`={_sql(run_id)} AND `action`='update';\n")
        dst.write(f"  SELECT COUNT(*) INTO v_create_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`={_sql(run_id)} AND `action`='create';\n")
        dst.write(f"  IF v_audit_rows <> {expected_audit} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='catalog audit count mismatch'; END IF;\n")
        dst.write(f"  IF v_update_rows <> {expected_updates} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='catalog update count mismatch'; END IF;\n")
        dst.write(f"  IF v_create_rows <> {expected_creates} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='catalog create count mismatch'; END IF;\n")
        dst.write(f"  SELECT COUNT(*) INTO v_bad FROM `oc_product` p JOIN `oc_netlab_transfer_audit` a ON a.`target_product_id`=p.`product_id` WHERE a.`run_id`={_sql(run_id)} AND a.`action`='create' AND (p.`status`<>0 OR p.`noindex`<>1 OR p.`quantity`<>0);\n")
        dst.write("  IF v_bad <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='new product publication guard mismatch'; END IF;\n")
        dst.write("  COMMIT;\n")
        dst.write("  SELECT 'NETLAB_CATALOG_PASS' AS marker, v_audit_rows AS audit_rows, v_update_rows AS update_rows, v_create_rows AS create_rows;\n")
        dst.writelines(_procedure_suffix(procedure))
    return _summary(output, kind="catalog", run_id=run_id, expected_updates=expected_updates, expected_creates=expected_creates, expected_audit_rows=expected_audit)


def build_attribute_packet(source: Path, output: Path, *, expected_rows: int, min_id: int, max_id: int) -> dict[str, object]:
    if not (0 <= min_id <= max_id) or expected_rows <= 0:
        raise ValueError("invalid attribute seed bounds")
    procedure = "netlab_attribute_seed_" + str(min_id) + "_" + str(max_id)
    with source.open("r", encoding="utf-8", newline="") as src, output.open("w", encoding="utf-8", newline="\n") as dst:
        lines = src.readlines()
        if not lines or not lines[0].startswith("SET NAMES"):
            raise ValueError("attribute seed header mismatch")
        body = [line for line in lines[1:] if line.strip() not in {"START TRANSACTION;", "COMMIT;"}]
        dst.write(lines[0])
        dst.writelines(_procedure_prefix(procedure, "NETLAB_ATTRIBUTE_PASS", "NETLAB_ATTRIBUTE_FAILED"))
        dst.write("\n")
        dst.write(f"  SELECT COUNT(*) INTO v_bad FROM `oc_attribute` WHERE `attribute_id` BETWEEN {min_id} AND {max_id};\n")
        dst.write("  IF v_bad <> 0 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='attribute IDs already exist'; END IF;\n")
        dst.write("  START TRANSACTION;\n")
        dst.writelines("  " + line if line.strip() else line for line in body)
        dst.write(f"  SELECT COUNT(*) INTO v_product_rows FROM `oc_attribute` WHERE `attribute_id` BETWEEN {min_id} AND {max_id};\n")
        dst.write(f"  SELECT COUNT(*) INTO v_gallery_rows FROM `oc_attribute_description` WHERE `attribute_id` BETWEEN {min_id} AND {max_id} AND `language_id`=1;\n")
        dst.write(f"  IF v_product_rows <> {expected_rows} OR v_gallery_rows <> {expected_rows} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='attribute seed count mismatch'; END IF;\n")
        dst.write("  COMMIT;\n")
        dst.write("  SELECT 'NETLAB_ATTRIBUTE_PASS' AS marker, v_product_rows AS attribute_rows, v_gallery_rows AS description_rows;\n")
        dst.writelines(_procedure_suffix(procedure))
    return _summary(output, kind="attribute", expected_rows=expected_rows, min_id=min_id, max_id=max_id)


def _json_lines(path: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("media assignment row is not an object")
                rows.append(value)
    return rows


def build_media_packet(source: Path, output: Path, *, expected_products: int, expected_gallery: int) -> dict[str, object]:
    rows = _json_lines(source)
    if len(rows) != expected_products:
        raise ValueError("media product count mismatch")
    if len({row.get("catalog_sku") for row in rows}) != expected_products:
        raise ValueError("media SKU set is not unique")
    gallery: list[tuple[str, str, int]] = []
    for row in rows:
        sku = str(row.get("catalog_sku", ""))
        main = str(row.get("target_main_image", ""))
        images = row.get("target_gallery_images")
        if not sku or not main or not isinstance(images, list):
            raise ValueError("media assignment row is incomplete")
        for order, image in enumerate(images):
            gallery.append((sku, str(image), order))
    if len(gallery) != expected_gallery:
        raise ValueError("media gallery count mismatch")
    procedure = "netlab_media_20260919_r1"
    expected_name = "netlab_media_expected_20260919_r1"
    gallery_name = "netlab_media_gallery_20260919_r1"
    with output.open("w", encoding="utf-8", newline="\n") as dst:
        dst.write("SET NAMES utf8mb4;\n")
        dst.writelines(_procedure_prefix(procedure, "NETLAB_MEDIA_PASS", "NETLAB_MEDIA_FAILED"))
        dst.write(f"  CREATE TEMPORARY TABLE `{expected_name}` (`sku` VARCHAR(64) NOT NULL PRIMARY KEY, `main_image` TEXT NOT NULL, `gallery_count` INT NOT NULL) ENGINE=InnoDB;\n")
        dst.write(f"  INSERT INTO `{expected_name}` (`sku`,`main_image`,`gallery_count`) VALUES\n")
        values = []
        by_sku = {str(row["catalog_sku"]): row for row in rows}
        for sku in sorted(by_sku):
            row = by_sku[sku]
            values.append(f"({_sql(sku)},{_sql(row['target_main_image'])},{len(row['target_gallery_images'])})")
        dst.write(",\n".join(values) + ";\n")
        dst.write(f"  CREATE TEMPORARY TABLE `{gallery_name}` (`sku` VARCHAR(64) NOT NULL, `image` TEXT NOT NULL, `sort_order` INT NOT NULL, PRIMARY KEY (`sku`,`sort_order`)) ENGINE=InnoDB;\n")
        if gallery:
            dst.write(f"  INSERT INTO `{gallery_name}` (`sku`,`image`,`sort_order`) VALUES\n")
            dst.write(",\n".join(f"({_sql(sku)},{_sql(image)},{order})" for sku, image, order in gallery) + ";\n")
        dst.write(f"  SELECT COUNT(*) INTO v_product_rows FROM `{expected_name}` e JOIN `oc_product` p ON p.`sku`=e.`sku`;\n")
        dst.write(f"  IF v_product_rows <> {expected_products} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='media product identity count mismatch'; END IF;\n")
        dst.write(f"  SELECT COUNT(*) INTO v_gallery_rows FROM `{gallery_name}`;\n")
        dst.write(f"  IF v_gallery_rows <> {expected_gallery} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='media expected gallery count mismatch'; END IF;\n")
        dst.write("  START TRANSACTION;\n")
        dst.write(f"  UPDATE `oc_product` p JOIN `{expected_name}` e ON p.`sku`=e.`sku` SET p.`image`=e.`main_image`;\n")
        dst.write(f"  SELECT COUNT(*) INTO v_product_rows FROM `oc_product` p JOIN `{expected_name}` e ON p.`sku`=e.`sku` WHERE p.`image`=e.`main_image`;\n")
        dst.write(f"  IF v_product_rows <> {expected_products} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='media main image readback mismatch'; END IF;\n")
        dst.write(f"  DELETE pi FROM `oc_product_image` pi JOIN `oc_product` p ON p.`product_id`=pi.`product_id` JOIN `{expected_name}` e ON e.`sku`=p.`sku`;\n")
        dst.write(f"  INSERT INTO `oc_product_image` (`product_id`,`image`,`sort_order`) SELECT p.`product_id`,g.`image`,g.`sort_order` FROM `{gallery_name}` g JOIN `oc_product` p ON p.`sku`=g.`sku`;\n")
        dst.write(f"  SELECT COUNT(*) INTO v_gallery_rows FROM `oc_product_image` pi JOIN `oc_product` p ON p.`product_id`=pi.`product_id` JOIN `{expected_name}` e ON e.`sku`=p.`sku`;\n")
        dst.write(f"  IF v_gallery_rows <> {expected_gallery} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='media gallery readback mismatch'; END IF;\n")
        dst.write("  COMMIT;\n")
        dst.write("  SELECT 'NETLAB_MEDIA_PASS' AS marker, v_product_rows AS product_rows, v_gallery_rows AS gallery_rows;\n")
        dst.writelines(_procedure_suffix(procedure))
    return _summary(output, kind="media", expected_products=expected_products, expected_gallery=expected_gallery, assignment_rows=len(rows))


def build_publication_packet(output: Path, *, run_id: str, expected_creates: int) -> dict[str, object]:
    procedure = "netlab_publish_20260919_r1"
    with output.open("w", encoding="utf-8", newline="\n") as dst:
        dst.writelines(_procedure_prefix(procedure, "NETLAB_PUBLICATION_PASS", "NETLAB_PUBLICATION_FAILED"))
        dst.write(f"  SELECT COUNT(*) INTO v_audit_rows FROM `oc_netlab_transfer_audit` WHERE `run_id`={_sql(run_id)} AND `action`='create';\n")
        dst.write(f"  IF v_audit_rows <> {expected_creates} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='publication candidate count mismatch'; END IF;\n")
        dst.write("  START TRANSACTION;\n")
        dst.write(f"  UPDATE `oc_product` p JOIN `oc_netlab_transfer_audit` a ON a.`target_product_id`=p.`product_id` SET p.`status`=1,p.`noindex`=0 WHERE a.`run_id`={_sql(run_id)} AND a.`action`='create';\n")
        dst.write(f"  SELECT COUNT(*) INTO v_published_rows FROM `oc_product` p JOIN `oc_netlab_transfer_audit` a ON a.`target_product_id`=p.`product_id` WHERE a.`run_id`={_sql(run_id)} AND a.`action`='create' AND p.`status`=1 AND p.`noindex`=0;\n")
        dst.write(f"  IF v_published_rows <> {expected_creates} THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='publication readback count mismatch'; END IF;\n")
        dst.write("  COMMIT;\n")
        dst.write("  SELECT 'NETLAB_PUBLICATION_PASS' AS marker, v_published_rows AS published_rows;\n")
        dst.writelines(_procedure_suffix(procedure))
    return _summary(output, kind="publication", run_id=run_id, expected_creates=expected_creates)


def validate_packet_contract(path: Path, *, packet_kind: str) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if "DECLARE EXIT HANDLER FOR SQLEXCEPTION" not in text or "SIGNAL SQLSTATE '45000'" not in text:
        raise ValueError("packet lacks internal exception/validation handler")
    if text.count("START TRANSACTION;") != 1 or text.count("COMMIT;") != 1:
        raise ValueError("packet must contain exactly one transaction and commit")
    if "DROP TABLE" in text.upper() or "TRUNCATE TABLE" in text.upper() or "ALTER TABLE" in text.upper():
        raise ValueError("packet contains destructive schema SQL")
    if packet_kind == "catalog" and ("status`=1" in text or "noindex`=0" in text):
        raise ValueError("catalog packet contains publication mutation")
    if packet_kind == "publication" and "NETLAB_PUBLICATION_PASS" not in text:
        raise ValueError("publication pass marker missing")
    if packet_kind == "media" and "DELETE pi FROM `oc_product_image`" not in text:
        raise ValueError("media packet lacks scoped gallery replacement")
    return {"path": str(path), "sha256": _sha256(path), "bytes": path.stat().st_size, "packet_kind": packet_kind}
