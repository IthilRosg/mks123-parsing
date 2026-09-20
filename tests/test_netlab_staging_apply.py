from __future__ import annotations

from pathlib import Path

import pytest

import mks123_pipeline.netlab_staging_apply as staging_apply
from mks123_pipeline.netlab_staging_apply import (
    StagingApplyError,
    StagingTarget,
    validate_candidate_sql,
    validate_staging_target,
)


def test_production_like_database_name_is_rejected() -> None:
    with pytest.raises(StagingApplyError, match="staging database"):
        validate_staging_target(StagingTarget(database="mks123_prod_stage"))


def test_non_loopback_host_is_rejected() -> None:
    with pytest.raises(StagingApplyError, match="loopback"):
        validate_staging_target(StagingTarget(host="10.0.0.8", database="mks123_stage_trial"))


def test_candidate_cannot_write_category_or_media_relations() -> None:
    sql = "INSERT INTO `oc_product_to_category` VALUES (1, 2);"
    with pytest.raises(StagingApplyError, match="out-of-scope|shape"):
        validate_candidate_sql(sql)


def test_candidate_requires_staging_markers() -> None:
    with pytest.raises(StagingApplyError, match="marker|columns"):
        validate_candidate_sql("INSERT INTO `oc_product` (`sku`) VALUES ('x');")


def test_attribute_mapping_scope_includes_explicit_candidate_exceptions() -> None:
    scope = staging_apply._candidate_attribute_scope(
        [{"target_sku": "3111"}],
        [{"source_sku": "3112", "reason": "target_schema_limit"}],
    )

    assert scope == frozenset({"3111", "3112"})


def test_loopback_staging_candidate_passes_static_guard(tmp_path: Path) -> None:
    candidate = (
        "SET NAMES utf8mb4;\n"
        f"CREATE TABLE `oc_netlab_transfer_audit` ({','.join(staging_apply._AUDIT_DDL_PARTS)}) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;\n"
        "SELECT 'NETLAB_TRANSFER_APPLY_DONE' AS marker, COUNT(*) AS audit_rows "
        "FROM `oc_netlab_transfer_audit` WHERE `run_id`=CONVERT(0x74657374 USING utf8mb4);\n"
        "SELECT 'NETLAB_TRANSFER_RELATIONS_CREATED' AS marker, 0 AS value;\n"
        "SELECT 'NETLAB_TRANSFER_MEDIA_ASSIGNMENTS' AS marker, 0 AS value;\n"
        "SELECT 'NETLAB_TRANSFER_PUBLICATION_ENABLED' AS marker, 0 AS value;\n"
    )
    path = tmp_path / "APPLY_STAGING.sql"
    path.write_text(candidate, encoding="utf-8")

    validate_staging_target(StagingTarget(database="mks123_stage_trial"))
    validate_candidate_sql(path.read_text(encoding="utf-8"))
