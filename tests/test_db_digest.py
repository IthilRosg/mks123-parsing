import inspect
from pathlib import Path

import duckdb
import pytest

from mks123_pipeline import integrity, manifest, runner, verifier
from mks123_pipeline.db_digest import DUCKDB_TABLES, database_content_sha256


def _create_expected_tables(path: Path) -> None:
    with duckdb.connect(str(path)) as db:
        for table in DUCKDB_TABLES:
            db.execute(f'CREATE TABLE "{table}" (value VARCHAR)')
            db.execute(f'INSERT INTO "{table}" VALUES (?)', [table])


def test_database_digest_rejects_view_instead_of_base_table(tmp_path: Path) -> None:
    path = tmp_path / "view.duckdb"
    _create_expected_tables(path)
    with duckdb.connect(str(path)) as db:
        db.execute('DROP TABLE "proposals"')
        db.execute('CREATE VIEW "proposals" AS SELECT * FROM "normalized_items"')

    with pytest.raises(ValueError, match="base table|view"):
        database_content_sha256(path)


def test_duckdb_writer_does_not_import_csv_by_path() -> None:
    source = inspect.getsource(runner._write_duckdb)
    assert "read_csv_auto" not in source
    assert "StringIO" in source
    assert "allowed_directories" in source


def test_sealed_paths_are_read_through_descriptor_bound_evidence() -> None:
    for module in (integrity, manifest, runner, verifier):
        source = inspect.getsource(module)
        assert ".read_bytes()" not in source
        assert ".read_text(" not in source
    assert "_open_windows_parent_directories" in inspect.getsource(integrity)


def test_database_digest_rejects_user_defined_macro(tmp_path: Path) -> None:
    path = tmp_path / "macro.duckdb"
    _create_expected_tables(path)
    with duckdb.connect(str(path)) as db:
        db.execute("CREATE MACRO user_macro(value) AS value")

    with pytest.raises(ValueError, match="macro"):
        database_content_sha256(path)
