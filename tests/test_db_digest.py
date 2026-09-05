import inspect
from pathlib import Path
from typing import Self

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


def test_duckdb_writer_uses_in_memory_dataframe_registration() -> None:
    source = inspect.getsource(runner._write_duckdb)
    assert "read_csv_auto" not in source
    assert "read_csv" not in source
    assert "executemany" not in source
    assert "pd.DataFrame" in source
    assert "register" in source
    assert "DUCKDB_SAFE_CONFIG" in source


def test_duckdb_writer_uses_restricted_creation_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class _Connection:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *unused: object) -> None:
            return None

        def register(self, name: str, relation: object) -> None:
            observed.setdefault("registered", []).append((name, relation))

        def unregister(self, name: str) -> None:
            observed.setdefault("unregistered", []).append(name)

        def execute(self, statement: str) -> None:
            observed.setdefault("statements", []).append(statement)

        def executemany(self, statement: str, rows: object) -> None:
            observed["executemany"] = (statement, rows)

    def connect(path: str, *, config: dict[str, str]) -> _Connection:
        observed["path"] = path
        observed["config"] = config
        return _Connection()

    monkeypatch.setattr(runner.duckdb, "connect", connect)
    runner._write_duckdb(
        tmp_path / "pilot.duckdb",
        [("normalized_items", ["product_id"], [{"product_id": 1}])],
    )

    assert observed["config"] == {
        "enable_external_access": "false",
        "autoload_known_extensions": "false",
        "autoinstall_known_extensions": "false",
    }
    statements = observed["statements"]
    assert all("allowed_directories" not in statement for statement in statements)
    assert statements == [
        'CREATE TABLE "normalized_items" AS SELECT * FROM "_netlab_materialization_0"',
        "SET enable_external_access = 'false'",
    ]
    assert [name for name, _ in observed["registered"]] == ["_netlab_materialization_0"]


def test_duckdb_writer_materializes_rows_with_external_access_disabled(tmp_path: Path) -> None:
    database = tmp_path / "pilot.duckdb"
    runner._write_duckdb(
        database,
        [("normalized_items", ["product_id", "name"], [{"product_id": 1, "name": "Cable"}])],
    )

    with duckdb.connect(str(database), read_only=True, config=runner.DUCKDB_SAFE_CONFIG) as db:
        settings = {
            key: db.execute(f"SELECT current_setting('{key}')").fetchone()[0]
            for key in (
                "enable_external_access",
                "autoload_known_extensions",
                "autoinstall_known_extensions",
            )
        }
        row = db.execute('SELECT "product_id", "name" FROM "normalized_items"').fetchone()

    assert settings == {
        "enable_external_access": False,
        "autoload_known_extensions": False,
        "autoinstall_known_extensions": False,
    }
    assert row == ("1", "Cable")


def test_sealed_paths_are_read_through_descriptor_bound_evidence() -> None:
    for module in (integrity, manifest, runner, verifier):
        source = inspect.getsource(module)
        assert ".read_bytes()" not in source
        assert ".read_text(" not in source
    assert "_open_windows_parent_directories" in inspect.getsource(integrity)


def test_database_digest_uses_captured_bytes_after_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = tmp_path / "original.duckdb"
    replacement = tmp_path / "replacement.duckdb"
    _create_expected_tables(original)
    _create_expected_tables(replacement)
    with duckdb.connect(str(replacement)) as db:
        db.execute('UPDATE "proposals" SET value = ?', ["replacement"])

    expected = database_content_sha256(original)
    real_read_evidence = integrity.read_evidence
    swapped = False

    def capture_then_swap(path: str | Path, *args: object, **kwargs: object):
        nonlocal swapped
        evidence = real_read_evidence(path, *args, **kwargs)
        if Path(path) == original and not swapped:
            swapped = True
            original.unlink()
            replacement.rename(original)
        return evidence

    monkeypatch.setattr(integrity, "read_evidence", capture_then_swap)

    assert database_content_sha256(original) == expected
    assert swapped is True


def test_database_digest_rejects_user_defined_macro(tmp_path: Path) -> None:
    path = tmp_path / "macro.duckdb"
    _create_expected_tables(path)
    with duckdb.connect(str(path)) as db:
        db.execute("CREATE MACRO user_macro(value) AS value")

    with pytest.raises(ValueError, match="macro"):
        database_content_sha256(path)
