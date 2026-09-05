from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import duckdb

DUCKDB_TABLES = (
    "normalized_items",
    "matches",
    "source_only",
    "review_queue",
    "proposals",
    "category_mapping_proposals",
    "product_category_proposals",
    "catalog_missing_supplier",
)
DUCKDB_SAFE_CONFIG = {
    "enable_external_access": "false",
    "autoload_known_extensions": "false",
    "autoinstall_known_extensions": "false",
}


def _canonical_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _assert_same_database_file(before: Any, path: Path) -> None:
    after = _read_database_identity(path)
    if before.file_identity != after.file_identity:
        raise ValueError("DuckDB evidence path changed during verification")


def _read_database_identity(path: str | Path) -> Any:
    from .integrity import read_evidence

    return read_evidence(path, max_bytes=0)


def _validate_catalog_objects(db: duckdb.DuckDBPyConnection) -> None:
    table_rows = db.execute(
        """
        SELECT table_schema, table_name, table_type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
        ORDER BY table_schema, table_name
        """
    ).fetchall()
    expected = {("main", table) for table in DUCKDB_TABLES}
    actual = {(str(schema), str(name)) for schema, name, _ in table_rows}
    if actual != expected or any(
        schema != "main" or table_type != "BASE TABLE"
        for schema, _, table_type in table_rows
    ):
        raise ValueError("DuckDB evidence must contain only expected base tables")
    macros = db.execute(
        """
        SELECT function_name, function_type
        FROM duckdb_functions()
        WHERE internal = false AND function_type IN ('macro', 'table_macro')
        """
    ).fetchall()
    if macros:
        names = ", ".join(sorted(str(name) for name, _ in macros))
        raise ValueError(f"DuckDB evidence contains user-defined macro: {names}")


def connect_read_only_database(path: str | Path) -> duckdb.DuckDBPyConnection:
    database_path = Path(path)
    before = _read_database_identity(database_path)
    db = duckdb.connect(
        str(database_path),
        read_only=True,
        config=DUCKDB_SAFE_CONFIG,
    )
    try:
        _validate_catalog_objects(db)
        _assert_same_database_file(before, database_path)
        return db
    except BaseException:
        db.close()
        raise


def read_only_table_counts(
    path: str | Path,
    table_names: Iterable[str] = DUCKDB_TABLES,
) -> dict[str, int]:
    database_path = Path(path)
    before = _read_database_identity(database_path)
    db = connect_read_only_database(database_path)
    try:
        counts: dict[str, int] = {}
        for name in table_names:
            if name not in DUCKDB_TABLES:
                raise ValueError(f"unexpected DuckDB table name: {name}")
            counts[name] = int(db.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0])
        return counts
    finally:
        db.close()
        _assert_same_database_file(before, database_path)


def database_content_sha256(path: str | Path) -> str:
    database_path = Path(path)
    before = _read_database_identity(database_path)
    db = connect_read_only_database(database_path)
    try:
        tables = []
        for table in DUCKDB_TABLES:
            result = db.execute(f'SELECT * FROM "{table}"')
            columns = [column[0] for column in result.description]
            rows = [list(row) for row in result.fetchall()]
            rows.sort(key=lambda row: _canonical_bytes(row))
            tables.append({"table": table, "columns": columns, "rows": rows})
    finally:
        db.close()
        _assert_same_database_file(before, database_path)
    return hashlib.sha256(_canonical_bytes(tables)).hexdigest()
