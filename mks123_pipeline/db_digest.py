from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
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


@contextmanager
def _captured_database(path: str | Path) -> Iterator[duckdb.DuckDBPyConnection]:
    from .integrity import read_evidence

    evidence = read_evidence(path, calculate_hash=False)
    with tempfile.TemporaryDirectory(prefix="mks123-duckdb-") as temp_dir:
        snapshot = Path(temp_dir) / "captured.duckdb"
        with snapshot.open("xb") as handle:
            handle.write(evidence.data)
            handle.flush()
            os.fsync(handle.fileno())
        with duckdb.connect(
            str(snapshot),
            read_only=True,
            config=DUCKDB_SAFE_CONFIG,
        ) as db:
            _validate_catalog_objects(db)
            yield db


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


def read_only_table_counts(
    path: str | Path,
    table_names: Iterable[str] = DUCKDB_TABLES,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    with _captured_database(path) as db:
        for name in table_names:
            if name not in DUCKDB_TABLES:
                raise ValueError(f"unexpected DuckDB table name: {name}")
            counts[name] = int(db.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0])
    return counts


def database_content_sha256(path: str | Path) -> str:
    tables = []
    with _captured_database(path) as db:
        for table in DUCKDB_TABLES:
            result = db.execute(f'SELECT * FROM "{table}"')
            columns = [column[0] for column in result.description]
            rows = [list(row) for row in result.fetchall()]
            rows.sort(key=lambda row: _canonical_bytes(row))
            tables.append({"table": table, "columns": columns, "rows": rows})
    return hashlib.sha256(_canonical_bytes(tables)).hexdigest()
