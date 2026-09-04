from __future__ import annotations

import hashlib
import json
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


def _canonical_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def database_content_sha256(path: str | Path) -> str:
    with duckdb.connect(str(path), read_only=True) as db:
        tables = []
        for table in DUCKDB_TABLES:
            result = db.execute(f"SELECT * FROM {table}")
            columns = [column[0] for column in result.description]
            rows = [list(row) for row in result.fetchall()]
            rows.sort(key=lambda row: _canonical_bytes(row))
            tables.append({"table": table, "columns": columns, "rows": rows})
    return hashlib.sha256(_canonical_bytes(tables)).hexdigest()
