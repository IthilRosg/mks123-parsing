from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import time as time_module
from collections import Counter
from collections.abc import Callable
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

if os.name == "nt":
    import msvcrt
else:
    import fcntl

import duckdb
import pandas as pd

from .adapters import ElectrozoneAdapter, SupplierAdapter
from .category_mapping import build_category_mapping
from .db_digest import DUCKDB_SAFE_CONFIG, database_content_sha256
from .integrity import build_run_seal, read_evidence
from .manifest import build_run_manifest, capture_run_inputs, write_run_manifest
from .matcher import CatalogItem, match_supplier_items
from .netlab_acquisition import (
    parse_netlab_acquisition_metadata,
    validate_netlab_acquisition_metadata,
    validate_netlab_properties_acquisition_metadata,
)
from .netlab_content import NetlabEnrichmentResult, enrich_netlab_snapshot
from .pricing import ExchangeRate, PricingContext, build_proposal
from .state import update_missing_state

_RUN_THREAD_LOCKS: dict[str, threading.Lock] = {}
_RUN_THREAD_LOCKS_GUARD = threading.Lock()
_REQUIRED_CATALOG_HEADERS = {
    "product_id",
    "model",
    "sku",
    "ean",
    "name",
    "manufacturer",
    "price",
    "quantity",
    "status",
    "category_ids",
    "categories",
}
_RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _sha256(path: Path) -> str:
    return read_evidence(path).sha256


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})


def _quote_duckdb_identifier(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        raise ValueError("DuckDB identifier is invalid")
    return f'"{value}"'


def _duckdb_text_value(value: Any) -> str:
    normalized = _csv_value(value)
    return "" if normalized is None else str(normalized)


def _write_duckdb(
    database: Path,
    specifications: list[tuple[str, list[str], list[dict[str, Any]]]],
) -> None:
    with duckdb.connect(str(database), config=DUCKDB_SAFE_CONFIG) as db:
        for index, (table_name, fieldnames, rows) in enumerate(specifications):
            table_identifier = _quote_duckdb_identifier(table_name)
            column_identifiers = [_quote_duckdb_identifier(name) for name in fieldnames]
            if not column_identifiers:
                raise ValueError("DuckDB table must have at least one column")
            if not rows:
                columns_sql = ", ".join(f"{name} VARCHAR" for name in column_identifiers)
                db.execute(f"CREATE TABLE {table_identifier} ({columns_sql})")
                continue
            dataframe = pd.DataFrame(
                {
                    name: [_duckdb_text_value(row.get(name)) for row in rows]
                    for name in fieldnames
                },
                columns=fieldnames,
            )
            view_name = f"_netlab_materialization_{index}"
            view_identifier = _quote_duckdb_identifier(view_name)
            db.register(view_name, dataframe)
            try:
                db.execute(f"CREATE TABLE {table_identifier} AS SELECT * FROM {view_identifier}")
            finally:
                db.unregister(view_name)
        db.execute("SET enable_external_access = 'false'")


@contextmanager
def _run_reservation(lock_path: Path, timeout: float = 30.0):
    key = str(lock_path.resolve())
    with _RUN_THREAD_LOCKS_GUARD:
        thread_lock = _RUN_THREAD_LOCKS.setdefault(key, threading.Lock())
    deadline = time_module.monotonic() + timeout
    remaining = max(0.0, deadline - time_module.monotonic())
    if not thread_lock.acquire(timeout=remaining):
        raise TimeoutError(f"timed out waiting for run reservation: {lock_path.name}")
    try:
        with lock_path.open("a+b") as handle:
            if os.name == "nt":
                if handle.seek(0, os.SEEK_END) == 0:
                    handle.write(b"\0")
                    handle.flush()
                    os.fsync(handle.fileno())
                while True:
                    try:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if time_module.monotonic() >= deadline:
                            raise TimeoutError(
                                f"timed out waiting for run reservation: {lock_path.name}"
                            ) from exc
                        time_module.sleep(0.02)
            else:
                while True:
                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError as exc:
                        if time_module.monotonic() >= deadline:
                            raise TimeoutError(
                                f"timed out waiting for run reservation: {lock_path.name}"
                            ) from exc
                        time_module.sleep(0.02)
            try:
                handle.seek(0)
                handle.truncate()
                handle.write(f"pid={os.getpid()}\n".encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
                yield
            finally:
                if os.name == "nt":
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        thread_lock.release()


def _remove_tree(path: Path) -> None:
    def onerror(function: Any, failed_path: str, exc_info: Any) -> None:
        if os.path.islink(failed_path):
            os.unlink(failed_path)
            return
        os.chmod(failed_path, stat.S_IREAD | stat.S_IWRITE)
        function(failed_path)

    if path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path, onerror=onerror)
    else:
        path.unlink(missing_ok=True)


def _remove_abandoned_staging(output_dir: Path) -> None:
    pattern = f".{output_dir.name}.stage-*"
    for candidate in output_dir.parent.glob(pattern):
        if candidate.is_dir():
            _remove_tree(candidate)
        else:
            candidate.unlink(missing_ok=True)


def _load_catalog(path: Path, *, sku_prefix: str = "11") -> tuple[list[CatalogItem], str]:
    evidence = read_evidence(path)
    source_bytes = evidence.data
    source_hash = evidence.sha256
    result: list[CatalogItem] = []
    with io.StringIO(source_bytes.decode("utf-8-sig"), newline="") as handle:
        reader = csv.DictReader(handle)
        headers = reader.fieldnames
        if not headers:
            raise ValueError("catalog CSV header is required")
        if any(header is None or not header.strip() for header in headers):
            raise ValueError("catalog CSV contains an empty header")
        normalized_headers = [header.strip() for header in headers]
        duplicates = sorted({header for header in normalized_headers if normalized_headers.count(header) > 1})
        if duplicates:
            raise ValueError(f"duplicate catalog header: {', '.join(duplicates)}")
        missing = sorted(_REQUIRED_CATALOG_HEADERS - set(normalized_headers))
        if missing:
            raise ValueError(f"missing catalog headers: {', '.join(missing)}")
        if normalized_headers != headers:
            raise ValueError("catalog headers must not contain surrounding whitespace")
        seen_product_ids: set[int] = set()
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"catalog row has extra fields at line {line_number}")
            if any(value is None for value in row.values()):
                raise ValueError(f"catalog row has missing fields at line {line_number}")
            try:
                product_id = int((row["product_id"] or "").strip())
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid catalog product_id at line {line_number}") from exc
            if product_id <= 0:
                raise ValueError(f"catalog product_id must be positive at line {line_number}")
            if product_id in seen_product_ids:
                raise ValueError(f"duplicate catalog product_id: {product_id}")
            seen_product_ids.add(product_id)
            sku = (row["sku"] or "").strip()
            if not sku:
                raise ValueError(f"catalog sku is required at line {line_number}")
            price_text = (row["price"] or "0").strip()
            try:
                price = Decimal(price_text)
            except (InvalidOperation, ValueError) as exc:
                raise ValueError(f"invalid catalog price at line {line_number}") from exc
            if not price.is_finite() or price < 0:
                raise ValueError(f"catalog price must be finite and nonnegative at line {line_number}")
            quantity_text = (row["quantity"] or "0").strip()
            status_text = (row["status"] or "0").strip()
            try:
                quantity = int(quantity_text)
                status = int(status_text)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid catalog quantity/status at line {line_number}") from exc
            if quantity < 0:
                raise ValueError(f"catalog quantity must be nonnegative at line {line_number}")
            if not sku.startswith(sku_prefix):
                continue
            result.append(CatalogItem(
                product_id=product_id,
                sku=sku,
                model=(row["model"] or "").strip(),
                ean=(row["ean"] or "").strip(),
                manufacturer=(row["manufacturer"] or "").strip(),
                name=(row["name"] or "").strip(),
                price=price,
                quantity=quantity,
                status=status,
                category_ids=(row["category_ids"] or "").strip(),
                categories=(row["categories"] or "").strip(),
            ))
    return result, source_hash


def _validate_adapter_snapshot(
    snapshot: Any,
    adapter: SupplierAdapter,
    source_path: Path,
    *,
    min_items: int,
    max_items: int,
) -> None:
    if snapshot.source_sha256 != _sha256(source_path):
        raise ValueError("adapter snapshot source hash mismatch")
    item_count = len(snapshot.items)
    if item_count < min_items or item_count > max_items:
        raise ValueError(f"adapter snapshot item count outside configured bounds: {item_count}")
    if not snapshot.items:
        raise ValueError("adapter snapshot must contain at least one item")
    seen_ids: set[str] = set()
    seen_skus: set[str] = set()
    for item in snapshot.items:
        if item.supplier != adapter.supplier_id:
            raise ValueError("adapter snapshot supplier identity mismatch")
        if not item.supplier_item_id or item.supplier_item_id in seen_ids:
            raise ValueError("adapter snapshot supplier item id is not unique")
        if not item.catalog_sku.startswith(adapter.catalog_sku_prefix):
            raise ValueError("adapter snapshot catalog SKU prefix mismatch")
        if item.catalog_sku in seen_skus:
            raise ValueError("adapter snapshot generated catalog SKU is not unique")
        if item.currency not in snapshot.currencies:
            raise ValueError(f"adapter snapshot currency is not declared: {item.currency}")
        if not item.name.strip():
            raise ValueError(f"adapter snapshot item name is required: {item.supplier_item_id}")
        if not re.fullmatch(r"[0-9a-f]{64}", item.raw_hash):
            raise ValueError(f"adapter snapshot raw hash is invalid: {item.supplier_item_id}")
        seen_ids.add(item.supplier_item_id)
        seen_skus.add(item.catalog_sku)


def _build_pilot(
    source_path: str | Path,
    catalog_csv: str | Path,
    output_dir: str | Path,
    fetched_at: str,
    *,
    min_source_items: int = 1,
    max_source_items: int = 100_000,
    max_source_bytes: int = 64 * 1024 * 1024,
    adapter: SupplierAdapter | None = None,
    pricing: PricingContext | None = None,
    pricing_resolver: Callable[[Any], PricingContext] | None = None,
    config_path: str | Path | None = None,
    source_metadata_path: str | Path | None = None,
    properties_path: str | Path | None = None,
    properties_metadata_path: str | Path | None = None,
    properties_fetched_at: str | None = None,
    previous_state_path: str | Path | None = None,
    missing_product_action: str | None = None,
    consecutive_missing_runs: int | None = None,
    seal_canonical_root: str | Path | None = None,
) -> dict[str, Any]:
    source_path = Path(source_path)
    catalog_csv = Path(catalog_csv)
    output_dir = Path(output_dir)
    original_source_path = source_path
    original_catalog_path = catalog_csv
    original_config_path = Path(config_path) if config_path is not None else None
    original_source_metadata_path = Path(source_metadata_path) if source_metadata_path is not None else None
    original_properties_path = Path(properties_path) if properties_path is not None else None
    original_properties_metadata_path = (
        Path(properties_metadata_path) if properties_metadata_path is not None else None
    )
    original_state_path = Path(previous_state_path) if previous_state_path is not None else None
    input_records, source_path, catalog_csv, _, bundled_state, bundled_source_metadata, bundled_properties, bundled_properties_metadata = capture_run_inputs(
        output_dir,
        source_path,
        catalog_csv,
        original_config_path,
        original_state_path,
        source_metadata_path=original_source_metadata_path,
        properties_path=original_properties_path,
        properties_metadata_path=original_properties_metadata_path,
        source_max_bytes=max_source_bytes,
    )

    adapter = adapter or ElectrozoneAdapter()
    if adapter.supplier_id != "netlab" and (
        bundled_properties is not None or bundled_properties_metadata is not None
    ):
        raise ValueError("properties enrichment is supported only for the Netlab adapter")
    if adapter.supplier_id == "netlab" and (
        source_path.suffix.casefold() != ".zip" or bundled_source_metadata is None
    ):
        raise ValueError(
            "Netlab pricing requires an accepted immutable supplier ZIP with acquisition metadata"
        )
    snapshot = adapter.parse(
        source_path,
        fetched_at=fetched_at,
        min_items=min_source_items,
        max_items=max_source_items,
        max_bytes=max_source_bytes,
    )
    _validate_adapter_snapshot(
        snapshot,
        adapter,
        source_path,
        min_items=min_source_items,
        max_items=max_source_items,
    )
    if adapter.supplier_id == "netlab":
        metadata_payload = parse_netlab_acquisition_metadata(read_evidence(bundled_source_metadata).data)
        validate_netlab_acquisition_metadata(
            metadata_payload,
            source_data=read_evidence(source_path).data,
            expected_fetched_at=fetched_at,
            expected_catalog_date=snapshot.catalog_date,
            expected_item_count=len(snapshot.items),
            expected_currency_rates=snapshot.currencies,
        )
    content_result: NetlabEnrichmentResult | None = None
    if bundled_properties is not None and bundled_properties_metadata is not None:
        if adapter.supplier_id != "netlab":
            raise ValueError("properties enrichment is supported only for the Netlab adapter")
        content_result = enrich_netlab_snapshot(snapshot, bundled_properties, max_bytes=max_source_bytes)
        properties_metadata = parse_netlab_acquisition_metadata(read_evidence(bundled_properties_metadata).data)
        validate_netlab_properties_acquisition_metadata(
            properties_metadata,
            source_data=read_evidence(bundled_properties).data,
            expected_fetched_at=properties_fetched_at or fetched_at,
            expected_catalog_date=content_result.properties_stats.catalog_date,
            expected_stats=content_result.properties_stats,
        )
        snapshot = snapshot.model_copy(update={"items": content_result.items})
    if pricing is not None and pricing_resolver is not None:
        raise ValueError("pricing and pricing_resolver are mutually exclusive")
    if pricing_resolver is not None:
        pricing = pricing_resolver(snapshot)
    catalog, catalog_sha256 = _load_catalog(catalog_csv, sku_prefix=adapter.catalog_sku_prefix)
    catalog_by_id = {item.product_id: item for item in catalog}
    supplier_by_id = {item.supplier_item_id: item for item in snapshot.items}
    match_result = match_supplier_items(snapshot.items, catalog)
    missing_products = {
        str(product_id): catalog_by_id[product_id].sku
        for product_id in match_result.catalog_missing_supplier
    }
    feed_complete = not missing_products
    previous_state: dict[str, Any] | None = None
    if bundled_state is not None:
        try:
            previous_state = json.loads(read_evidence(bundled_state).data.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid previous missing-product state") from exc
    state_run_id = f"{adapter.supplier_id}-{snapshot.source_sha256[:12]}-catalog-{catalog_sha256[:12]}"
    next_state, missing_decision = update_missing_state(
        previous_state,
        supplier=adapter.supplier_id,
        run_id=state_run_id,
        complete=feed_complete,
        missing_products=missing_products,
        action=missing_product_action,
        threshold=consecutive_missing_runs,
    )

    for directory in ("normalized", "matches", "proposals", "reports", "logs", "state"):
        (output_dir / directory).mkdir(parents=True, exist_ok=True)

    if pricing is None:
        rates: dict[str, ExchangeRate] = {}
        if snapshot.currencies.get("RUR") == Decimal(1):
            rates["RUR"] = ExchangeRate(currency="RUR", rub_per_unit=Decimal(1), source=f"{adapter.supplier_id}-source", observed_at=snapshot.catalog_date or fetched_at)
        pricing = PricingContext(rates=rates, rule=None, vat_basis="unknown")
    else:
        rates = pricing.rates
    proposals = []
    for match in match_result.matches:
        supplier = supplier_by_id[match.supplier_item_id]
        current = Decimal(0)
        if match.catalog_product_id is not None:
            current = catalog_by_id[match.catalog_product_id].price
        proposals.append(build_proposal(supplier, match, current, pricing))

    normalized_rows = [item.model_dump(mode="json") for item in snapshot.items]
    match_rows = [item.model_dump(mode="json") for item in match_result.matches]
    proposal_rows = [item.model_dump(mode="json") for item in proposals]
    category_mapping_rows, product_category_rows, category_mapping_summary = build_category_mapping(
        normalized_rows,
        match_rows,
        {item.product_id: item.model_dump(mode="json") for item in catalog},
    )
    source_only_rows = [
        supplier_by_id[match.supplier_item_id].model_dump(mode="json")
        for match in match_result.matches
        if match.status == "unmatched"
    ]
    review_queue_rows: list[dict[str, Any]] = []
    for match in match_result.matches:
        if match.status not in {"conflict", "high_confidence", "ambiguous"}:
            continue
        source = supplier_by_id[match.supplier_item_id]
        catalog_item = catalog_by_id.get(match.catalog_product_id) if match.catalog_product_id is not None else None
        review_queue_rows.append({
            "status": match.status,
            "matched_by": match.matched_by,
            "warnings": match.warnings,
            "confidence": match.confidence,
            "supplier_item_id": source.supplier_item_id,
            "source_catalog_sku": source.catalog_sku,
            "product_id": catalog_item.product_id if catalog_item else None,
            "catalog_sku": catalog_item.sku if catalog_item else None,
            "source_name": source.name,
            "catalog_name": catalog_item.name if catalog_item else None,
            "source_mpn": source.mpn,
            "catalog_model": catalog_item.model if catalog_item else None,
            "source_ean": source.ean,
            "catalog_ean": catalog_item.ean if catalog_item else None,
            "source_manufacturer": source.manufacturer,
            "catalog_manufacturer": catalog_item.manufacturer if catalog_item else None,
            "source_price": source.source_price,
            "current_price": catalog_item.price if catalog_item else None,
            "source_available": source.available,
            "catalog_quantity": catalog_item.quantity if catalog_item else None,
        })
    normalized_fields = list(normalized_rows[0]) if normalized_rows else ["supplier_item_id"]
    match_fields = list(match_rows[0]) if match_rows else ["supplier_item_id"]
    proposal_fields = list(proposal_rows[0]) if proposal_rows else ["supplier_item_id"]
    _write_csv(output_dir / "normalized/items.csv", normalized_rows, normalized_fields)
    _write_jsonl(output_dir / "normalized/items.jsonl", normalized_rows)
    _write_csv(output_dir / "matches/matches.csv", match_rows, match_fields)
    _write_csv(output_dir / "matches/source_only.csv", source_only_rows, normalized_fields)
    review_queue_fields = [
        "status", "matched_by", "warnings", "confidence", "supplier_item_id", "source_catalog_sku",
        "product_id", "catalog_sku", "source_name", "catalog_name", "source_mpn", "catalog_model",
        "source_ean", "catalog_ean", "source_manufacturer", "catalog_manufacturer", "source_price",
        "current_price", "source_available", "catalog_quantity",
    ]
    _write_csv(output_dir / "matches/review_queue.csv", review_queue_rows, review_queue_fields)
    catalog_missing_rows = [
        {"product_id": product_id, "sku": catalog_by_id[product_id].sku}
        for product_id in match_result.catalog_missing_supplier
    ]
    _write_csv(
        output_dir / "matches/catalog_missing_supplier.csv",
        catalog_missing_rows,
        ["product_id", "sku"],
    )
    _write_csv(output_dir / "proposals/proposals.csv", proposal_rows, proposal_fields)
    category_mapping_fields = list(category_mapping_rows[0]) if category_mapping_rows else ["source_category_path"]
    product_category_fields = list(product_category_rows[0]) if product_category_rows else ["supplier_item_id"]
    _write_csv(output_dir / "proposals/category-mapping-proposals.csv", category_mapping_rows, category_mapping_fields)
    _write_csv(output_dir / "proposals/product-category-proposals.csv", product_category_rows, product_category_fields)

    match_counts = dict(sorted(Counter(item.status for item in match_result.matches).items()))
    proposal_counts = dict(sorted(Counter(item.status for item in proposals).items()))
    price_comparison = {"equal": 0, "source_higher": 0, "source_lower": 0}
    availability_comparison = {
        "agree_in_stock": 0,
        "agree_out_of_stock": 0,
        "source_in_catalog_out": 0,
        "source_out_catalog_in": 0,
    }
    for match in match_result.matches:
        if match.status != "exact" or match.catalog_product_id is None:
            continue
        supplier = supplier_by_id[match.supplier_item_id]
        catalog_item = catalog_by_id[match.catalog_product_id]
        if supplier.currency != "RUR" or "RUR" not in rates:
            price_comparison["not_comparable"] = price_comparison.get("not_comparable", 0) + 1
        elif supplier.source_price == catalog_item.price:
            price_comparison["equal"] += 1
        elif supplier.source_price > catalog_item.price:
            price_comparison["source_higher"] += 1
        else:
            price_comparison["source_lower"] += 1
        catalog_available = catalog_item.quantity > 0
        if supplier.available and catalog_available:
            availability_comparison["agree_in_stock"] += 1
        elif not supplier.available and not catalog_available:
            availability_comparison["agree_out_of_stock"] += 1
        elif supplier.available:
            availability_comparison["source_in_catalog_out"] += 1
        else:
            availability_comparison["source_out_catalog_in"] += 1
    source_identity = {
        "with_ean": sum(1 for item in snapshot.items if item.ean),
        "with_mpn": sum(1 for item in snapshot.items if item.mpn),
        "with_image": sum(1 for item in snapshot.items if item.image_urls),
    }
    (output_dir / "state/next-missing-state.json").write_text(
        json.dumps(next_state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    coverage_ratio = (
        Decimal(len(snapshot.items)) / Decimal(len(catalog))
        if catalog
        else Decimal(1)
    )
    content_summary: dict[str, Any]
    if content_result is None:
        content_summary = {"enabled": False, "reason": "properties_input_not_provided"}
    else:
        stats = content_result.properties_stats
        content_summary = {
            "enabled": True,
            "join_key": "price_offer.uid=GoodsProperties.item.@id",
            "description_property_id": "p9999995",
            "properties_source_sha256": stats.source_sha256,
            "properties_catalog_date": stats.catalog_date,
            "properties_item_count": stats.item_count,
            "properties_count": stats.property_count,
            "properties_observation_count": stats.observation_count,
            "properties_missing_observation_count": stats.missing_observation_count,
            "unknown_property_id_count": stats.unknown_property_id_count,
            "unknown_observation_count": stats.unknown_observation_count,
            "uid_price_items": content_result.uid_price_items,
            "uid_properties_overlap": content_result.uid_properties_overlap,
            "description_items": content_result.description_items,
            "invalid_image_url_count": content_result.invalid_image_url_count,
            "missing_uid_count": content_result.missing_uid_count,
            "duplicate_uid_count": content_result.duplicate_uid_count,
            "properties_fetched_at": properties_fetched_at or fetched_at,
            "detail_pages": "not_fetched",
            "review_only_unknown_properties": True,
        }
    summary = {
        "supplier": adapter.supplier_id,
        "catalog_sku_prefix": adapter.catalog_sku_prefix,
        "mode": "read_only",
        "source_file": original_source_path.name,
        "source_sha256": snapshot.source_sha256,
        "catalog_sha256": catalog_sha256,
        "source_catalog_date": snapshot.catalog_date,
        "fetched_at": fetched_at,
        "source_items": len(snapshot.items),
        "source_available": sum(1 for item in snapshot.items if item.available),
        "catalog_scope_items": len(catalog),
        "matches": match_counts,
        "review_queue": len(review_queue_rows),
        "source_only": len(source_only_rows),
        "catalog_missing_supplier": len(match_result.catalog_missing_supplier),
        "feed_completeness": {
            "status": "complete" if feed_complete else "blocked_incomplete",
            "source_to_catalog_ratio": str(coverage_ratio),
            "catalog_covered_ratio": str(Decimal(len(catalog) - len(missing_products)) / Decimal(len(catalog))) if catalog else "1",
            "missing_actions_allowed": False,
            "reason": "all_catalog_scope_items_seen" if feed_complete else "source_does_not_cover_catalog_scope",
        },
        "missing_product_policy": {
            "configured_action": missing_product_action,
            "consecutive_missing_runs": consecutive_missing_runs,
            "production_writes": 0,
        },
        "missing_product_state": missing_decision,
        "proposals": proposal_counts,
        "exact_source_price_vs_current": price_comparison,
        "exact_availability_vs_catalog": availability_comparison,
        "source_identity": source_identity,
        "content_enrichment": content_summary,
        "category_mapping": category_mapping_summary,
        "vat_basis": pricing.vat_basis,
        "markup_policy": (
            f"{pricing.rule.id}@{pricing.rule.version}"
            if pricing.rule is not None and pricing.rule.approved
            else "not_approved"
        ),
        "production_writes": 0,
    }
    (output_dir / "reports/summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = [
        f"# {adapter.supplier_id} read-only pilot",
        "",
        f"- Source items: {summary['source_items']}",
        f"- Available: {summary['source_available']}",
        f"- Catalog scope (`SKU {adapter.catalog_sku_prefix}*`): {summary['catalog_scope_items']}",
        f"- Match statuses: `{json.dumps(match_counts, ensure_ascii=False, sort_keys=True)}`",
        f"- Review queue: {len(review_queue_rows)}",
        f"- Source-only offers: {len(source_only_rows)}",
        f"- Catalog products absent from source: {summary['catalog_missing_supplier']}",
        f"- Proposal statuses: `{json.dumps(proposal_counts, ensure_ascii=False, sort_keys=True)}`",
        f"- Exact-match source/current price comparison: `{json.dumps(price_comparison, ensure_ascii=False, sort_keys=True)}`",
        f"- Exact-match availability comparison: `{json.dumps(availability_comparison, ensure_ascii=False, sort_keys=True)}`",
        f"- Source identity coverage: `{json.dumps(source_identity, ensure_ascii=False, sort_keys=True)}`",
        f"- Content enrichment: `{json.dumps(content_summary, ensure_ascii=False, sort_keys=True)}`",
        f"- Category mapping proposals: `{json.dumps(category_mapping_summary, ensure_ascii=False, sort_keys=True)}`",
        f"- VAT basis: {summary['vat_basis']}.",
        f"- Markup policy: {summary['markup_policy']}.",
        "- Production writes: 0.",
    ]
    (output_dir / "reports/REPORT.md").write_text("\n".join(report) + "\n", encoding="utf-8")

    database = output_dir / "pilot.duckdb"
    _write_duckdb(
        database,
        [
            ("normalized_items", normalized_fields, normalized_rows),
            ("matches", match_fields, match_rows),
            ("source_only", normalized_fields, source_only_rows),
            ("review_queue", review_queue_fields, review_queue_rows),
            ("proposals", proposal_fields, proposal_rows),
            ("category_mapping_proposals", category_mapping_fields, category_mapping_rows),
            ("product_category_proposals", product_category_fields, product_category_rows),
            ("catalog_missing_supplier", ["product_id", "sku"], catalog_missing_rows),
        ],
    )
    summary["duckdb_content_sha256"] = database_content_sha256(database)
    (output_dir / "reports/summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = build_run_manifest(
        output_dir,
        source_path=original_source_path,
        catalog_path=original_catalog_path,
        config_path=original_config_path,
        input_records=input_records,
        adapter=adapter,
        snapshot=snapshot,
        fetched_at=fetched_at,
        pricing=pricing,
        summary=summary,
    )
    write_run_manifest(output_dir / "run-manifest.json", manifest)
    build_run_seal(output_dir, canonical_path_root=seal_canonical_root)
    return summary


def run_pilot(
    source_path: str | Path,
    catalog_csv: str | Path,
    output_dir: str | Path,
    fetched_at: str,
    *,
    min_source_items: int = 1,
    max_source_items: int = 100_000,
    max_source_bytes: int = 64 * 1024 * 1024,
    adapter: SupplierAdapter | None = None,
    pricing: PricingContext | None = None,
    pricing_resolver: Callable[[Any], PricingContext] | None = None,
    config_path: str | Path | None = None,
    source_metadata_path: str | Path | None = None,
    properties_path: str | Path | None = None,
    properties_metadata_path: str | Path | None = None,
    properties_fetched_at: str | None = None,
    previous_state_path: str | Path | None = None,
    missing_product_action: str | None = None,
    consecutive_missing_runs: int | None = None,
) -> dict[str, Any]:
    output_dir = Path(output_dir)
    if not _RUN_NAME.fullmatch(output_dir.name):
        raise ValueError(f"invalid run name: {output_dir.name!r}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing run directory: {output_dir}")
    lock_path = output_dir.parent / f".{output_dir.name}.lock"
    with _run_reservation(lock_path):
        if os.path.lexists(output_dir):
            raise FileExistsError(f"Refusing to overwrite existing run directory: {output_dir}")
        _remove_abandoned_staging(output_dir)
        staging: Path | None = None
        try:
            staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-", dir=output_dir.parent))
            summary = _build_pilot(
                source_path,
                catalog_csv,
                staging,
                fetched_at,
                min_source_items=min_source_items,
                max_source_items=max_source_items,
                max_source_bytes=max_source_bytes,
                adapter=adapter,
                pricing=pricing,
                pricing_resolver=pricing_resolver,
                config_path=config_path,
                source_metadata_path=source_metadata_path,
                properties_path=properties_path,
                properties_metadata_path=properties_metadata_path,
                properties_fetched_at=properties_fetched_at,
                previous_state_path=previous_state_path,
                missing_product_action=missing_product_action,
                consecutive_missing_runs=consecutive_missing_runs,
                seal_canonical_root=output_dir,
            )
            try:
                os.rename(staging, output_dir)
            except FileExistsError as exc:
                raise FileExistsError(f"Refusing to overwrite existing run directory: {output_dir}") from exc
            staging = None
            return summary
        finally:
            if staging is not None:
                _remove_tree(staging)
