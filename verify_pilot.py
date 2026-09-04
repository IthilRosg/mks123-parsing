from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from uuid import uuid4

import duckdb
from defusedxml import ElementTree as ET

from mks123_pipeline.integrity import load_sealed_run, read_evidence

ROOT = Path(r"D:/Sites/mks123/.ops-tmp/electrozone-pilot")
RUN = ROOT / "runs/electrozone-07981576-catalog-49471b9f-v10"
SOURCE = ROOT / "raw/electrozone-live-20260901T1810-07981576b831.yml"
SOURCE_META = ROOT / "raw/electrozone-live-20260901T1810-07981576b831.metadata.json"
CATALOG = Path(r"D:/Sites/mks123/.ops-tmp/catalog-audit/snapshot/catalog-products.csv")
VERIFICATION_ROOT = ROOT / "verification"


def csv_rows(data: bytes) -> list[dict[str, str]]:
    with io.StringIO(data.decode("utf-8-sig"), newline="") as handle:
        return list(csv.DictReader(handle))


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}-{uuid4().hex}.part"
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


checks: dict[str, dict[str, object]] = {}


def check(name: str, condition: bool, detail: object) -> None:
    checks[name] = {"passed": bool(condition), "detail": detail}


source = read_evidence(SOURCE)
source_metadata = read_evidence(SOURCE_META)
catalog = read_evidence(CATALOG)
sealed_run = load_sealed_run(RUN)
run_files = sealed_run.files
check("run_seal", True, {"files": len(run_files), "seal_sha256": sealed_run.seal_evidence.sha256})

summary = json.loads(run_files["reports/summary.json"].data.decode("utf-8"))
metadata = json.loads(source_metadata.data.decode("utf-8"))
check("source_hash_manifest", source.sha256 == metadata["sha256"], source.sha256)
check("source_hash_run", source.sha256 == summary["source_sha256"], source.sha256)
check("catalog_hash_run", catalog.sha256 == summary["catalog_sha256"], catalog.sha256)

root = ET.fromstring(source.data)
offers = root.findall("./shop/offers/offer")
offer_ids = [node.attrib.get("id", "") for node in offers]
check("xml_offer_count", len(offers) == summary["source_items"], len(offers))
check("xml_offer_ids_unique", len(offer_ids) == len(set(offer_ids)), len(set(offer_ids)))

normalized = csv_rows(run_files["normalized/items.csv"].data)
normalized_jsonl = [
    json.loads(line)
    for line in run_files["normalized/items.jsonl"].data.decode("utf-8").splitlines()
]
matches = csv_rows(run_files["matches/matches.csv"].data)
source_only = csv_rows(run_files["matches/source_only.csv"].data)
review_queue = csv_rows(run_files["matches/review_queue.csv"].data)
proposals = csv_rows(run_files["proposals/proposals.csv"].data)
category_mappings = csv_rows(run_files["proposals/category-mapping-proposals.csv"].data)
product_categories = csv_rows(run_files["proposals/product-category-proposals.csv"].data)
missing = csv_rows(run_files["matches/catalog_missing_supplier.csv"].data)
check("normalized_count", len(normalized) == len(offers), len(normalized))
check("normalized_jsonl_count", len(normalized_jsonl) == len(offers), len(normalized_jsonl))
check(
    "normalized_supplier_ids_unique",
    len({row["supplier_item_id"] for row in normalized}) == len(normalized),
    len(normalized),
)
check(
    "normalized_catalog_skus_unique",
    len({row["catalog_sku"] for row in normalized}) == len(normalized),
    len(normalized),
)
check("match_count", len(matches) == len(normalized), len(matches))
check("proposal_count", len(proposals) == len(normalized), len(proposals))
check("source_only_count", len(source_only) == summary["source_only"], len(source_only))
check(
    "category_mapping_count",
    len(category_mappings) == summary["category_mapping"]["source_categories"],
    len(category_mappings),
)
check(
    "product_category_count",
    len(product_categories) == summary["category_mapping"]["source_only_products"],
    len(product_categories),
)
check(
    "category_publication_disabled",
    all(row["publication_eligible"] == "False" for row in category_mappings + product_categories),
    0,
)
check("review_queue_count", len(review_queue) == summary["review_queue"], len(review_queue))
check("missing_count", len(missing) == summary["catalog_missing_supplier"], len(missing))

match_counts = dict(sorted(Counter(row["status"] for row in matches).items()))
proposal_counts = dict(sorted(Counter(row["status"] for row in proposals).items()))
check("match_status_counts", match_counts == summary["matches"], match_counts)
check("proposal_status_counts", proposal_counts == summary["proposals"], proposal_counts)
check(
    "no_calculated_prices",
    all(not row["calculated_price"] and not row["proposed_price"] for row in proposals),
    proposal_counts,
)
check(
    "vat_blocked_exact",
    proposal_counts.get("blocked_vat_basis") == match_counts.get("exact"),
    proposal_counts,
)
check(
    "production_writes_zero",
    summary["production_writes"] == 0 and summary["mode"] == "read_only",
    summary["production_writes"],
)
check(
    "source_prices_positive",
    all(float(row["source_price"]) > 0 for row in normalized),
    min(float(row["source_price"]) for row in normalized),
)
check(
    "source_currency_known",
    {row["currency"] for row in normalized} == {"RUR"},
    sorted({row["currency"] for row in normalized}),
)

catalog_skus = {
    row["sku"]
    for row in csv_rows(catalog.data)
    if row["sku"].startswith("11")
}
direct_sku_intersection = sum(row["catalog_sku"] in catalog_skus for row in normalized)
matched_by_sku = sum(row["matched_by"] == "sku" for row in matches)
check(
    "direct_sku_intersection",
    direct_sku_intersection == matched_by_sku,
    {"intersection": direct_sku_intersection, "matched_by_sku": matched_by_sku},
)

VERIFICATION_ROOT.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(
    prefix="verify-duckdb-",
    suffix=".duckdb",
    dir=VERIFICATION_ROOT,
    delete=False,
) as temporary_database:
    temporary_database.write(run_files["pilot.duckdb"].data)
    temporary_database.flush()
    os.fsync(temporary_database.fileno())
    temporary_database_path = Path(temporary_database.name)
try:
    with duckdb.connect(str(temporary_database_path), read_only=True) as db:
        db_counts = {
            "normalized_items": db.execute("select count(*) from normalized_items").fetchone()[0],
            "matches": db.execute("select count(*) from matches").fetchone()[0],
            "source_only": db.execute("select count(*) from source_only").fetchone()[0],
            "review_queue": db.execute("select count(*) from review_queue").fetchone()[0],
            "proposals": db.execute("select count(*) from proposals").fetchone()[0],
            "category_mapping_proposals": db.execute(
                "select count(*) from category_mapping_proposals"
            ).fetchone()[0],
            "product_category_proposals": db.execute(
                "select count(*) from product_category_proposals"
            ).fetchone()[0],
            "catalog_missing_supplier": db.execute(
                "select count(*) from catalog_missing_supplier"
            ).fetchone()[0],
        }
finally:
    temporary_database_path.unlink(missing_ok=True)
expected_db_counts = {
    "normalized_items": len(normalized),
    "matches": len(matches),
    "source_only": len(source_only),
    "review_queue": len(review_queue),
    "proposals": len(proposals),
    "category_mapping_proposals": len(category_mappings),
    "product_category_proposals": len(product_categories),
    "catalog_missing_supplier": len(missing),
}
check("duckdb_counts", db_counts == expected_db_counts, db_counts)

conflicts = [row for row in matches if row["status"] == "conflict"]
check(
    "conflicts_blocked",
    len(conflicts) == proposal_counts.get("blocked_match", 0) - match_counts.get("unmatched", 0),
    len(conflicts),
)

result = {
    "status": "PASS" if all(item["passed"] for item in checks.values()) else "FAIL",
    "checks_passed": sum(item["passed"] for item in checks.values()),
    "checks_total": len(checks),
    "checks": checks,
}
verification_path = VERIFICATION_ROOT / f"{RUN.name}-verification.json"
write_atomic(
    verification_path,
    (json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
)
print(json.dumps(result, ensure_ascii=False, sort_keys=True))
raise SystemExit(0 if result["status"] == "PASS" else 1)
