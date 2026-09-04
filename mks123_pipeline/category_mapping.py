from __future__ import annotations

import json
from collections import Counter
from typing import Any


def _category_key(value: Any) -> str:
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = [value]
    else:
        parsed = value
    if not isinstance(parsed, list):
        parsed = [str(parsed)]
    return json.dumps([str(part) for part in parsed], ensure_ascii=False)


def build_category_mapping(
    normalized_items: list[dict[str, Any]],
    matches: list[dict[str, Any]],
    catalog_by_id: dict[int, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    normalized_by_id = {str(row["supplier_item_id"]): row for row in normalized_items}
    source_counts = Counter(_category_key(row.get("category_path", [])) for row in normalized_items)
    source_only_counts: Counter[str] = Counter()
    learned: dict[str, Counter[tuple[str, str]]] = {}

    for match in matches:
        supplier_id = str(match["supplier_item_id"])
        source = normalized_by_id[supplier_id]
        source_category = _category_key(source.get("category_path", []))
        if match["status"] == "unmatched":
            source_only_counts[source_category] += 1
            continue
        if match["status"] != "exact" or match.get("catalog_product_id") in (None, ""):
            continue
        product_id = int(match["catalog_product_id"])
        catalog = catalog_by_id[product_id]
        target = (str(catalog.get("category_ids") or ""), str(catalog.get("categories") or ""))
        learned.setdefault(source_category, Counter())[target] += 1

    mapping_rows: list[dict[str, Any]] = []
    mapping_by_source: dict[str, dict[str, Any]] = {}
    for source_category in sorted(source_counts):
        candidates = learned.get(source_category, Counter())
        support = sum(candidates.values())
        ranked = candidates.most_common()
        top_target = ranked[0][0] if ranked else ("", "")
        top_count = ranked[0][1] if ranked else 0
        dominance = top_count / support if support else 0.0
        if support >= 3 and dominance == 1.0:
            status = "strong_candidate"
        elif support >= 2 and dominance >= 0.8:
            status = "review_candidate"
        elif support:
            status = "ambiguous"
        else:
            status = "unmapped"
        alternatives = [
            {"category_ids": target[0], "categories": target[1], "support": count}
            for target, count in ranked
        ]
        row = {
            "source_category_path": source_category,
            "source_total": source_counts[source_category],
            "source_only_products": source_only_counts[source_category],
            "exact_support": support,
            "suggested_category_ids": top_target[0],
            "suggested_categories": top_target[1],
            "dominant_support": top_count,
            "dominance_pct": round(dominance * 100, 2),
            "alternatives": alternatives,
            "mapping_status": status,
            "publication_eligible": False,
        }
        mapping_rows.append(row)
        mapping_by_source[source_category] = row

    product_rows: list[dict[str, Any]] = []
    for match in matches:
        if match["status"] != "unmatched":
            continue
        supplier_id = str(match["supplier_item_id"])
        source = normalized_by_id[supplier_id]
        source_category = _category_key(source.get("category_path", []))
        mapping = mapping_by_source[source_category]
        if mapping["mapping_status"] in {"strong_candidate", "review_candidate"}:
            proposal_status = "review_only"
        elif mapping["mapping_status"] == "ambiguous":
            proposal_status = "blocked_ambiguous_category"
        else:
            proposal_status = "blocked_unmapped"
        product_rows.append({
            "supplier_item_id": supplier_id,
            "catalog_sku": source.get("catalog_sku"),
            "name": source.get("name"),
            "source_category_path": source_category,
            "suggested_category_ids": mapping["suggested_category_ids"],
            "suggested_categories": mapping["suggested_categories"],
            "mapping_status": mapping["mapping_status"],
            "proposal_status": proposal_status,
            "publication_eligible": False,
        })
    product_rows.sort(key=lambda row: row["supplier_item_id"])

    status_counts = Counter(row["mapping_status"] for row in mapping_rows)
    summary = {
        "source_categories": len(mapping_rows),
        "source_only_products": len(product_rows),
        "strong_candidate_categories": status_counts["strong_candidate"],
        "review_candidate_categories": status_counts["review_candidate"],
        "ambiguous_categories": status_counts["ambiguous"],
        "unmapped_categories": status_counts["unmapped"],
        "source_only_with_candidate": sum(row["proposal_status"] == "review_only" for row in product_rows),
        "publication_eligible": 0,
    }
    return mapping_rows, product_rows, summary
