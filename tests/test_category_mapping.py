from mks123_pipeline.category_mapping import build_category_mapping


def test_category_mapping_learns_only_from_exact_matches_and_never_auto_approves() -> None:
    normalized = [
        {"supplier_item_id": "1", "category_path": ["Computers", "SSDs"], "name": "A"},
        {"supplier_item_id": "2", "category_path": ["Computers", "SSDs"], "name": "B"},
        {"supplier_item_id": "3", "category_path": ["Computers", "SSDs"], "name": "C"},
        {"supplier_item_id": "4", "category_path": ["Computers", "SSDs"], "name": "New SSD"},
        {"supplier_item_id": "5", "category_path": ["TV", "All"], "name": "New TV"},
    ]
    matches = [
        {"supplier_item_id": "1", "status": "exact", "catalog_product_id": 11},
        {"supplier_item_id": "2", "status": "exact", "catalog_product_id": 12},
        {"supplier_item_id": "3", "status": "exact", "catalog_product_id": 13},
        {"supplier_item_id": "4", "status": "unmatched", "catalog_product_id": None},
        {"supplier_item_id": "5", "status": "unmatched", "catalog_product_id": None},
    ]
    catalog = {
        11: {"category_ids": "485", "categories": "SSD"},
        12: {"category_ids": "485", "categories": "SSD"},
        13: {"category_ids": "485", "categories": "SSD"},
    }

    mappings, products, summary = build_category_mapping(normalized, matches, catalog)

    ssd = next(row for row in mappings if row["source_category_path"] == '["Computers", "SSDs"]')
    assert ssd["mapping_status"] == "strong_candidate"
    assert ssd["suggested_category_ids"] == "485"
    assert ssd["publication_eligible"] is False
    assert next(row for row in products if row["supplier_item_id"] == "4")["proposal_status"] == "review_only"
    assert next(row for row in products if row["supplier_item_id"] == "5")["proposal_status"] == "blocked_unmapped"
    assert summary == {
        "source_categories": 2,
        "source_only_products": 2,
        "strong_candidate_categories": 1,
        "review_candidate_categories": 0,
        "ambiguous_categories": 0,
        "unmapped_categories": 1,
        "source_only_with_candidate": 1,
        "publication_eligible": 0,
    }
