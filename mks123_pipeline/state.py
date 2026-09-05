from __future__ import annotations

from copy import deepcopy
from typing import Any

SCHEMA_VERSION = 1


def _empty_state(supplier: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "supplier": supplier,
        "last_run_id": None,
        "last_feed_complete": None,
        "products": {},
    }


def _validated_previous(previous: dict[str, Any] | None, supplier: str) -> dict[str, Any]:
    if previous is None:
        return _empty_state(supplier)
    if not isinstance(previous, dict):
        raise TypeError("missing-product state must be a JSON object")
    if previous.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported missing-product state schema")
    if previous.get("supplier") != supplier:
        raise ValueError("missing-product state supplier mismatch")
    products = previous.get("products")
    if not isinstance(products, dict):
        raise TypeError("missing-product state products must be an object")
    state = deepcopy(previous)
    for product_id, record in products.items():
        if not isinstance(product_id, str) or not isinstance(record, dict):
            raise TypeError("invalid missing-product state record")
        count = record.get("consecutive_missing_runs", 0)
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("invalid consecutive_missing_runs")
    return state


def update_missing_state(
    previous: dict[str, Any] | None,
    *,
    supplier: str,
    run_id: str,
    complete: bool,
    missing_products: dict[str, str],
    action: str | None,
    threshold: int | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not supplier or not run_id:
        raise ValueError("supplier and run_id are required for missing-product state")
    if any(not product_id or not sku for product_id, sku in missing_products.items()):
        raise ValueError("missing-product state requires product IDs and SKUs")
    if threshold is not None and (
        not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1
    ):
        raise ValueError("missing-product threshold must be a positive integer")
    state = _validated_previous(previous, supplier)
    products = state["products"]

    if complete:
        for product_id, record in list(products.items()):
            if product_id in missing_products:
                record["sku"] = missing_products[product_id]
                record["consecutive_missing_runs"] = int(record.get("consecutive_missing_runs", 0)) + 1
                record["last_missing_run_id"] = run_id
            else:
                record["consecutive_missing_runs"] = 0
                record["last_seen_run_id"] = run_id
        for product_id, sku in missing_products.items():
            if product_id not in products:
                products[product_id] = {
                    "sku": sku,
                    "consecutive_missing_runs": 1,
                    "last_missing_run_id": run_id,
                }
    state["last_run_id"] = run_id
    state["last_feed_complete"] = complete

    proposed_actions: list[dict[str, Any]] = []
    if complete and action and threshold is not None:
        for product_id in sorted(missing_products):
            record = products[product_id]
            count = int(record["consecutive_missing_runs"])
            if count >= threshold:
                proposed_actions.append({
                    "action": action,
                    "product_id": product_id,
                    "sku": record["sku"],
                    "consecutive_missing_runs": count,
                })
    decision = {
        "complete": complete,
        "actions_allowed": complete and bool(action) and threshold is not None,
        "reason": "complete_feed" if complete else "incomplete_feed",
        "proposed_actions": proposed_actions,
    }
    return state, decision
