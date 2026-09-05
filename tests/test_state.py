import json
from pathlib import Path

import pytest

from mks123_pipeline.runner import run_pilot
from mks123_pipeline.state import update_missing_state


def test_incomplete_feed_does_not_advance_missing_counters() -> None:
    previous = {
        "schema_version": 1,
        "supplier": "electrozone",
        "products": {
            "100": {
                "sku": "11-100",
                "consecutive_missing_runs": 2,
                "last_seen_run_id": "run-1",
            }
        },
    }

    state, decision = update_missing_state(
        previous,
        supplier="electrozone",
        run_id="run-2",
        complete=False,
        missing_products={"100": "11-100", "200": "11-200"},
        action="quarantine",
        threshold=3,
    )

    assert state["products"]["100"]["consecutive_missing_runs"] == 2
    assert "200" not in state["products"]
    assert decision == {
        "complete": False,
        "actions_allowed": False,
        "reason": "incomplete_feed",
        "proposed_actions": [],
    }


def test_complete_feed_advances_state_but_never_writes() -> None:
    previous = {
        "schema_version": 1,
        "supplier": "electrozone",
        "products": {
            "100": {
                "sku": "11-100",
                "consecutive_missing_runs": 2,
                "last_seen_run_id": "run-1",
            },
            "300": {
                "sku": "11-300",
                "consecutive_missing_runs": 1,
                "last_seen_run_id": "run-1",
            },
        },
    }

    state, decision = update_missing_state(
        previous,
        supplier="electrozone",
        run_id="run-2",
        complete=True,
        missing_products={"100": "11-100", "200": "11-200"},
        action="quarantine",
        threshold=3,
    )

    assert state["products"]["100"]["consecutive_missing_runs"] == 3
    assert state["products"]["200"]["consecutive_missing_runs"] == 1
    assert state["products"]["300"]["consecutive_missing_runs"] == 0
    assert decision["actions_allowed"] is True
    assert decision["proposed_actions"] == [{
        "action": "quarantine",
        "product_id": "100",
        "sku": "11-100",
        "consecutive_missing_runs": 3,
    }]


def test_missing_state_rejects_boolean_counters_and_threshold() -> None:
    previous = {
        "schema_version": 1,
        "supplier": "electrozone",
        "products": {"100": {"sku": "11-100", "consecutive_missing_runs": True}},
    }

    with pytest.raises(ValueError, match="consecutive_missing_runs"):
        update_missing_state(
            previous,
            supplier="electrozone",
            run_id="run-2",
            complete=False,
            missing_products={},
            action="quarantine",
            threshold=3,
        )

    with pytest.raises(ValueError, match="threshold"):
        update_missing_state(
            None,
            supplier="electrozone",
            run_id="run-2",
            complete=True,
            missing_products={"100": "11-100"},
            action="quarantine",
            threshold=True,
        )


def test_runner_marks_partial_catalog_coverage_and_does_not_advance_state(tmp_path: Path) -> None:
    source = tmp_path / "feed.yml"
    source.write_text(
        '<yml_catalog><shop><currencies><currency id="RUR" rate="1"/></currencies><offers>'
        '<offer id="1" available="true"><name>Widget</name><price>100</price><currencyId>RUR</currencyId></offer>'
        '</offers></shop></yml_catalog>',
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.csv"
    catalog.write_text(
        "product_id,model,sku,ean,name,manufacturer,price,quantity,status,category_ids,categories\n"
        "1,M1,111,,Widget,Acme,100,1,1,,\n"
        "2,M2,112,,Missing,Acme,100,1,1,,\n",
        encoding="utf-8",
    )
    previous = tmp_path / "previous-state.json"
    previous.write_text(json.dumps({
        "schema_version": 1,
        "supplier": "electrozone",
        "products": {
            "2": {"sku": "112", "consecutive_missing_runs": 2},
        },
    }), encoding="utf-8")

    summary = run_pilot(
        source,
        catalog,
        tmp_path / "run",
        fetched_at="2026-09-03T12:00:00Z",
        previous_state_path=previous,
        missing_product_action="quarantine",
        consecutive_missing_runs=3,
    )

    assert summary["feed_completeness"]["status"] == "blocked_incomplete"
    assert summary["feed_completeness"]["missing_actions_allowed"] is False
    assert summary["missing_product_state"]["proposed_actions"] == []
    next_state = json.loads((tmp_path / "run/state/next-missing-state.json").read_text(encoding="utf-8"))
    assert next_state["products"]["2"]["consecutive_missing_runs"] == 2
