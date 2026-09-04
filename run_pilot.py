from __future__ import annotations

import argparse
import json
from pathlib import Path

from mks123_pipeline.adapters import create_adapter
from mks123_pipeline.config import load_pilot_config, pricing_context_from_config
from mks123_pipeline.runner import run_pilot

parser = argparse.ArgumentParser(description="Run a read-only mks123 supplier pilot")
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--catalog", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--fetched-at", required=True)
parser.add_argument("--config", type=Path, default=Path(__file__).parent / "config/pilot.yaml")
parser.add_argument("--previous-state", type=Path, default=None)
args = parser.parse_args()
config = load_pilot_config(args.config)
adapter = create_adapter(
    config.supplier.id,
    expected_catalog_sku_prefix=config.supplier.scope.catalog_sku_prefix,
)
summary = run_pilot(
    args.source,
    args.catalog,
    args.output,
    args.fetched_at,
    min_source_items=config.supplier.source.min_offer_count,
    max_source_items=config.supplier.source.max_offer_count,
    max_source_bytes=config.supplier.source.max_response_bytes,
    adapter=adapter,
    pricing=pricing_context_from_config(config.pricing, observed_at=args.fetched_at),
    config_path=args.config,
    previous_state_path=args.previous_state,
    missing_product_action=(config.stock.missing_product_policy.action if config.stock else None),
    consecutive_missing_runs=(config.stock.missing_product_policy.consecutive_missing_runs if config.stock else None),
)
print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
