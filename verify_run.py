from __future__ import annotations

import argparse
import json
from pathlib import Path

from mks123_pipeline.verifier import verify_run


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a sealed read-only mks123 run")
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--no-deterministic-replay",
        action="store_true",
        help="skip the expensive deterministic artifact replay; retain seal and semantic checks",
    )
    args = parser.parse_args()
    result = verify_run(
        args.run,
        source=args.source,
        catalog=args.catalog,
        config=args.config,
        deterministic_replay=not args.no_deterministic_replay,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
