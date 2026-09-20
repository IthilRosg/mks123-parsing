"""Apply one Netlab transfer candidate to a loopback-only staging database."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from mks123_pipeline.netlab_staging_apply import (
    StagingApplyError,
    StagingTarget,
    apply_candidate,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--database", default="mks123_stage")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--socket")
    parser.add_argument("--mariadb-bin", default="mariadb")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--confirm-staging-only", action="store_true")
    parser.add_argument("--trusted-run-manifest", type=Path, required=True)
    parser.add_argument("--expected-trusted-run-seal-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    target = StagingTarget(
        host=args.host,
        port=args.port,
        database=args.database,
        socket=args.socket,
        mariadb_bin=args.mariadb_bin,
        timeout_seconds=args.timeout_seconds,
    )
    try:
        result = apply_candidate(
            args.candidate,
            target=target,
            backup_root=args.backup_root,
            confirm_staging_only=args.confirm_staging_only,
            trusted_run_manifest=args.trusted_run_manifest,
            expected_trusted_run_seal_sha256=args.expected_trusted_run_seal_sha256,
        )
    except (OSError, StagingApplyError) as exc:
        print(f"staging apply failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
