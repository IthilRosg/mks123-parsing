from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from .integrity import read_evidence
from .netlab_media import (
    STORAGE_ROOT,
    build_media_plan,
    stage_media_plan,
)
from .netlab_media_finalize import finalize_media_stage, init_storage, verify_media_run

MEDIA_ROOT = STORAGE_ROOT
_MAX_JSON = 256 * 1024 * 1024


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _sha(value: str) -> str:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise argparse.ArgumentTypeError("must be a lowercase SHA-256")
    return value


def _load_json(path: str, expected_sha: str | None = None) -> dict[str, object]:
    evidence = read_evidence(Path(path), max_bytes=_MAX_JSON)
    if expected_sha is not None and evidence.sha256 != expected_sha:
        raise ValueError("JSON digest mismatch")
    value = json.loads(evidence.data)
    if not isinstance(value, dict):
        raise TypeError("JSON must be an object")
    return value


def _write_json(path: str, value: object) -> str:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with Path(path).open("xb") as handle:
        handle.write(data)
    return hashlib.sha256(data).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netlab-media")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init-storage")
    init.add_argument("--writer-uid", required=True, type=_positive)
    init.add_argument("--writer-gid", required=True, type=_positive)
    plan = commands.add_parser("plan")
    plan.add_argument("--run-dir", required=True)
    plan.add_argument("--selection-policy", required=True)
    plan.add_argument("--expected-source-seal-sha256", required=True, type=_sha)
    plan.add_argument("--output", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--plan", required=True)
    stage.add_argument("--expected-plan-sha256", required=True, type=_sha)
    stage.add_argument("--stage-id", required=True)
    stage.add_argument("--timeout-seconds", type=_positive, default=15)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--stage-id", required=True)
    finalize.add_argument("--media-run-id", required=True)
    finalize.add_argument("--expected-stage-seal-sha256", required=True, type=_sha)
    finalize.add_argument("--expected-plan-sha256", required=True, type=_sha)
    finalize.add_argument("--writer-uid", required=True, type=_positive)
    finalize.add_argument("--writer-gid", required=True, type=_positive)
    verify = commands.add_parser("verify")
    verify.add_argument("--media-run-id", required=True)
    verify.add_argument("--expected-final-seal-sha256", required=True, type=_sha)
    verify.add_argument("--source-run-dir", required=True)
    verify.add_argument("--expected-source-seal-sha256", required=True, type=_sha)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "init-storage":
        result = init_storage(MEDIA_ROOT, writer_uid=args.writer_uid, writer_gid=args.writer_gid)
    elif args.command == "plan":
        result = build_media_plan(args.run_dir, _load_json(args.selection_policy),
                                  expected_source_seal_sha256=args.expected_source_seal_sha256)
        digest = _write_json(args.output, result)
        result = {"output": args.output, "plan_sha256": digest, "counts": result["counts"]}
    elif args.command == "stage":
        result = stage_media_plan(_load_json(args.plan, args.expected_plan_sha256), media_root=MEDIA_ROOT,
                                  stage_id=args.stage_id, expected_plan_sha256=args.expected_plan_sha256,
                                  timeout_seconds=args.timeout_seconds)
    elif args.command == "finalize":
        result = finalize_media_stage(media_root=MEDIA_ROOT, stage_id=args.stage_id,
                                      media_run_id=args.media_run_id,
                                      expected_stage_seal_sha256=args.expected_stage_seal_sha256,
                                      expected_plan_sha256=args.expected_plan_sha256,
                                      writer_uid=args.writer_uid, writer_gid=args.writer_gid)
    else:
        result = verify_media_run(MEDIA_ROOT, args.media_run_id, args.expected_final_seal_sha256,
                                  source_run_dir=args.source_run_dir,
                                  expected_source_seal_sha256=args.expected_source_seal_sha256)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
