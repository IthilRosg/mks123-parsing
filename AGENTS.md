# mks123 supplier-pipeline

This repository is the project context for the mks123 Netlab shadow and isolated
staging-transfer work. Keep work bounded, evidence-first, and reversible.

## Scope and hard boundaries

- Default mode is read-only shadow analysis or local code/docs work.
- A staging database write is allowed only when the exact candidate, isolated
  target, before-dump, `--confirm-staging-only` boundary, read-back, and rollback
  receipt are all present.
- Production DB, CMS, storefront, category/media/compatibility publication,
  remote privilege, destructive cleanup, commit, and push are separate approvals.
  This file never grants those approvals.
- Do not change the Hermes SSH plugin, its approval policy, or the configured
  personality while working on this repository. Do not read credentials,
  private keys, cookies, `.env`, `auth.json`, or DPAPI payloads.
- Never treat a historical receipt, process exit code, planned after-value, or
  hardcoded `production_writes=0` as current external read-back.

## Canonical project state

Read these before resuming a non-trivial packet:

1. `docs/OPERATING_STATE.md` — current candidate, gates, blockers, next action.
2. `docs/AGENT_WORKFLOW.md` — tool/router, approval, WSL path, and handoff rules.
3. `docs/ENVIRONMENTS.md` — verified environments and rollback handles.
4. `docs/NETLAB_READINESS.md` — source/pricing/shadow contract and readiness gates.
5. `.hermes/plans/` — planning context only; a plan is not permission.

Current truth is the exact bytes and fresh receipts in the durable evidence root
`D:/ServerBackups/mks123webserver/`. Preserve old evidence; do not edit old
receipts to make them agree with newer code.

## Work modes and routers

- **shadow/read-only:** use the Netlab shadow pipeline; validate supplier
  freshness, source/rate/properties provenance, matches, exceptions, and
  `production_writes=0`.
- **staging transfer:** use the transfer/apply modules and staging CLI only;
  bind SQL, manifest, records, source/matches hashes, selected scope, and code
  identity; verify affected fields and untouched relation content; restore and
  read back on failure.
- **storefront/publication:** stop at a proposal until a separate approved
  scope supplies category/media/compatibility rules, before-state, publisher,
  browser/API read-back, and rollback.
- **Hermes/profile work:** change only the explicitly approved docs/skills/router
  surface. Keep SSH plugin and personality out of scope.

## Verification

Use project `uv` commands, not global pip assumptions:

```text
uv sync --frozen
uv run python -m pytest -q
uv run ruff check .
uv run python -m compileall -q mks123_pipeline scripts verify_run.py
git diff --check
```

For a behavior change use RED → minimal fix → focused GREEN → full suite. Any
candidate byte, policy, schema, selection, or dependent helper change invalidates
its prior review and dependent receipts. Recompute identities before accepting
new evidence. Reconcile every stated count programmatically.

Native path rules: Windows tools use `D:/...`; WSL/Linux tools use
`/mnt/d/...`; keep redirection inside the WSL shell. Do not paste SQL backticks
inside an outer double-quoted MSYS command. Keep one-off scripts in
`D:/Sites/mks123/.ops-tmp/` and durable evidence under `D:/ServerBackups/`.

## Handoff

End each packet with `Changed`, `Verified`, `Blocked`, `External writes`, `Next`,
and elapsed time. If a gate is missing or stale, mark it `PARTIAL` or `BLOCKED`;
do not infer readiness from a local or synthetic PASS.
