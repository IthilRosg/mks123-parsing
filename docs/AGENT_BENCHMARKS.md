# Agent and pipeline benchmark report

> **Superseding snapshot — 2026-09-20:** the current repository run is `526 passed, 18 skipped`; Ruff, compileall, and diff hygiene pass. The current self-enforcing production packets are local-only. The newest independent exact-byte review was not completed because the provider returned HTTP 429, so release status remains BLOCKED. See `docs/NETLAB_PROJECT_AUDIT.md` for the current audit and keep the historical measurements below as historical evidence only.

**Snapshot:** 2026-09-14 11:37 +0300
**Scope:** current mks123 repository/worktree, two-category pilot scope, local quality gates, isolated v22 staging rehearsal, and read-only Netlab candidate relevance.
**External writes:** `0`
**Commit/push/cleanup:** historical snapshot; current source was later committed and pushed; cleanup not performed

This is a measured handoff, not an SLA and not a production-readiness claim.

## 1. Current-byte quality measurements

| Gate | Result | Evidence |
|---|---|---|
| Frozen dependency environment | PASS | `uv sync --frozen`; 24 packages checked |
| Full test suite | PASS | `uv run pytest -q`: 439 passed, 13 skipped, 125.21 s |
| Ruff | PASS | `uv run ruff check .` |
| Bytecode compilation | PASS | `uv run python -m compileall -q mks123_pipeline scripts tests` |
| Repository boundary | PASS | `scripts/check_repository_boundary.py`: 75 tracked files |
| Diff hygiene | PASS | `git diff --check` (existing LF/CRLF warnings retained) |
| Full candidate streaming validator | PARTIAL | Fresh POSIX shadow completed `52/52` checks, but the sealed run is not accepted under the fixed D: trust root; no current trusted `VALIDATION_RESULT-current.json` receipt |
| Independent adversarial review | PASS | `deleg_23f34dff` reviewed exact current `5dc42a8d…` bytes; security concerns and logic errors are empty |
| Fresh supplier acquisition | PASS | Price/properties fetched read-only on 2026-09-14; price SHA `0cea225b…`, properties SHA `2e2cb1c8…`, `production_writes=0` |
| Live category read-back | PASS | Evidence SHA `76a5fc00…`; roots `456=132/132`, `537=103/103` |
| Trusted fixed-root candidate | BLOCKED | Windows loader requires POSIX descriptor primitives; D: mounted NTFS cannot satisfy the seal-freeze gate |

The current code requires a pre-created `oc_netlab_transfer_audit` table with the
exact InnoDB/utf8mb4 columns and keys contract, rejects every pilot-table engine
other than InnoDB before backup/DML, and uses external seal-digest/trust-root
checks plus exclusive candidate snapshot locks. One physical client holds a named
coordination lock and SERIALIZABLE transaction through preflight, before-state
read-back, pending receipt, commit, and rollback. The exact current bytes passed
independent review. Fresh supplier/category evidence and shadow validation pass, but a
trusted filtered candidate and live staging evidence remain blocked by the fixed-root
POSIX-seal runtime gate.

## 2. Isolated staging measurements

Target: `mks123_stage_rehearsal_20260910`; candidate v22; the historical canary
used the pre-remediation `lock_all_tables` path.

- Apply/read-back: **PASS (historical pre-remediation canary)**. Products `1 → 2`; one create; two records checked;
  two audit rows; category/image semantic digests unchanged; no relations/media
  assignments; `production_writes=0`; `publication_enabled=false`.
- Rollback: **PASS**. Six semantic checks true, including products,
  descriptions, categories, images, affected-state digest, and audit-table
  absence.
- Receipts: `D:/ServerBackups/mks123webserver/netlab-staging-rehearsal-v22-20260910/APPLY_RESULT.json` and `ROLLBACK_RESULT.json`.
- This proves the isolated rehearsal path only. It does not prove current
  supplier freshness, production safety, storefront rendering, or publication.
- The canary predates current category-relation, guarded-audit, trusted-seal,
transaction-only rollback, and post-commit receipt bytes; no new candidate apply has
been run. Current apply also requires a pre-created audit table, which was not
verified for this historical receipt.

## 3. Two-category pilot scope

The intended first pilot is limited to the MKS123 site roots:

- `456` — `Ноутбуки и компьютеры`;
- `537` — `Смартфоны,ТВ и электроника`.

The preserved site database snapshot contains 132 and 103 descendants
respectively. The full source/candidate is not accepted as this pilot because
its records contain source category paths but no complete verified target-site
category assignment. The required next artifact is a fresh category-bound
manifest with a trusted selector-input seal, a descendant allowlist, source
mappings, exclusions, exact hashes, freshness proof, and semantic SQL/records
binding. Staging should keep new products disabled and unindexed while exact
category relations, photos/media, and storefront behavior are checked.
Production publication remains a separate explicit approval gate. Detailed
scope is in `docs/TWO_CATEGORY_PILOT_SCOPE.md`.

## 4. Candidate relevance measurements

Artifacts were streamed and counted with
`D:/Sites/mks123/.ops-tmp/analyze_netlab_relevance.py` and
`analyze_netlab_raw_currency.py`; the result was written to
`D:/Sites/mks123/.ops-tmp/netlab_relevance_current.json`.

| Measurement | Result |
|---|---:|
| Source rows | 65,931 |
| Candidate records | 57,700 |
| Updates / creates | 5,354 / 52,346 |
| Exceptions | 8,231 (12.48%) |
| Exact catalog overlap | 5,409 |
| Eligible updates among exact overlap | 98.98% |
| Availability agreement on exact overlap | 51.97% |
| Source snapshot age at analysis | 40.83 h (policy max 24 h) |
| Source rows marked available | 13,860 (21.02%) |
| Creates marked available | 8,808 (16.83%) |
| Payloads with positive quantity | 0; all candidate quantities are 0 |
| Raw quantity empty / zero | 14,012 / 51,919 |
| Raw `OutOfProd=true` | 803 (1.22%) |
| `DescrUpdated` sentinel/older than 5 years | 8,528 (12.93%) |
| Create descriptions non-empty | 59.41% |
| Create image coverage | 80.39% |
| Source-only rows with category candidate | 33.71% |
| Unmapped source categories | 70.10% of 1,836 |
| Publication-eligible categories | 0 |
| Catalog coverage | 42.877%; missing actions blocked |

The business conclusion is bounded: the exact-match subset is worth revisiting
as a controlled refresh after a fresh fetch, but this snapshot is too old for a
current claim, availability differs from the catalog in 48.03% of exact matches,
and the full create set has unusable stock quantity semantics for automatic
production transfer. The new-product set is staging/review material, not a
publishable catalog.

## 5. Hermes context/router changes

- Created `AGENTS.md` at the repository root; no `.hermes.md` was added.
- Existing project router/state docs remain `docs/AGENT_WORKFLOW.md`,
  `docs/ENVIRONMENTS.md`, and `docs/OPERATING_STATE.md`.
- Updated the Hermes context reference to match current official docs: root
  `AGENTS.md` plus progressive subdirectory discovery, and dynamic context-file
  caps instead of a fixed 20,000-character claim.
- Aligned the active routing guidance: OpenAI Codex only; Luna implementation;
  Sol independent review; Astra only for complex reasoning/escalation after
  actual availability/quota verification; no silent fallback.
- Made plan/review skills treat commit as an explicit approval gate.
- SSH plugin/policy and personality were not changed. No profile config or
  memory change was made.

## 6. Readiness by gate (not blended)

| Workstream | State | Meaning |
|---|---|---|
| Local implementation quality | PASS | Current full suite/static/compile/boundary gates are green; InnoDB same-session transaction/counter rollback regressions pass |
| Isolated staging apply/read-back | BLOCKED | No current filtered candidate or fresh source; live MariaDB client is unavailable; current apply requires an InnoDB clone and exact pre-created audit schema |
| Isolated rollback | PARTIAL | Historical v22 rollback is PASS only; current InnoDB same-session rollback is covered locally but not live-verified |
| Full current candidate validation | PARTIAL | Streaming validator stopped without a durable current receipt |
| Independent exact-byte review | FAIL → pending | `deleg_b1386a5a` failed older pre-fix bytes; current strict bytes require a new structured review |
| Fresh supplier currentness | BLOCKED | Current snapshot is 40.83 h old vs 24 h policy |
| Quantity/stock business policy | BLOCKED | Candidate quantity is zero for every record |
| Category/media/storefront publication | BLOCKED | No publication-eligible categories; separate approval absent |
| Production readiness | BLOCKED | No production approval, publisher, before-state, or production read-back |

## 7. Acceptance rule

Do not convert the report to PASS by counting exit codes. The final handoff
requires a durable current validator receipt, fresh independent review, and
explicit reconciliation of candidate identity/counts. The current local
implementation has green tests and focused race/provenance regressions, but
that is not an independent acceptance. If review fails, add a focused RED
regression before fixing and invalidate dependent evidence. No commit,
production write, publication, destructive cleanup, or SSH/personality change
is part of this packet.
