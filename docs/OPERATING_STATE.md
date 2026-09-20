# Operating state

**Snapshot:** 2026-09-20 15:36 +0300
**Repository:** `D:/Sites/mks123/supplier-pipeline`
**Mode:** Netlab source-covered production-candidate hardening and GitHub handoff
**Production catalog/media/publication writes:** `0`
**Publication:** disabled
**Overall release:** **BLOCKED**
**Canonical current audit:** `docs/NETLAB_PROJECT_AUDIT.md` (public redacted); full audit remains in durable local evidence.

## Current gates

- `uv run pytest -q`: **PASS** (`526 passed, 18 skipped`).
- `uv run ruff check .`: **PASS**.
- `git diff --check`: **PASS**.
- `python -m compileall -q mks123_pipeline .ops-tmp`: **PASS**.
- Hermes registry/plugin validation: **PASS**.
- Local MariaDB production-writer fixture: **PASS**; forced catalog count mismatch produced handler failure and rollback.
- Current r7 self-enforcing packets: **LOCAL_ONLY_NOT_EXECUTED**.
- Current independent exact-byte review: **PENDING/BLOCKED**; dispatched reviewer hit provider HTTP 429 and did not return a valid review.
- Production reconciliation after the restore rehearsal: **BLOCKED/PARTIAL**; product/attribute/category identity matched, but full database equality was not proven.
- Media ACL, exact document root, image route, and production HTTP canary: **PENDING**.
- Production catalog/media/publication mutation: **NOT EXECUTED**.

## Current Netlab candidate

- Catalog: `2,787` updates, `11,430` creates, `14,217` records.
- Attributes: `710` seed rows.
- Media: `14,217` main assignments, `10,430` gallery rows.
- Exceptions: five 404 URLs and products without image URLs remain explicit exclusions.
- Candidate packet r7 hashes and durable evidence are recorded in the full local audit and release evidence. Any byte/config/schema/policy change invalidates dependent review and approval.

## Current production incident boundary

A previous restore rehearsal imported an unsuitable dump containing production-targeting database statements. The event is contained and documented; catalog/media/publication rollout DML remained zero. Do not infer full production equality from the matching product/attribute/category identity sets alone. Use the no-database isolated restore method for future rehearsals.

## Next bounded action

Finish the exact-byte independent review, production reconciliation, fresh backup binding, audit-schema validation, media ACL/route canary, and release packet rebuild. Do not execute production SQL until all P0 gates and final approval pass.

## Exact current implementation identity

- `mks123_pipeline/netlab_staging_apply.py`: `5dc42a8d537e019be4b22c1af8a525eb4848d15607ac1a23343d9f7f135d71b0`
- `mks123_pipeline/trusted_run.py`: `dc58779d5b7a1c58f4c0543e9d6aa536095d230209ea65be589c83a9048abf96`
- `mks123_pipeline/netlab_transfer.py`: `b1aeedea45e75cfa774c410da240ef5c464d1398de43a7727d5739bd78746498`
- `scripts/apply_netlab_staging.py`: `1a1db006fe7966b37e7c27f6549396f75eaccfe6a75ad9233badad75a2c6e9de`
- `tests/test_netlab_staging_apply.py`: `54c662e0ee487756fbb0932322e90bc065e97d203ad1e986730e6eb5c9ac6d3b`
- `scripts/run_netlab_transfer.py`: `d28d50c2007e5546e5b1013d5bcbeea0332cc12965fefb53e4d472902e558dd0`
- `tests/test_netlab_staging_integrity.py`: `eeb5893f1a6827142eff0f7aedea87e206f9ef6acebf482c6c452510e7099416`
- `tests/test_netlab_transfer.py`: `ec38e64ec568e8520ed5eb5124bec57c2a13c13e449aa05b57d47a0abd584be4`
- `tests/test_two_category_selector.py`: `87679cfedc6fddf148c5bb8dc723b7750c71a00284dd645e6b779160ea38baee`
- `tests/conftest.py`: `fb5e2aacbe74e7478781f43cec32104a10fb4ee00a44216484b782dac829bd04`
- Repository HEAD: `ce0b1ada39e0965c8900e60390addb1d6176fcc3`; worktree remains mixed and uncommitted.

## Docs and router changes in this packet

- Created repo-root `AGENTS.md` as the auto-loaded project context. No `.hermes.md` was created, so the root `AGENTS.md` is not shadowed.
- Existing `docs/AGENT_WORKFLOW.md`, `docs/ENVIRONMENTS.md`, and this state ledger are the canonical project handoff surface.
- Patched Hermes references/routing only: project context discovery, quota routing, Netlab escalation wording, plan commit boundary, and review commit boundary.
- Hermes `linux-ssh-sudo-executor` plugin/policy and `display.personality=uwu` were not changed.
- Schema-v2 candidate generation and apply now require an external expected seal
  SHA-256 and fixed durable trust root in addition to `--trusted-run-manifest`;
  the trusted seal binds normalized source, matches, proposals, and category
  snapshot identities.
- Scoped candidate generation rejects malformed/stale/future source timestamps
  (24-hour max age, 15-minute future skew), emits category relations, and binds
  the configured description language instead of hard-coding language `1`.
- The current staging apply path requires a pre-created audit table with the exact
  InnoDB/utf8mb4 columns and keys contract, and rejects every pilot-table engine
  other than InnoDB before backup/DML. One physical client holds the named
  coordination lock and SERIALIZABLE transaction through preflight, before-state
  metadata snapshot, apply, read-back, pending receipt, commit, and rollback;
  candidate snapshots use exclusive Windows/POSIX locks and post-execution identity
  checks.
- No profile memory/config change, production action, remote privilege, commit,
  push, or cleanup was performed.

## Staging rehearsal evidence

Historical target: `mks123_stage_rehearsal_20260910`; pre-remediation MyISAM
consistency strategy `lock_all_tables`.

- Apply/read-back receipt: `D:/ServerBackups/mks123webserver/netlab-staging-rehearsal-v22-20260910/APPLY_RESULT.json` — **PASS (historical pre-remediation canary)**.
  - products `1 → 2`; created `1`; records checked `2`; audit rows `2`;
  - categories/images content unchanged; relations/media assignments `0`;
  - `production_writes=0`; `publication_enabled=false`;
  - candidate ID `beaecc21594e1d55c12ccba723ccbba45e750e6c5e486c8c1be97a1cf2e51eac`.
- Rollback receipt: `D:/ServerBackups/mks123webserver/netlab-staging-rehearsal-v22-20260910/ROLLBACK_RESULT.json` — **PASS**.
  - affected state, products, descriptions, categories, images and audit-table absence: all checks `true`.
- The staging DB was restored; this does not certify production or storefront behavior.
- The canary predates the current category-relation, guarded-audit, trusted-seal,
  transaction-only rollback, and post-commit receipt implementation; it is not
  current evidence. Current apply also requires a pre-created
  `oc_netlab_transfer_audit` table, which was not verified for this receipt.

## Two-category pilot scope

The intended first business pilot is limited to the two MKS123 root categories:

- `456` — `Ноутбуки и компьютеры`;
- `537` — `Смартфоны,ТВ и электроника`.

The detailed scope, snapshot evidence, descendant allowlist requirement, and
publication boundary are recorded in `docs/TWO_CATEGORY_PILOT_SCOPE.md`.
The existing full candidate is not accepted for this scope: it has Netlab source
category paths but no complete verified target-site category assignment. A new
candidate must bind the live/read-back category tree, mapping decisions,
exclusions, records, SQL and manifest before any staging apply.

The intended test is selected staging products with `status=0` and `noindex=1`,
allowlisted categories, source/derived media, and storefront behavior. Any
production publication remains a separate explicit approval gate.

## Full candidate and data relevance

Source/candidate roots:

- fresh raw snapshots: `D:/ServerBackups/mks123webserver/netlab-shadow-20260914/raw/`
- fresh POSIX shadow evidence (not trusted for apply):
  `D:/ServerBackups/mks123webserver/netlab-shadow-20260914/posix-sealed-run-untrusted/`
- historical transfer candidate (not reused): `D:/ServerBackups/mks123webserver/netlab-transfer-full-v2-20260910/`

Fresh shadow measurements:

- source rows: `65,708`; source available: `13,704`; catalog scope: `25,363`.
- matches: exact `5,389`; ambiguous `73`; conflict `5,280`; unmatched `54,799`.
- review queue: `5,520`; source-only: `54,799`; catalog-missing-supplier: `14,527`.
- fresh source catalog date: `2026-09-14 11:04`; acquisition was within the 24-hour
  freshness bound. Feed completeness remains `blocked_incomplete`; missing actions
  are not allowed.
- source identity: EAN `47,358`; MPN `64,185`; image `55,280`.
- category mapping: `219` strong candidates, `104` review candidates, `226`
  ambiguous, `1,284` unmapped; publication-eligible categories: `0`.
- content enrichment joined `56,537/65,708` UIDs; descriptions observed for
  `42,494`; unknown properties remain review-only; detail pages were not fetched.
- shadow verifier: `52/52` checks, `production_writes=0`; sealed run ID is
  `netlab-89f5381e6d43-catalog-49471b9f3c81-config-cb46299b5d94-policy-cf3bd0802225-code-927e29bf2307-properties-2e2cb1c894ee`.

Interpretation: fresh acquisition and read-only shadow validation pass, but no
trusted filtered two-category candidate exists yet. The current POSIX sealed run
is preserved as evidence only because the fixed D: trust root is on writable NTFS.

## Remaining gates

1. Preserve the current fresh shadow as PARTIAL: its `52/52` POSIX verification
   is evidence-only; a trusted fixed-root receipt is still required.
2. Independent exact-byte adversarial review is **PASS** for the current
   implementation: `deleg_23f34dff` reviewed `5dc42a8d…` with empty concern/error
   arrays.
3. Fresh price/properties acquisition and live category read-back are **PASS**;
   evidence paths and hashes are recorded above.
4. Build and validate a new category-bound two-category candidate with external
   seal digest/trust-root evidence, explicit source-to-site mappings, exclusions,
   SQL/records/manifest hashes, and exact semantic binding. This is currently
   **BLOCKED** because the fixed D: trust root cannot satisfy the POSIX seal gate.
5. Confirm an isolated staging clone with InnoDB pilot tables and the exact audit
   schema contract; apply only the fresh candidate, then verify disabled/noindex
   products, categories, descriptions, images/photos, and storefront behavior.
6. Decide the quantity/availability policy separately; no production stock/status
   change is authorized by this packet.
7. Production catalog, CMS, media, category writes, publication, commit, push,
   remote privilege, DB deletion, and cleanup remain blocked/not approved.

## Next bounded action

Intervention is required: provide/approve a POSIX execution target with a durable
trusted-run root (or approve a separately reviewed cross-platform trust-root
architecture change). Do not use the D: NTFS evidence copy as a trusted run.
After that target is available, bind the fresh source/category inputs into a new
sealed run and build the filtered candidate; no staging or production apply is
authorized yet.
