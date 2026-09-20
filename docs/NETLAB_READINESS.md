# Netlab readiness and operations

Updated: 2026-09-05

## Approved read-only pricing contract

```text
source_price_usd = Netlab Price.xml priceE
rub_per_usd = Price.xml currencies/currency[@id="USD"]/@rate
site_price_rub = source_price_usd × rub_per_usd × 1.10
```

- VAT is already included; no second VAT calculation is allowed.
- Arithmetic uses `Decimal`.
- No rounding step is applied in the current policy.
- The rate must come from the same accepted immutable Netlab price ZIP.
- The policy records supplier ID, rate, supplier timestamp and source SHA-256.
- Accepted rate range: `40…200 RUB/USD`.
- Direct acquisition rejects a price feed older than 24 hours or more than 15 minutes in the future. Netlab timestamps are interpreted as Moscow time.
- There is no external, OpenCart, cached or parity fallback for USD.
- `publication.enabled=false`; no publisher exists.

## Fast refresh contract

Run `scripts/run_netlab_shadow.py` from a checked-out repository with an explicit catalog CSV. The supervisor:

1. conditionally requests and strictly validates the current `pricexml4.zip`; a `304` is only a bandwidth hint and still requires local size/SHA/freshness validation plus an append-only receipt;
2. installs/deduplicates a changed immutable archive by SHA-256;
3. computes source, catalog, config and executable-code identities;
4. verifies an existing sealed run before returning `NO_CHANGE`;
5. creates a full new match/price proposal run when any identity changes;
6. runs the independent verifier and succeeds only on `PASS`;
7. always reports `production_writes=0`.

A previous match map is deliberately not reused after a changed supplier ZIP. A rate update can coincide with changed prices, stock or identities, so reuse would trade seconds for correctness. Measured performance makes the safer full rerun practical.

Recommended deployment cadence after scheduler review: every 15 minutes, with overlap prevention, alerting and retention configured separately. A failed fetch/run/verifier keeps the last verified run and must alert; it is never converted into `NO_CHANGE`.

## Live content evidence

Current representative content-enabled run:

- price catalog date: `2026-09-05 02:04` Moscow;
- price ZIP SHA-256: `d9a98f456fd667be744012cf398ddf9eb123f4cc2672ab8cd2f81c6812865c59`;
- price offers: `65,998`;
- supplier USD/RUB rate: `86.89`;
- properties ZIP SHA-256: `eaf56c976c1e802b280013b42e3ff1df0a38d9003d10684d582ed810c6de7813`;
- properties items: `56,860`; observations: `2,864,706`;
- UID joins: `56,744`; source descriptions: `42,857`;
- exact matches: `5,426`; conflicts: `5,302`; ambiguous: `75`;
- ready-for-review price proposals: `3,632`; delta-blocked: `1,794`;
- catalog coverage: `42.956%`; missing catalog products: `14,468`;
- verifier: `52/52 PASS`;
- production writes: `0`; detail pages: not fetched.

The content run keeps unknown properties review-only and does not publish the
42.956% catalog gap. It uses the structured properties feed for descriptions and
characteristics; HTML card crawling is intentionally outside the scheduled cycle.

## Measured live evidence

- latest full content cycle completed successfully under the scheduler command;
- unchanged runs are still accepted only after sealed-run verification;
- deterministic artifact comparison and DuckDB semantic digest are part of the `52/52` verifier gate.

These are observations, not an SLA.

## Deployment boundary

The production-like content shadow package is in `deploy/`. It installs a
systemd service/timer only; no production DB writer, OpenCart publisher or
catalog mutation is included. The approved remote target is Ubuntu VM
`mks123webserver` / Tailscale `100.81.66.42`, service account `zenit`.

The current practical-v1 candidate was uploaded only to its seal-bound user
staging directory and read back by exact name, size, owner, mode, link count and
SHA-256. Remote bootstrap installation and the root transaction have not been
executed. The service and timer remain `inactive`/`disabled`, and the root
transaction home is absent. The registered install operation must not be used
until its source path is rebound to the exact current candidate stage and the
registry is read back.

## Artifact cleanup and retention contract

The same cleanup criteria apply to the Windows workstation and the Linux
server. A filename containing `fail`, `old`, `current`, `fix`, `final`, or a
PID/timestamp is not, by itself, evidence that an artifact is disposable.
Every candidate artifact is classified before cleanup as one of:

- **current** — the exact seal-bound stage, its coordination lock, the active
  run, or an input/install target currently referenced by the approved packet;
- **durable evidence** — before-state receipts, backups, rollback directories,
  audit records, failure transcripts needed to explain a gate, and the last
  known-good sealed run;
- **failed disposable attempt** — an incomplete stage or `.building`/`.incoming`
  sibling created by a known run, after that run has stopped and ownership is
  proven;
- **obsolete or ambiguous** — anything outside the canonical allowlist, with an
  old identity, conflicting binding, unknown owner/type, active lock, or
  incomplete provenance. Ambiguous artifacts are never auto-deleted.

### Cleanup timing

1. **Immediate cleanup is allowed only for local scratch and failed disposable
   stages** after bounded process-tree cleanup, lock non-ownership proof, exact
   path confinement, `lstat` type/owner/mode/link-count checks, and a read-back
   showing that no current candidate or rollback record references the path.
   This includes temporary transport probes, generated bytecode/cache files,
   and failed `.building`/`.incoming` directories created by the current run.
2. **Server staging failures are quarantined first**, not deleted directly:
   move only the exact owned failed path into a run-id quarantine directory,
   preserve a manifest and reason, and retain it for at least 7 days. Delete it
   only after a second inventory confirms no live lock, process, approved
   operation, rollback reference, or audit dependency.
3. **Failure logs and `*.fail` transcripts are retained for at least 30 days**
   or until the incident review is closed, whichever is later. Duplicate or
   regenerated traces may be removed only when an indexed copy with matching
   hash remains in the evidence root.
4. **Backups, before-state receipts, rollback directories, installed-state
   evidence, and the last known-good run are durable artifacts.** Retain them
   until the next deployment has passed independent postflight and rollback
   verification, then retain for at least 30 additional days. Durable backups
   under `D:/ServerBackups/` and root-owned server rollback directories require
   explicit cleanup approval; age alone never authorizes deletion.
5. **Current candidate stage and coordination lock are retained** until the
   operation is explicitly completed or abandoned. Never remove a lock because
   its filename is old; prove the lock is not held using the lock protocol and
   re-read its owner/type/mode/link count immediately before any cleanup.

### Cleanup safety and read-back

- Workstation cleanup is confined to the task's `.ops-tmp` root. Server cleanup
  is confined to exact allowlisted paths under `/home/zenit/.ops-tmp` or a
  reviewed root-owned quarantine; broad `rm -rf`, wildcards, traversal,
  symlink-following, hard-link cleanup, and age-only deletion are forbidden.
- A candidate, archive, binary, or script is not disposable until its exact
  type, owner, mode, link count, SHA-256, stage/run identity and references
  have been read back. Existing production inputs and installed binaries are
  preserved even when their size or name differs from a new candidate.
- On ambiguity, partial state, unexpected extra entry, active lock, or failed
  read-back, cleanup fails closed and the artifact remains quarantined.
- After every approved cleanup, independently read back exact absence of the
  removed paths, the remaining directory entry set, adjacent service/timer
  state, and unchanged hashes for all out-of-scope targets. Record the cleanup
  manifest, operator approval, reason, before/after hashes and rollback handle.

No cleanup of server artifacts was performed by this document change; inventory,
classification and any destructive action remain separate approval gates.

## Readiness

Netlab readiness for a controlled production deployment: **78%**.

| Gate | Weight | Ready |
|---|---:|---:|
| Official supplier-owned sources | 10% | 10% |
| Bounded acquisition and freshness | 10% | 10% |
| Immutable archive/metadata boundary | 10% | 10% |
| Price and properties parsers | 10% | 10% |
| Approved supplier-feed FX pricing | 10% | 10% |
| Deterministic matching/proposals | 10% | 10% |
| Verifier and replay evidence | 10% | 10% |
| Scheduled shadow operations | 10% | 6% |
| Effective-price and stock policies | 10% | 2% |
| Publisher, canary and rollback | 10% | 0% |

Read-only engineering is substantially complete. The missing 22% is intentionally concentrated at production boundaries, not parser work.

## Remaining before deployment

1. Install the supervisor under an approved Task Scheduler/service account and add overlap locking, retention and alert delivery.
2. Refresh the catalog snapshot through an approved read-only acquisition path; the current live evidence uses catalog SHA-256 `49471b9f…`.
3. Run consecutive scheduled snapshots and establish normal change-rate/shrinkage baselines.
4. Resolve or explicitly quarantine the `5,297` conflicts and `75` ambiguous matches.
5. Confirm effective storefront pricing when specials/customer groups are active.
6. Approve stock, missing-item and lifecycle rules; the feed currently covers only about 42.95% of the scoped `31*` catalog, so missing actions remain blocked.
7. Complete independent adversarial code review and GitHub CI.
8. Separately design and approve publisher, canary, exact before-state backup, three-way read-back and rollback. Do not use the legacy importer as fallback.
