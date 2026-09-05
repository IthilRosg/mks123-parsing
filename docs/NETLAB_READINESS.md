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
`mks123webserver` / Tailscale `100.81.66.42`, service account `zenit`. Remote
installation has not been executed: BatchMode SSH returned `Permission denied`
and credentials were not guessed or collected.

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
