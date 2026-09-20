# mks123 / Netlab — current project audit

**Snapshot:** 2026-09-20
**Repository:** `IthilRosg/mks123-parsing`
**Status:** source and local validation PASS; production rollout BLOCKED

## What this project is

This is a Python supplier-ingestion and catalog-evidence pipeline. It supports source acquisition, normalization, matching, pricing/properties, category/manufacturer evidence, read-only shadow validation, isolated staging transfer, original-byte media preparation, and release receipts.

It is not a general-purpose CMS and it is not currently a production publisher. Production publication, media, category, compatibility, storefront, and remote-privilege operations are separate approval gates.

## Current Netlab scope

The current approved source-covered candidate contains:

- 14,217 catalog records;
- 2,787 updates;
- 11,430 new-product creates;
- 710 attribute dictionary seed rows;
- 14,217 main-image assignments;
- 10,430 gallery rows;
- original JPEG/PNG/WebP bytes preserved;
- first available unique image used as main, later images as gallery;
- five 404 URLs preserved as explicit exceptions;
- products without image URLs excluded from automatic image publication.

No fabricated images are substituted, and existing production main images are not automatically overwritten.

## Architecture and plan

The controlled flow is:

1. acquire and fingerprint source data;
2. validate freshness, provenance, matches, and exceptions;
3. build an immutable candidate and evidence bundle;
4. run read-only shadow checks;
5. apply only to isolated staging with a before-state backup;
6. read back all affected fields and untouched-scope invariants;
7. prepare media separately while preserving source bytes;
8. build exact production packets;
9. obtain an independent review and fresh approval;
10. run production canary, read back, and publish only as a separate approved phase.

## Completed work

- source, matching, staging-transfer, media, and evidence integrity controls were strengthened;
- staging catalog and media rehearsals completed;
- media download/assignment policy implemented with explicit 404/no-image exceptions;
- production identity and ID snapshots captured read-only;
- self-enforcing production-writer packets were generated;
- local MariaDB fixtures verified successful catalog/media paths and catalog rollback on forced count mismatch;
- full local quality gates passed: **526 tests passed, 18 skipped**, Ruff, compileall, and diff hygiene;
- Hermes registry/plugin validation passed for the configured runtime path.

## Current production state

No production catalog, media, or publication DML has been executed for this rollout. A previous restore rehearsal used an unsuitable production-targeting dump; the event was contained and documented. Key identity checks matched, but full database equality after that event was not proven. This is why production remains blocked.

The newest independent exact-byte review did not complete because the review provider returned HTTP 429. A partial or rate-limited review is not a PASS. The earlier production packet review was FAIL/BLOCKED.

## Remaining blockers

### P0

1. Complete an independent adversarial review of the exact current packet and writer bytes.
2. Reconcile production after the restore rehearsal beyond product/attribute/category identity.
3. Create and validate a fresh backup bound to the exact release candidate.
4. Validate the existing audit-table schema against the writer contract.
5. Verify media storage ACLs, document root, image route, and HTTP canary.
6. Resolve missing/ambiguous attribute mapping before mutation.
7. Rebuild the release packet after all byte changes and obtain fresh approval.

### P1

- run a bounded production canary;
- verify original media bytes through the real serving path;
- read back exact catalog/media/publication counts and exceptions;
- verify status/indexing behavior and storefront rendering;
- rehearse rollback only with an isolated/no-database restore method;
- repeat independent review after every candidate/config/policy change.

## Tools used

- Python, `uv`, pytest, Ruff, compileall;
- Git and GitHub CLI;
- WSL/MariaDB for disposable SQL rehearsal;
- Hermes registered SSH broker for remote checks and privileged operations;
- OpenSSH agent through the registered Hermes path;
- browser canary checks for staging;
- independent delegated adversarial review.

No credentials, private keys, tokens, cookies, dumps, CAS objects, or transient operator scripts are part of this public repository upload.

## Release verdict

| Gate | Result |
|---|---|
| Repository code/tests | PASS locally |
| Staging catalog/media | PASS / explicit exceptions |
| Production candidate | Prepared, local-only |
| Full restore equality | Not proven |
| Independent current review | Pending; latest attempt rate-limited |
| Media ACL/route/canary | Pending |
| Production rollout | **BLOCKED** |

The next safe action is to close the P0 blockers, not to execute production SQL.
