# Operating state

**Snapshot:** 2026-09-20 15:36 +0300
**Repository:** `D:/Sites/mks123/supplier-pipeline`
**Mode:** Netlab source-covered production-candidate hardening and GitHub handoff
**Production catalog/media/publication writes:** `0`
**Publication:** disabled
**Overall release:** **BLOCKED**
**Public audit:** `docs/NETLAB_PROJECT_AUDIT.md`
**Full audit:** durable local evidence only; it is not part of the public repository.

## Current gates

- `uv run pytest -q`: **PASS** (`526 passed, 18 skipped`).
- `uv run ruff check .`: **PASS**.
- `git diff --check`: **PASS** before the GitHub commit.
- `python -m compileall -q mks123_pipeline .ops-tmp`: **PASS**.
- Hermes registry/plugin validation: **PASS** for the configured runtime files.
- Local MariaDB production-writer fixture: **PASS**; forced catalog count mismatch produced handler failure and rollback.
- Current r7 self-enforcing packets: **LOCAL_ONLY_NOT_EXECUTED**.
- Current independent exact-byte review: **PENDING/BLOCKED**; the dispatched reviewer hit provider HTTP 429 and did not return a valid review.
- Production reconciliation after the restore rehearsal: **BLOCKED/PARTIAL**; product/attribute/category identity matched, but full database equality was not proven.
- Media ACL, exact document root, image route, and production HTTP canary: **PENDING**.
- Production catalog/media/publication mutation: **NOT EXECUTED**.

## Current Netlab candidate

- Catalog: `2,787` updates, `11,430` creates, `14,217` records.
- Attributes: `710` seed rows.
- Media: `14,217` main assignments, `10,430` gallery rows.
- Media policy: first unique image is main; later unique images are gallery; source JPEG/PNG/WebP bytes are retained.
- Exceptions: five 404 URLs and products without image URLs remain explicit exclusions.
- Any candidate byte, policy, schema, selection, or helper change invalidates dependent review and approval.

## Completed layers

### Code and evidence

- Source, matching, staging-transfer, media, and evidence integrity controls were strengthened.
- Audit provenance is preserved across JSON round-trips.
- Media handling retains source bytes and format; no mandatory conversion, resize, or recompression is performed.
- Self-enforcing production-writer packet generation was added for catalog, attributes, media, and publication phases.
- Project context and operational handoff documents were added.

### Staging

- Clean staging catalog apply: `12,788` creates; products `75,059 -> 87,847`; `15,588` audit rows.
- Full staging media apply: `14,217` products, `14,217` main assignments, `10,430` gallery rows.
- Media canary: `24/24` HTTP reads returned `200` with matching image hashes.
- Five media failures remain explicit exceptions.

### Production preparation

- Exact product identity snapshot: `75,059` rows.
- Attribute IDs: `5,546`.
- Category IDs: `1,263`.
- Offline catalog/media/publication candidates built without production catalog/media/publication DML.
- Hermes read-only connection, storage, rollback-inventory, backup, and restore-containment operations recorded.

## Restore incident boundary

A previous restore rehearsal imported an unsuitable dump containing production-targeting database statements. The event is contained and documented in the durable release evidence. It did not execute the approved catalog/media/publication rollout DML. Product identity, attribute IDs, category IDs, and isolated no-database restore checks matched. Full post-restore database equality was not proven.

Do not reuse a dump containing `CREATE DATABASE`, `USE mks123`, or production-targeting `DROP TABLE` for a rehearsal. Future rehearsal imports must use a no-database dump and an isolated temporary database, followed by absence read-back and cleanup verification.

## Current exact packet identities

The current self-enforcing r7 packet is local-only. The durable manifest records the complete file map and expected counts. Key identities:

- catalog SHA-256: `c9414f4cfe5c10280b2577d68754085706373c17e7639a500457bf8ab799691a`;
- media SHA-256: `065d6f6d7a3023cb714d9c757296d3ade1b7292e84fdd0443548823fac929ce2`;
- publication SHA-256: `50f208fd7c9ba8e4b74e1e277f71871b0c0a46ae8a1d85bf4d8708a4b656ad3e`;
- writer bundle SHA-256: `4b532814c3d845a7092acc39dfe639d75a9d2c107b6ec7a644fe314af6860749`;
- root helper SHA-256: `3ca7ba7947b36f685b027f43592b22c41bd0fe139826b8d7e9fb427380b01c7b`.

Any byte/config/schema/policy change requires a new manifest, review, and gate.

## Remaining P0 gates

1. Complete an independent adversarial review of exact current packet and writer bytes. HTTP 429 is not a review result.
2. Reconcile current production after the restore rehearsal beyond product/attribute/category identity.
3. Create and validate a fresh backup bound to the exact candidate and writer bundle.
4. Validate the existing `oc_netlab_transfer_audit` schema against the writer preflight contract.
5. Resolve production media ACL/readability, document root, image route, and HTTP canary.
6. Complete attribute mapping review for missing and ambiguous names.
7. Rebuild the release packet after all byte changes and obtain fresh phase-specific approval.

## Remaining P1 gates

- bounded production canary after P0 gates;
- original-byte HTTP/media read-back;
- exact catalog/media/publication count and exception read-back;
- status/indexing and storefront checks;
- isolated/no-database rollback rehearsal;
- independent review after every candidate/config/policy change.

## Repository/GitHub handoff

The public source repository contains code, tests, non-secret documentation, and the redacted audit. It does not contain production dumps, media CAS objects, transient `.ops-tmp` scripts, credentials, private keys, cookies, or the full internal audit. Hermes profile/plugin changes remain outside this repository.

The current source snapshot was uploaded to branch `feat/netlab-live-shadow`. The production release gate is independent of GitHub upload and remains BLOCKED.

## Next bounded action

Finish the exact-byte independent review, production reconciliation, fresh backup binding, audit-schema validation, media ACL/route canary, and release packet rebuild. Do not execute production SQL until all P0 gates and final approval pass.
