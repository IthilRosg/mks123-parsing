# Two-category MKS123 pilot scope

**Status:** approved working scope for planning; no production approval
**Captured:** 2026-09-11 01:13 +0300
**External writes in this scope change:** `0`

## Business scope

The first pilot is limited to the two root categories shown in the MKS123
storefront screenshot:

1. **`category_id=456` — `Ноутбуки и компьютеры`**
2. **`category_id=537` — `Смартфоны,ТВ и электроника`**

The IDs and names were read from the preserved OpenCart database snapshot:

`D:/ServerBackups/mks123webserver/opencart-20260908/mks123-database-20260908-01.sql`

using `oc_category_description` and the parent links in `oc_category`. In that
snapshot root `456` has 132 categories including descendants and root `537` has
103 categories including descendants. These counts are snapshot evidence, not a
claim that the live tree has not changed; the live category tree must be read
back before a candidate is frozen.

The exact root names are preserved literally. Do not silently normalize the
comma in `Смартфоны,ТВ и электроника` or replace the IDs with names.

## What is out of scope

- The current full source set of `65,931` rows.
- The current full transfer candidate of `57,700` records.
- All other root categories and their descendants.
- Automatic missing-item, stock-zero, or lifecycle actions outside the selected
  category trees.
- Production catalog, category, media, CMS, or storefront writes without a
  separate explicit approval packet.

The full candidate must not be treated as a two-category candidate. Its records
currently carry Netlab `category_json` source paths and do not carry a complete,
verified target-site category assignment. Text similarity or a filename is not
sufficient to include a product.

## Candidate contract

A new pilot candidate is acceptable only when its immutable manifest binds all
of the following:

- live/read-back target root IDs `456` and `537`;
- the complete descendant-ID allowlist used for this run;
- the site category-tree snapshot hash and capture time;
- source snapshot identity and freshness (maximum age 24 hours; future skew no
  more than 15 minutes; malformed timestamps fail closed);
- a separately supplied trusted run-manifest/evidence seal binding the normalized
  source, matches, category proposals, and category-tree snapshot bytes;
- an externally recorded expected seal SHA-256 and fixed durable trust root
  (`D:/ServerBackups/mks123webserver`); a self-generated local seal outside that
  root is not trusted;
- source-to-site mapping decisions and explicit exclusion counts;
- exact record count and action counts;
- `RECORDS.jsonl`, SQL, manifest, and provenance hashes;
- code/policy identity and run ID;
- a semantic validator proving SQL values equal the canonical records before any
  database write; schema-v2 apply also requires `--trusted-run-manifest` and
  `--expected-trusted-run-seal-sha256` and rejects schema-v1 candidates.

Rows with ambiguous, unmapped, stale, or conflicting category mapping remain
excluded or review-only. They do not enter the publishable pilot by default.

## Intended sequence

### 1. Read-only selection

Refresh the supplier snapshot, read back the current site category tree, map
source paths to the two approved trees, and produce an exclusion report. No
production or CMS write occurs.

### 2. Isolated staging

Apply only the frozen pilot candidate to an isolated staging database. New
products remain disabled and unindexed (`status=0`, `noindex=1`). Assign only
allowlisted categories and verify exact category relations in read-back. The apply path requires a pre-created `oc_netlab_transfer_audit` table with the
exact InnoDB/utf8mb4 column and index contract. All pilot tables must be InnoDB;
any non-InnoDB engine is rejected by preflight before backup or DML. For an
accepted apply, one physical MariaDB client acquires the named coordination lock,
starts a SERIALIZABLE transaction, writes the before-state metadata snapshot through
that same client, then retains the session through candidate execution, read-back,
pending receipt, commit, and rollback. Candidate snapshots use an exclusive OS
file lock on Windows or POSIX. Rollback is transaction-only, with validated
counter-reset DDL after rollback; no logical restore or advisory-only
nontransactional fallback is supported. Revalidate source freshness
directly before candidate DML. Preserve and hash original source images before any
photo transformation.

### 3. Photo/media preparation

Create or normalize product photos only for selected staging products. Keep
original supplier URLs/hashes, derived image hashes, dimensions, crop policy,
and failures in the evidence bundle. Do not overwrite production media during
this phase.

### 4. Storefront verification

Check category navigation, product cards, product pages, image URLs, thumbnails,
responsive layout, descriptions, properties, pricing, disabled/noindex behavior,
and absence of publication leakage. Verify by browser/read-back, not HTTP status
alone.

### 5. Separate publication decision

After staging, media, and storefront checks pass, prepare a separate narrow
production publication packet. It must include before-state, backup, exact
product/category/media scope, read-back, rollback, and explicit user approval.
This scope document itself does not authorize publication.

## Current state

- The current local verifier has independent selector replay from stable captured
  input copies, explicit target-to-root descendant checks, an external seal digest
  and fixed durable trust-root check, Windows/POSIX exclusive candidate snapshot
  locking, source freshness bounds at validation and execution boundaries,
  non-default language binding, guarded audit/relation DML, and a strict audit
  schema contract.
- The staging apply path now fails closed before backup/DML unless every pilot table
  is InnoDB and the pre-created audit table matches the exact InnoDB/utf8mb4
  columns and keys contract. MyISAM is explicitly outside this pilot contract.
- Full local gate is **PASS** (`439 passed, 13 skipped in 125.21s`); focused affected
  gate is **PASS** (`60 passed, 0 skipped`). This is local quality evidence, not
  independent acceptance.
- Fresh price/properties acquisition is **PASS** and read-only; the new source is
  within the 24-hour bound. Live category navigation read-back is **PASS** with
  `456=132/132` and `537=103/103`; evidence is
  `D:/ServerBackups/mks123webserver/netlab-shadow-20260914/category-live-readback.json`.
- The fresh POSIX shadow completed `52/52` checks with `production_writes=0`, but
  its sealed run is evidence-only at
  `D:/ServerBackups/mks123webserver/netlab-shadow-20260914/posix-sealed-run-untrusted/`.
  The fixed Windows D: trust root is writable NTFS and Windows rejects sealed-run
  verification because POSIX descriptor primitives are unavailable.
- The latest exact-byte review `deleg_23f34dff` is **PASS** for the current
  `5dc42a8d…` implementation; security concerns and logic errors are empty.
- No current trusted filtered candidate, staging apply receipt, live DB read-back,
  or rollback receipt exists. The historical two-record v22 rehearsal remains
  pre-remediation evidence only.
- No production catalog writes, CMS writes, media publication, category writes,
  storefront publication, commit, or cleanup were performed for this scope.
- The next safe gate is an approved POSIX trusted-root execution target; only after
  that target can the fresh source/category inputs be rebound into a trusted
  filtered candidate and an isolated InnoDB staging apply be considered.
