# mks123 supplier and price pipeline architecture

## Boundary

This design is only for `mks123`. It does not share catalog mappings, pricing rules, jobs or publication credentials with `62masla`.

## Data flow

```text
credentialed source connector
  -> immutable raw snapshot + manifest + SHA-256
  -> supplier adapter
  -> Pydantic normalized items
  -> deterministic identity matcher
  -> catalog/source diff
  -> price and stock proposals
  -> validation gates
  -> human preview and approval
  -> narrow allowlisted publisher (future)
  -> production read-back x3
  -> append-only audit and rollback package
```

Acquisition, parsing, matching, pricing and publication are separate processes. A scraper cannot write OpenCart prices directly.

## Components

### 1. Source connector

Responsibilities:

- obtain one supplier feed using a secret reference;
- never print or persist credentials;
- stream directly to a unique temporary file in the local `raw/` directory;
- enforce connection/read timeouts, maximum response size at acquisition and parser boundaries, and pinned SSH host keys;
- feed one bounded byte buffer to both `defusedxml` and SHA-256 provenance so a pathname cannot change between size, parse and hash operations;
- reject HTTP errors, malformed YML, duplicate source identities, invalid container structure and offer counts outside the configured range;
- accept only the strict `YYYY-MM-DD HH:MM` feed date format and constrain the resolved target to `raw/`;
- read the downloaded part once, verify its SHA-256, then create the final snapshot name directly with an exclusive no-share Windows handle; write, flush, read back through the same handle, mark read-only, and close, with no hard-link or writable staging alias;
- serialize each content-addressed target with an ownership-safe OS byte-range lock so failure cleanup cannot remove a snapshot adopted by another installer;
- create metadata directly at its final name through the same exclusive write/flush/read-back/read-only sequence, with no hard-link alias or metadata temporary file, and clean the new snapshot/manifest on failure;
- record fetch time, feed time, byte length and SHA-256;
- retain the last known good snapshot when fetching fails.

The current Electrozone connector performs a direct HTTPS request to the exact allowlisted supplier URL. Its PowerShell wrapper loads the supplier credential from the current Windows user's DPAPI store and exposes it only to the connector child process. The source returns HTTP 401 without credentials. No SSH relay, browser session or production database lookup is part of this acceptance boundary; feed credentials must not be copied into YAML, source code, argv or reports.

### 2. Electrozone adapter

Normalized identity and commercial fields:

```text
supplier
supplier_item_id
catalog_sku
supplier_sku
manufacturer
model
mpn
ean
identity_warnings
name
category_id
category_path
source_price
old_price
currency
available
store
pickup
delivery
source_url
image_urls
description
sales_notes
manufacturer_warranty
warranty_days
vat
weight
dimensions
attributes
fetched_at
raw_hash
```

`offer.id` is the supplier identity. `catalog_sku = "11" + offer.id` is specific to Electrozone and versioned as adapter policy, not embedded in generic matching rules.

#### Supplier expansion

Electrozone is only the first adapter. Other supplier sites must implement the same normalized adapter boundary and must not duplicate matching, pricing, registry or publication logic. Each adapter preserves its own source URL, fetch timestamp, raw snapshot hash, supplier SKU, manufacturer/model/MPN, EAN, description, full raw attribute map, price/currency/VAT signal, availability and images. A supplier adapter may fail or be quarantined without blocking another supplier's read-only ingestion.

The executable boundary is:

```python
class SupplierAdapter(Protocol):
    supplier_id: str
    catalog_sku_prefix: str

    def parse(source_path, *, fetched_at, min_items, max_items, max_bytes) -> SupplierSnapshot: ...
```

`run_pilot(..., adapter=...)` sends the returned `SupplierSnapshot` through the same generic stages. `ElectrozoneAdapter` is the default implementation; its `11` prefix is not a generic matcher rule.

#### Netlab adapter (`31`)

`NetlabAdapter` accepts the supplier-owned `pricexml4.zip` boundary, validates the single top-level `Price.xml` member, then maps the `xml_catalog` fields explicitly:

```text
offer @id       -> supplier_item_id / catalog_sku = 31 + id
name            -> name
Vendor          -> manufacturer
Model           -> model
PN              -> mpn
GTIN            -> ean when it is singular
priceE          -> source_price (historical form 3, column 8)
count           -> quantity; `*`, `**`, `***` are documented availability signals with quantity unset
OutOfProd       -> availability override
url/picture*    -> source_url/image_urls
```

`uid`, `priceR`…`priceF`, `priceRRP`, `currencyId`, `count`, `OutOfProd` and every other direct source field remain in the raw attribute map. `GoodsProperties.zip` is an independent streaming enrichment input: the price offer `<uid>` joins only to `GoodsProperties.item.@id`, `p9999995` is the source description, and every property is retained with source-hash provenance. Unknown property IDs and invalid content remain review-only. The accepted Netlab pricing boundary uses `priceE` in USD and the USD→RUB rate from the same immutable `pricexml4.zip`.

#### Vetcom adapter (`41`)

`VetcomAdapter` accepts the historical `yml_catalog` root from `4.xml` and maps:

```text
offer @id       -> supplier_item_id / catalog_sku = 41 + id
price           -> source_price
name/vendor     -> name/manufacturer
description     -> full description
barcode         -> singular ean only when unambiguous
picture*        -> image_urls
quantity        -> quantity
categoryId      -> category and category path
```

Repeated pictures are all retained. Multiple distinct barcodes are retained under numbered raw attributes and leave normalized `ean` empty, so matching cannot select an arbitrary code. A negative or zero quantity is retained as an observed integer but forces normalized availability to false even when the legacy feed says `available="true"`.

The historical public `4.xml` snapshot was 2,535 offers with feed date `2023-05-24 11:16` and parsed successfully. The configured current `price_vetcom.xml` endpoint is unavailable/empty; that failure cannot replace the historical raw snapshot.

The minimum catalog path does not require a registry export. Registry status is an orthogonal enrichment field and is never inferred from a supplier category or product wording.

### 3. Identity matcher

Order and behavior:

1. Exact catalog SKU: candidate for an exact match.
2. Unique EAN in both source and target: review-only high confidence.
3. Unique normalized manufacturer + model/MPN in both source and target: review-only high confidence.
4. Non-unique source or catalog SKU/EAN/model: ambiguous; no product ID is selected.
5. Contradictory populated EAN or model: conflict.
6. Fuzzy names: diagnostic only; never an automatic identity decision.

Only `exact` is currently eligible to enter pricing. `high_confidence`, `ambiguous`, `conflict` and `unmatched` remain blocked until reviewed. A product may not be mapped to two source offers in one run.

### 4. Product proposal layer

New source-only products are stored as normalized records and category-mapping proposals. Product creation must be a separate approval mode from price updates. Required gates before future creation:

- unique supplier ID and generated SKU;
- approved source category -> OpenCart category mapping;
- manufacturer resolution without creating spelling duplicates;
- non-empty name, positive source price and known currency;
- image URL validation and local image review;
- attribute names/units normalized;
- SEO name and URL preview;
- no duplicate EAN, MPN or SKU in the target catalog.

The live pilot contains many source offers absent from the current `11*` catalog, so automatic creation is intentionally disabled.

Category mapping is learned only from existing `exact` SKU matches:

- `strong_candidate`: at least three exact references and 100% agreement;
- `review_candidate`: at least two exact references and at least 80% agreement;
- `ambiguous`: some historical evidence, but below the review threshold;
- `unmapped`: no exact historical evidence.

Even strong candidates remain `review_only`; category inference never makes a product publication-eligible. Conflicts and high-confidence identity matches do not train category mappings.

### 5. Optional registry enrichment

Registry enrichment is outside the critical path for supplier catalog ingestion. The catalog parser may collect and normalize a product even when the official PP-878 source is unavailable. A supplier phrase such as `реестр` or `Минпромторг` creates only an internal candidate signal; it does not create a public registry category link.

For each candidate, the enrichment branch records one of `confirmed`, `review_only`, `blocked`, `conflict`, `stale` or `not_found`. Only a primary PP-878 record with exact manufacturer + model/MPN, record identifier, source URL, status and validity can set `confirmed` and propose the secondary `Реестровое оборудование` link. Manufacturer pages and supplier descriptions enrich characteristics but do not replace primary registry evidence.

The current pilot keeps this branch disabled and non-blocking in `config/pilot.yaml`:

```yaml
registry_enrichment:
  enabled: false
  required_for_catalog_ingestion: false
  scope: PP-878
  primary_evidence_required: true
```

The 20 existing candidates remain a frozen review queue until a valid primary source is available. No supplier run should parse or wait on a full registry export merely to collect product descriptions, characteristics, prices or stock.

### 6. Price proposal engine

Formula implemented by the approved price-preview policy:

```text
site_price_rub = source_price × approved_rub_per_unit × 1.10
VAT = already included in source_price
proposed_price = site_price_rub
```

For RUR/RUB, the configured parity rate is `1`. For Netlab USD, the only approved rate is the positive `USD` value embedded in the same accepted supplier ZIP: it must be bounded to `40…200 RUB/USD`, bound to the source SHA-256 and supplier ID, and carried into the sealed policy manifest. The preview deliberately adds no VAT adjustment, fixed cost, minimum-margin calculation or rounding.

Every proposal stores:

```text
product_id
supplier_item_id
current_price
source_price
source_currency
exchange_rate
exchange_rate_source
markup_rule_id
cost_rub
calculated_price
proposed_price
delta_abs
delta_pct
match_confidence
status
warnings
```

The supplier VAT codes (for example `VAT_22`) remain preserved provenance, not a calculation input. The approved policy explicitly records the source price as VAT-included and applies one global rule, `supplier-price-plus-10@2026-09-03`. Exact, warning-free matches with an approved, snapshot-bound rate can therefore produce a review-only price proposal; no production writer is present.

#### Pricing policy precedence

The current first-phase policy has exactly one global rule. Product/category/manufacturer overrides are not implemented; any additional pricing rule requires a new explicit policy version and tests before it can enter the proposal path.

#### Currency policy

- RUR/RUB feed values use the explicit parity rate `1`.
- Netlab USD requires `source=supplier_feed`; the rate, supplier ID, observation time and source SHA-256 are stored in the policy manifest.
- Netlab direct acquisition treats `xml_catalog@date` as Moscow time, rejects snapshots older than 24 hours or more than 15 minutes in the future, and has no cached/external FX fallback.
- Any other currency/source/supplier combination remains `blocked_currency`.
- The 2021 OpenCart USD value is never used.

#### VAT policy

- The approved pricing basis is `included`.
- Supplier VAT codes are retained for provenance but are not recalculated or inferred from.
- The policy applies the direct multiplier `1.10` once to the supplier price.
- An unapproved future policy with VAT basis `unknown` must still block its own proposal run.

#### Safety gates

Block a proposal when any condition holds:

- match is not exact or separately approved;
- source price is zero/negative;
- currency or exchange rate is missing/stale;
- VAT basis is unknown or its policy version is absent;
- markup rule is absent or invalid;
- an active special/group price is later found to affect the storefront effective price; that case is outside the current base-price preview and remains review-only;
- current price is non-positive;
- absolute percentage delta exceeds the configured limit;
- the raw snapshot is malformed, duplicated or materially smaller than its baseline;
- too many products disappear or change in one run.

### 7. Stock and lifecycle proposals

Stock semantics remain adapter-specific observations. Electrozone exposes `available`, not a reliable numeric quantity. Netlab provides `count` plus `OutOfProd`; Vetcom provides `quantity` and an availability attribute, with non-positive quantity normalized as unavailable while the raw conflict is retained.

- source available + catalog zero: propose stock activation for review;
- source unavailable + catalog positive: propose stock deactivation for review;
- absent from one feed: keep the previous counter unchanged and block any missing-product action until the feed is structurally complete;
- absent from three consecutive complete, verified feeds: eligible for a quarantine proposal only;
- failed, empty, encoding-inconsistent or incomplete fetch: unknown state, never a mass zero/disable event.

Price and stock decisions are separate proposal fields and may be approved independently.

### 8. Storage and idempotency

Each run ID is derived from supplier, raw SHA-256, catalog SHA-256 and policy version. The source parser and catalog loader each operate on a single immutable in-memory byte snapshot; parsing/matching and recorded provenance hashes therefore refer to the same bytes. Repeating the same inputs must produce the same normalized, match and proposal records. A run is first built completely in a unique sibling staging directory protected by a persistent reservation file plus an OS lock; the OS lock is released if the process dies, and the next owner removes only abandoned stage directories while holding that lock. Only a completed bundle is renamed to its final run ID. A competing invocation receives `FileExistsError` and cannot mix artifacts. Before publication, `seal.json` records the exact allowed file set plus SHA-256 and size for every artifact. Verification loads captured evidence and performs a second hash/size stability check for the seal and each artifact before returning success; DuckDB is verified from a temporary copy of its sealed bytes, including a deterministic semantic content digest because the physical DuckDB container is not guaranteed byte-identical across builds. Verification reports and operator-authored findings are written under the separate `verification/` tree so a published run is not modified.

DuckDB tables:

```text
raw_manifest
normalized_items
catalog_snapshot
matches
catalog_missing_supplier
proposals
run_summary
```

The pilot creates normalized, matches, source-only, review-queue, missing-catalog and proposal tables represented by CSV artifacts; manifests and summary remain JSON until productionization.

#### Netlab refresh supervisor

The supervisor first issues conditional GETs for both `pricexml4.zip` and `GoodsProperties.zip` using `ETag`/`Last-Modified` from validated immutable metadata. A `304` creates an append-only acquisition receipt and can reuse local bytes only after size, SHA-256 and freshness checks; HTTP validators are bandwidth hints, never provenance. It keys a content-enabled run by price source, properties source, catalog, config, policy and executable-code hashes. An existing key is accepted only after the sealed run passes `verify_run.py`; then the supervisor returns `NO_CHANGE` without rerunning matching. Any changed hash receives a new full shadow run and verification. The scheduler interval, overlap policy, retention and alerts remain deployment configuration.

### 8.1. Self-contained run bundle and batch operator

`run_pilot` captures the exact source, acquisition metadata, catalog, optional config and optional previous state into `inputs/` before parsing. Content-enabled Netlab runs also capture `GoodsProperties.zip` and its acquisition metadata. The parser and catalog loader consume those captured bytes, not mutable external paths. `run-manifest.json` records a content-derived canonical `run_id`, supplier/prefix, input hashes and sizes, policy hash, code-file hashes, feed timestamps and content summary identity. `seal.json` covers the manifest and every artifact. The completed files are read-only; this protects against ordinary accidental writes but is not a cryptographic signature or trusted publisher identity.

`run_all.py` is the three-supplier read-only operator batch. It runs each supplier independently, verifies each accepted bundle with `verify_run.py`, emits `aggregate.json`, and returns `0` only when every configured supplier passes. Empty, malformed or encoding-inconsistent feeds are `BLOCKED`, not successful no-op runs. State promotion is local and explicit (`--state-root --install-state`) and is never a production catalog write.

### 9. Promotion path

Stages:

```text
read_only -> shadow -> approved_batch -> canary -> full_batch
```

- `read_only`: current state; no publisher exists.
- `shadow`: scheduled fetch and proposal generation, no writes.
- `approved_batch`: signed/hashed proposal file and explicit user approval.
- `canary`: at most a small approved product set.
- `full_batch`: bounded approved batch only after canary read-back.

Future publication must use a new root-owned narrow runner separate from the news runner. It accepts only a validated proposal hash from an allowlisted directory. It must not accept SQL, shell fragments or arbitrary file paths.

### 10. Backup, read-back and rollback

Before an approved write:

1. export exact before rows from `oc_product` and related stock/status tables;
2. bind the backup hash to the proposal batch;
3. update in one transaction;
4. read back every changed row from the database;
5. verify public desktop and mobile output independently;
6. perform a third independent API/DB/public comparison;
7. retain an inverse rollback payload.

Rollback restores only rows belonging to the batch and verifies their before-state hash to avoid overwriting later legitimate changes.

### 11. Observability

Per run:

- fetch status and duration;
- raw size/hash/feed timestamp;
- item/category counts and schema errors;
- exact/high-confidence/ambiguous/conflict/unmatched counts;
- source additions/disappearances;
- price/stock proposal status counts;
- delta percentiles and blocked anomalies;
- policy versions;
- publication batch ID, before/after hashes and three read-back results.

Alerts fire on fetch failure, stale snapshot, feed shrinkage, identifier duplication, match-rate collapse, mass stock disappearance, unknown currency, or publication/read-back mismatch.

## Current blockers before any price publication

1. Accept fresh, complete source snapshots for Electrozone and Vetcom; the live Netlab supplier snapshot is valid but does not cover the current `31*` catalog scope, so missing actions remain disabled.
2. Confirm the effective storefront price source, including active specials and customer-group prices; the current preview compares only the catalog base price.
3. Approve the remaining stock/lifecycle policy over consecutive successful runs; incomplete-feed previews do not authorize stock or status changes.
4. Review Netlab `5,300` conflicts and `75` ambiguous matches plus the existing Electrozone/Vetcom conflicts; source-only/category proposals remain review-only.
5. Complete independent adversarial review of the changed acquisition, pricing and refresh path.
6. Run multiple consecutive live shadow snapshots across normal supplier updates and define alert/retention/overlap operations.
7. Build and separately approve a narrow catalog publisher with backup, read-back and rollback flow.
