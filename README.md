# mks123 supplier catalog pipeline

Read-only supplier parsers, deterministic matcher and proposal-only price engine.

## Current operating scope

The critical path is supplier catalog ingestion. The production scope has three supplier groups: Electrozone (`11`), Netlab (`31`) and Vetcom (`41`). Electrozone was the first adapter test, not the complete supplier scope. Each site has a separate parser, while normalization, class-aware characteristics, matching, proposals, registry enrichment and publication gates remain common. Product descriptions, raw supplier attributes, identity evidence, source URLs and provenance are collected without requiring a registry export.

| Supplier | Catalog SKU prefix | Adapter | Observed source format | Read-only status |
|---|---:|---|---|---|
| Electrozone | `11` | `ElectrozoneAdapter` | supplier YML/XML | current supplier URL returns `401`; previous pilot only |
| Netlab | `31` | `NetlabAdapter` | supplier `pricexml4.zip` / `xml_catalog` | live supplier-owned run accepted; USD FX blocked |
| Vetcom (ВТК) | `41` | `VetcomAdapter` | supplier B2B export pending | supplier-owned B2B found; no public XML/export endpoint |

Netlab and Vetcom profiles are available as `config/netlab.yaml` and `config/vetcom.yaml`. A profile selects an adapter through the fail-closed factory; it does not enable pricing, registry promotion or publication.

Registry enrichment is an optional, non-blocking branch. The current pilot keeps it disabled in `config/pilot.yaml`; a supplier phrase such as `реестр` or `Минпромторг` creates only an internal review signal. The visible secondary category `Реестровое оборудование` requires exact primary PP-878 evidence and is never populated from a supplier label or an unverified registry export.

## Supplier adapter contract

Each site-specific adapter exposes `supplier_id`, `catalog_sku_prefix` and `parse(...) -> SupplierSnapshot`. The common runner then applies the same normalization, full attribute preservation, deterministic matching, proposal gates, DuckDB output and sealing. A failed or quarantined adapter does not block a different supplier's read-only run.

## Current guarantees

- Production writes do not exist in this package.
- Raw YML/XML is content-addressed and retained locally with SHA-256 metadata; every run first captures source/catalog/config/state inputs into its own bundle, verifies byte-for-byte read-back, and seals the complete bundle. Completed artifact files are marked read-only; the seal is an integrity/checksum boundary, not a cryptographic signature.
- Feed dates are accepted only as `YYYY-MM-DD HH:MM` and cannot influence paths outside `raw/`.
- XML is parsed with `defusedxml`; one bounded byte read supplies both XML parsing and the recorded source SHA-256, removing separate stat/open and parse/hash races.
- Electrozone acquisition is included as a direct allowlisted HTTPS Basic Auth connector. It uses bounded downloads, rejects redirects and HTML responses, validates YML before installation and stores the accepted source as an immutable snapshot.
- The PowerShell wrapper resolves the Electrozone feed credential from the current user's DPAPI store. Credentials are inherited by the connector only for the child process and must not be stored in Git, YAML, argv or reports.
- Each adapter maps its supplier offer ID to its own catalog SKU prefix: Electrozone `11 + offer_id`, Netlab `31 + offer_id`, Vetcom `41 + offer_id`.
- Netlab accepts the supplier-owned `pricexml4.zip` boundary, preserves `uid`, `PN`, `GTIN`, all `priceR`…`priceF` levels, URLs, images and raw fields; `priceE` remains the configured source-price level. Documented `count=* / ** / ***` values are availability signals, not numeric quantities. `GoodsProperties.zip` is parsed by a separate streaming, review-aware template.
- Vetcom preserves full descriptions, repeated pictures and repeated barcodes. Multiple distinct barcodes remain ambiguous (`ean=null`) rather than selecting one; a non-positive quantity is retained but normalized as unavailable.
- Exact SKU is primary. Unique EAN and unique manufacturer+model are review signals only.
- Duplicate identities, conflicting populated EAN/model/manufacturer and ambiguous matches cannot become price proposals.
- Approved price-preview policy: `site_price = supplier_price × 1.10`; supplier price already includes VAT, and the preview applies no extra VAT step, fixed cost, minimum-margin rule or rounding. RUR/RUB use explicit parity `1`; non-RUB and non-parity rates are blocked by the current policy.
- CSV exports neutralize spreadsheet formulas; unmodified normalized provenance is retained as JSONL.
- The validated YAML config enforces read-only publication and the selected adapter's SKU scope.
- The catalog CSV is read once into memory; matching and the recorded catalog SHA-256 use those exact same bytes.
- Each run is built in a private staging directory under a persistent OS-backed reservation lock and is published as one complete directory; concurrent invocations cannot mix artifacts, and abandoned stages are recovered only after the lock is acquired. Run names use an allowlist and cannot inject glob metacharacters into cleanup.
- `feed_completeness.status=blocked_incomplete` is emitted when any scoped catalog product is absent. In that state `consecutive_missing_runs` is not advanced and no missing-product action is proposed. A complete feed may produce a quarantine proposal, but read-only mode never writes it.
- Verification output and operator-authored findings are stored beside runs under `verification/`, never written into an existing immutable run.

## Run

The supported operating mode is a checked-out repository initialized with `uv sync --frozen`. The wheel is a build-integrity artifact, not a deployment bundle; operational YAML profiles and PowerShell wrappers are intentionally run from the checkout.

### Electrozone read-only acquisition

Provision the supplier credential once through hidden console input:

```powershell
.\scripts\provision_supplier_credential.ps1 -Supplier electrozone
```

Then obtain and validate an immutable local snapshot without touching the production catalog:

```powershell
.\scripts\run_fetch_electrozone_current.ps1
```

The connector exits fail-closed on missing credentials, authentication/network errors, redirects, HTML responses, oversized responses, malformed YML or an offer count outside the configured acceptance range.

### Proposal generation

```bash
uv run python run_pilot.py \
  --source <path-to-raw-feed> \
  --catalog <path-to-catalog.csv> \
  --output runs/electrozone-<sha8>-catalog-<sha8>-vN \
  --fetched-at <UTC timestamp> \
  --config config/pilot.yaml
```

For another supplier, use the matching profile, for example `--config config/netlab.yaml` or `--config config/vetcom.yaml`. The source snapshot must be supplied separately; a failed/empty/malformed live fetch never replaces a last-known-good snapshot. The fresh Netlab evidence is documented in `verification/reports/NETLAB_PROVIDER_LIVE_RESULT_2026-09-04.md`.

### Three-supplier batch

`run_all.py` is the operator-facing read-only batch. It always evaluates Electrozone (`11`), Netlab (`31`) and Vetcom (`41`) independently, writes one sealed run per accepted source, and writes `aggregate.json`. A missing or rejected feed is reported as `BLOCKED`; the batch does not convert it into success.

```bash
uv run python run_all.py \
  --catalog <path-to-catalog.csv> \
  --output-root runs/batch-<safe-name> \
  --fetched-at <UTC timestamp> \
  --source electrozone=<path-to-electrozone.yml> \
  --source netlab=<path-to-pricexml4.zip> \
  --source vetcom=<path-to-vetcom.xml>
```

To carry proposal-only missing-product state between successful verified runs, provide `--state-root`; add `--install-state` only when the local state promotion itself is intended. This never writes the production catalog.

### Generic verification

```bash
uv run python verify_run.py \
  --run runs/<supplier-run> \
  --source <same source file> \
  --catalog <path-to-catalog.csv> \
  --config config/<supplier>.yaml
```

The verifier checks `seal.json`, manifest/input hashes, policy hash, summary/CSV/JSONL counts, identity uniqueness, DuckDB table counts and deterministic semantic content digest, read-only mode and missing-action gates. It returns exit `0` only for a full PASS.

## Test

```bash
uv run python -m pytest -q
```

## Output contract

```text
inputs/source.<feed-suffix>
inputs/catalog.csv
inputs/config.yaml (when supplied)
inputs/previous-state.json (when supplied)
normalized/items.csv
normalized/items.jsonl
matches/matches.csv
matches/review_queue.csv
matches/source_only.csv
matches/catalog_missing_supplier.csv
proposals/proposals.csv
proposals/category-mapping-proposals.csv
proposals/product-category-proposals.csv
reports/summary.json
reports/REPORT.md
state/next-missing-state.json
run-manifest.json
pilot.duckdb
seal.json
```

`aggregate.json` and `approval/<supplier>-<run-id>.json` are written by the batch command next to its supplier run directories. Approval files are pending templates bound to the run seal; they are not publication authorization.

See `ARCHITECTURE.md` for the planned promotion path. The supplier price preview policy is approved, but publication remains absent until the remaining operational rules, live-feed acceptance, preview approval and independent verification are complete.
