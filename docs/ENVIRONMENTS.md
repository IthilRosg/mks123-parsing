# Environment register

**Current superseding state — 2026-09-20:** the Netlab candidate is local-only and the production rollout is BLOCKED. Read-only production identity/ID capture and backup/restore containment were performed through the registered Hermes path; catalog/media/publication rollout DML remains `0`. Full post-restore database equality is not proven. See `docs/NETLAB_PROJECT_AUDIT.md`.

This register separates verified locations from assumptions. It contains no
credentials and does not authorize writes.

| Environment | Locator | Verified state | Writable scope | Rollback handle |
|---|---|---|---|---|
| Windows project | `D:/Sites/mks123/supplier-pipeline` | Git worktree with mixed existing changes; full tests currently green | Local code/docs/tests only under approved task | Git diff plus durable before snapshots; no automatic reset |
| Windows disposable ops | `D:/Sites/mks123/.ops-tmp` | Used for one-off reviewed scripts; cleanup read-back completed for this packet | Task-local temporary files only | Remove exact owned files; no broad cleanup |
| Durable evidence | `D:/ServerBackups/mks123webserver/` | Full/canary/apply and rehearsal receipts present | New evidence roots only; preserve historical roots | Exact before dump and receipt paths |
| WSL Debian MariaDB | socket `/run/mysqld/mysqld.sock`, port 3306 | MariaDB 11.8.6; local socket usable | Named isolated staging DB only | Before dump plus semantic restore receipt |
| Full staging DB | `mks123_stage_full_transfer_20260910` | Historical full transfer read-back PASS; 127,405 products | No repeat apply without new candidate/approval | Historical apply receipt and before dump |
| Canary staging DB | `mks123_stage_transfer_20260910` | Historical canary read-back PASS | No repeat apply without new candidate/approval | Canary before/apply receipts |
| Synthetic rehearsal DB | `mks123_stage_rehearsal_20260910` | Apply + restore rehearsal PASS; retained intentionally | Synthetic rehearsal only | `netlab-staging-rehearsal-v3-20260910/before.sql` |
| Accidental local DB | `mks123` | Created by an earlier dump import; retained | No writes/deletion in this task | Separate explicit cleanup decision |
| Historical HTTP clones | ports `18080`, `18082` | Not certified in this packet; current listener/URL must be rediscovered | Read-only browser/HTTP checks only after explicit staging scope | Server-specific backup required |
| Remote production | registered remote target | Read-only identity/ID snapshots, backup, and restore-containment operations performed through Hermes; catalog/media/publication rollout DML `0`; full post-restore equality unproven | No new catalog/media/publication writes until release gate passes | Durable backup and containment receipts; fresh reconciliation required |

## Rules for paths

Native Windows commands use `D:/...` paths. Commands executed inside WSL use
`/mnt/d/...`; redirection belongs inside `wsl ... bash -lc`. Never infer an
HTTP URL, schema, account, or production path from a filename or an old receipt.
Read it back from the live approved environment first.

## State labels

- **PASS:** exact command and read-back evidence exists.
- **PARTIAL:** a bounded layer passed but a broader gate is missing.
- **BLOCKED:** required approval, target, or evidence is unavailable.
- **FAIL:** a tested invariant failed; preserve the receipt and do not retry
  blindly.

A local or synthetic PASS never implies production or storefront readiness.
