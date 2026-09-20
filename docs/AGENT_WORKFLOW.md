# Agent workflow for mks123

This document is the compact operational router for this repository. It does
not grant production or remote privilege. `AGENTS.md` is the project contract;
this file records how to choose a tool and how to hand off a task.

## Work-packet contract

Every non-trivial packet records:

- `task_id`, exact allowed paths/actions, and mode (`read_only`, `local_edit`,
  or `staging_write`);
- current candidate identity and source/matches hashes when applicable;
- `PENDING`, `RUNNING`, `PASS`, `PARTIAL`, `FAIL`, or `BLOCKED` state;
- current gate, durable evidence paths, one next bounded action, and approval
  reference (or `null`);
- actual start/finish time and verified runtime provider/model, or `unknown`.

Do not claim a total, percentage, or reply count unless it was parsed and
verified. Do not reuse a receipt after candidate bytes, policy, schema, or
selection changed.

## Tool decision table

| Need | Route | Gate |
|---|---|---|
| Read a bounded file | `read_file` | Use exact path; do not print secrets |
| Search files/content | `search_files` | Narrow root and file glob |
| Patch known code/text | `patch` | Read the surrounding current bytes first |
| Create a new artifact | `write_file` | Confirm path/scope; no credentials |
| Arithmetic, hashes, parsing, batch counts | `execute_code` or `terminal` | Use a script; do not mentally compute |
| Git/build/test/system state | `terminal` | Native command syntax; capture exit code |
| 3+ mechanical independent operations | `execute_code` | Reduce output programmatically |
| Public documentation | `web_extract`/`web_search` | Prefer official source; cite when answer depends on it |
| Authorized local browser | browser tools | Use only explicit local/profile scope |
| Remote privilege | registered executor only | Exact approval, target, rollback, read-back |
| Long bounded process | background terminal + process wait | Receipt and exit code required |
| User decision | `clarify` | Ask only when scope changes materially |

## Windows/MSYS/WSL contract

Native Windows tools receive `D:/...` or `C:/...` paths. Linux tools receive
`/mnt/d/...` paths inside WSL. Redirection must be interpreted by the target
shell, for example:

```text
wsl.exe -d Debian -- bash -lc 'mariadb --socket=/run/mysqld/mysqld.sock < /mnt/d/.../input.sql'
```

Do not let the outer MSYS shell interpret WSL paths. Do not put SQL backticks
inside an outer double-quoted command. For long SQL or rollback probes, write a
reviewed `.ops-tmp` script, run it, read back the exact result, then remove the
script.

## Pipeline routes

### Shadow/read-only

Acquire or use an approved immutable source snapshot; validate freshness,
source identity, pricing/rate provenance, matching, exceptions, and
`production_writes=0`. No database or publication write is implied.

### Staging transfer

Build a candidate with external trusted run-manifest/evidence seal, exact file map,
candidate ID, selection-bound run ID, source/matches hashes, freshness proof, and
records. Validate the same candidate from Windows and WSL. Confirm isolated target,
engines, schema, competing writers, and before-state metadata snapshot. Apply only with
`--confirm-staging-only --trusted-run-manifest <sealed-run-manifest>` and
`--expected-trusted-run-seal-sha256 <externally-recorded-digest>`; schema-v1
candidates are rejected. Read back every affected field, duplicate/multiplicity,
provenance, status/noindex, exact category relations, untouched relation semantic
digests, audit rows, and production flags. The pilot requires every fixed pilot
table to use InnoDB and requires the pre-created `oc_netlab_transfer_audit` table
to match its exact InnoDB/utf8mb4 columns and keys contract. The apply path holds
one physical MariaDB client with a database named coordination lock and SERIALIZABLE
transaction through preflight, before-state metadata
snapshot, candidate execution, read-back, pending receipt, commit, and rollback.
Candidate snapshots are protected by an exclusive Windows/POSIX OS lock and
post-execution identity checks. Non-InnoDB engines are rejected before backup/DML;
logical restore fallbacks are not supported, and counter restoration uses only
validated `ALTER TABLE ... AUTO_INCREMENT` statements after transaction rollback.

### Two-category pilot

The first business pilot is limited to site roots `456` (`Ноутбуки и
компьютеры`) and `537` (`Смартфоны,ТВ и электроника`), including only their
read-back descendants. The full `65,931`-row source and `57,700`-record
candidate are not the pilot. Require a fresh category-tree snapshot, explicit
source-to-site mapping, exclusion counts, category-bound manifest, exact SQL /
`RECORDS.jsonl` semantic binding, and a new candidate identity. In staging,
keep new products `status=0` and `noindex=1`, then test assigned categories,
media/photos, and storefront behavior. For the pilot apply, require a
pre-created `oc_netlab_transfer_audit` table matching the exact InnoDB/utf8mb4
columns and keys contract, and require every fixed pilot table to use InnoDB.
Use one physical MariaDB client with the named coordination lock and SERIALIZABLE
transaction before preflight; create the before-state metadata snapshot, candidate execution,
read-back, pending receipt, commit, and rollback through that same client. Candidate snapshots
require an exclusive Windows/POSIX lock and post-execution identity check. Non-InnoDB
fallbacks and logical restore are not supported; rollback counter restoration is
limited to validated `ALTER TABLE ... AUTO_INCREMENT` statements.
Production publication is a separate explicit approval gate.

### Storefront/production

This is a separate queue. Database transfer PASS does not authorize category,
media, compatibility, CMS, HTTP storefront, or production work. Require a new
scope, candidate, before-state, publisher/approval gate, and browser/API
read-back.

## mks123 business conventions

- Store price is supplier price multiplied by `1.10`; VAT is included.
- Supplier identity is internal and is not exposed to the customer.
- Registry references must use the approved EРРРП/ПП-878 convention; do not
  invent compatibility relations or categories from missing source data.
- Publication remains preview/approval/rollback gated. Forms and email are the
  current request path; Telegram/WhatsApp are future scope.
- These are project conventions, not permission to write production.

## Stop and escalation rules

Stop at the current safe boundary after two failed focused fix cycles or a
long operation that produces no new evidence. Preserve the failed receipt and
refresh quota telemetry. The active parent is Luna via `openai-codex`; no
provider fallback is implicit. Any independent review must use the configured,
actually available Codex route and return structured fail-closed output.

Do not fan out optional work while quota telemetry is critical/unknown. The
current task can proceed sequentially because independent review and profile
changes are gated separately.

## Handoff checklist

Before handing work to another session:

1. read current Git status and exact file map;
2. write/update `docs/OPERATING_STATE.md` with current date, candidate/result
   identities, completed/blocked gates, and next bounded action;
3. write/update `docs/AGENT_BENCHMARKS.md` when measurements or readiness
   percentages change;
4. preserve durable evidence and do not copy secrets;
5. state whether DBs, files, external systems, publication, or commits changed;
6. include elapsed time and the exact command needed for the next gate.
