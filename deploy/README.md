# Netlab read-only shadow deployment

This package deploys only the Netlab acquisition, content enrichment, matching and
proposal shadow. It has no OpenCart/MySQL writer and must never be treated as a
catalog publication mechanism.

## Target

- Host: Ubuntu VM `mks123webserver` on the approved Tailscale address.
- Runtime: POSIX/Linux is required for sealed-run publication; Windows execution fails closed because Windows directory `chmod` does not provide immutability.
- Service account: existing `zenit` account; no new credential is created.
- Code: `/opt/mks123/supplier-pipeline` (read-only to the service).
- State: `/var/lib/mks123-netlab-shadow` (owned by `zenit`).
- Catalog: `/var/lib/mks123-netlab-shadow/catalog-products.csv`.

The exact host reachability and SSH authentication must be verified before any
remote command. Do not put passwords, tokens or private keys in this repository.

## What is installed

- `mks123-netlab-shadow.service`: one read-only `price + GoodsProperties` cycle.
- `mks123-netlab-shadow.timer`: every 15 minutes with overlap protection in the
  Python supervisor.
- `publication.enabled=false`, `production_writes=0`, and no publisher code.
- `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, private
  temporary directory and an explicit writable state directory.

The supervisor rejects incomplete or malformed feeds, verifies both acquisition
sidecars, seals the run, and runs the independent verifier. A failed cycle does
not replace the last verified run.

Sealing and verification operate inside the runner's exclusively reserved,
owner-controlled staging lifecycle through atomic rename. The seal proves the
captured bytes and topology at that adoption boundary; it is not an OS sandbox
and cannot revoke a writable descriptor already opened by a non-cooperating
process. Do not expose staging paths or descriptors to external writers.

## Prepare the host

These are operator commands for the approved deployment window; they are not
executed by the repository or by CI.

1. Copy/checkout the reviewed commit into `/opt/mks123/supplier-pipeline`.
2. As `zenit`, run `uv sync --frozen` in that checkout and verify
   `/opt/mks123/supplier-pipeline/.venv/bin/python` exists.
3. Copy the separately approved catalog snapshot to
   `/var/lib/mks123-netlab-shadow/catalog-products.csv`; verify its SHA-256 and
   row count from the release record. Do not copy raw supplier ZIPs into Git.
4. Run the installer from the checkout:

```bash
sudo ./deploy/install_netlab_shadow.sh
```

The default installer only installs the units and creates the intended state
folders. It does not enable or start the timer.

5. After catalog read-back and release approval, enable it explicitly:

```bash
sudo ./deploy/install_netlab_shadow.sh --enable
systemctl is-enabled mks123-netlab-shadow.timer
systemctl is-active mks123-netlab-shadow.timer
```

## Read-back and rollback

Read-only checks:

```bash
systemctl status mks123-netlab-shadow.timer --no-pager
systemctl status mks123-netlab-shadow.service --no-pager
journalctl -u mks123-netlab-shadow.service -n 100 --no-pager
```

To stop the shadow timer without touching the website catalog:

```bash
sudo systemctl disable --now mks123-netlab-shadow.timer
```

Rollback is a unit-only operation: stop/disable the timer, restore the previous
reviewed checkout and catalog snapshot, then run one manual shadow cycle and
verify its seal before re-enabling. This package does not define or perform a
production DB rollback because no production DB write is present.
