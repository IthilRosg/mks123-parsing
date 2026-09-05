#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/mks123/supplier-pipeline}"
STATE_ROOT="${STATE_ROOT:-/var/lib/mks123-netlab-shadow}"
SERVICE_USER="${SERVICE_USER:-zenit}"
SERVICE_NAME="mks123-netlab-shadow"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' 'run this installer with sudo on the target host' >&2
  exit 1
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  printf 'service user does not exist: %s\n' "$SERVICE_USER" >&2
  exit 1
fi

for required in \
  "$REPO_ROOT/scripts/run_netlab_shadow.py" \
  "$REPO_ROOT/config/netlab.yaml" \
  "$REPO_ROOT/deploy/mks123-netlab-shadow.service" \
  "$REPO_ROOT/deploy/mks123-netlab-shadow.timer"; do
  if [ ! -f "$required" ]; then
    printf 'missing deployment file: %s\n' "$required" >&2
    exit 1
  fi
done

install -d -o root -g root -m 0755 "$INSTALL_ROOT"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_ROOT"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_ROOT/raw" "$STATE_ROOT/runs"

# The checkout and catalog are deliberately not copied implicitly. The operator
# must place a reviewed checkout at INSTALL_ROOT and a reviewed catalog at
# STATE_ROOT/catalog-products.csv before enabling the timer.
if [ "$(realpath "$REPO_ROOT")" != "$(realpath "$INSTALL_ROOT" 2>/dev/null || true)" ]; then
  printf '%s\n' 'copy or checkout the reviewed repository into INSTALL_ROOT before running this installer' >&2
  exit 1
fi

if [ ! -x "$INSTALL_ROOT/.venv/bin/python" ]; then
  printf '%s\n' 'project venv is missing; run uv sync --frozen as the service user first' >&2
  exit 1
fi

chown -R root:root "$INSTALL_ROOT"
chmod -R u=rwX,go=rX "$INSTALL_ROOT"
install -o root -g root -m 0644 "$REPO_ROOT/deploy/mks123-netlab-shadow.service" \
  "/etc/systemd/system/${SERVICE_NAME}.service"
install -o root -g root -m 0644 "$REPO_ROOT/deploy/mks123-netlab-shadow.timer" \
  "/etc/systemd/system/${SERVICE_NAME}.timer"
systemctl daemon-reload

if [ "${1:-}" = "--enable" ]; then
  if [ ! -s "$STATE_ROOT/catalog-products.csv" ]; then
    printf '%s\n' 'catalog file is missing or empty; refusing to enable timer' >&2
    exit 1
  fi
  chown "$SERVICE_USER:$SERVICE_USER" "$STATE_ROOT/catalog-products.csv"
  chmod 0640 "$STATE_ROOT/catalog-products.csv"
  systemctl enable --now "${SERVICE_NAME}.timer"
else
  printf '%s\n' 'Installed units but did not enable or start the timer.'
  printf 'Review the catalog, then run: sudo %s --enable\n' "$0"
fi
