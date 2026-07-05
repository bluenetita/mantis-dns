#!/usr/bin/env bash

# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Native (no Docker) install of the Mantis-DNS management plane — Postgres +
# control plane + UI — onto a single Debian 12 host. Written for a Proxmox
# LXC container (plain unprivileged container, no nesting/keyctl features
# required, unlike the Docker Compose path in docs/deploy-lxc.md), but works
# on any Debian 12 host/VM.
#
# Run as root from inside a cloned mantis-dns checkout, e.g.:
#
#   git clone <repo> /opt/mantis-dns-src && cd /opt/mantis-dns-src
#   CORS_ALLOW_ORIGINS=https://dns.example.com ./infra/lxc/install.sh
#
# Re-running this script (e.g. after `git pull` to a new tag) redeploys the
# code and restarts services but reuses the existing Postgres role/secrets in
# /etc/mantis-control/mantis-control.env — delete that file to regenerate.
#
# NOT installed here: mantis-filter and Kea. Filter nodes belong at the
# network edge (often a separate LXC/site) — install the standalone .deb from
# a GitHub release instead (see packaging/filter/ and docs/deploy-lxc.md).
# Kea needs NET_ADMIN + L2 broadcast/relay reachability that a management-
# plane LXC shouldn't have — run it via docker-compose.prod.yml or its own
# host, pointed at this host's control API.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

: "${CORS_ALLOW_ORIGINS:?set CORS_ALLOW_ORIGINS to the public UI origin for this host, e.g. https://dns.example.com}"

INSTALL_DIR=/opt/mantis-dns
UI_ROOT=/var/www/mantis-dns
ENV_DIR=/etc/mantis-control
ENV_FILE="$ENV_DIR/mantis-control.env"

ensure_env_var() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

echo "==> Installing packages (postgresql, python3-venv, nodejs, nginx)..."
apt-get update
apt-get install -y postgresql python3-venv python3-pip nodejs npm nginx gettext-base openssl ca-certificates

mkdir -p "$ENV_DIR"

if [ -f "$ENV_FILE" ]; then
  echo "==> $ENV_FILE exists — reusing secrets/DB credentials, redeploying code only."
else
  echo "==> First install — provisioning Postgres role and generating secrets..."
  POSTGRES_DB=mantis
  POSTGRES_USER=mantis
  POSTGRES_PASSWORD=$(openssl rand -hex 16)
  MANTIS_INTERNAL_TOKEN=$(openssl rand -hex 32)
  MANTIS_SERVICE_TOKEN=$(openssl rand -hex 32)
  MANTIS_JWT_SECRET=$(openssl rand -hex 32)
  MANTIS_WEBHOOK_SECRET_KEY=$(openssl rand -hex 32)
  ADMIN_EMAIL=${ADMIN_EMAIL:-admin@mantis.local}
  ADMIN_PASSWORD=$(openssl rand -hex 16)

  sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'" | grep -q 1 \
    || sudo -u postgres psql -c "CREATE ROLE ${POSTGRES_USER} LOGIN PASSWORD '${POSTGRES_PASSWORD}';"
  sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" | grep -q 1 \
    || sudo -u postgres psql -c "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"

  cat > "$ENV_FILE" <<EOF
MANTIS_ENV=production
DATABASE_URL=postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}
CORS_ALLOW_ORIGINS=${CORS_ALLOW_ORIGINS}
MANTIS_INTERNAL_TOKEN=${MANTIS_INTERNAL_TOKEN}
MANTIS_SERVICE_TOKEN=${MANTIS_SERVICE_TOKEN}
MANTIS_JWT_SECRET=${MANTIS_JWT_SECRET}
MANTIS_WEBHOOK_SECRET_KEY=${MANTIS_WEBHOOK_SECRET_KEY}
MANTIS_FILTER_NODE_IP=${MANTIS_FILTER_NODE_IP:-}
KEA_CTRL_URL=${KEA_CTRL_URL:-http://127.0.0.1:8004/}
KEA4_CTRL_URL=${KEA4_CTRL_URL:-http://127.0.0.1:8004/}
KEA6_CTRL_URL=${KEA6_CTRL_URL:-http://127.0.0.1:8006/}
KEA_HOOKS_DIR=${KEA_HOOKS_DIR:-/usr/lib/kea/hooks}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chmod 600 "$ENV_FILE"
  echo "Generated ADMIN_PASSWORD (shown once): ${ADMIN_PASSWORD}"
fi
ensure_env_var KEA_CTRL_URL "${KEA_CTRL_URL:-http://127.0.0.1:8004/}"
ensure_env_var KEA4_CTRL_URL "${KEA4_CTRL_URL:-http://127.0.0.1:8004/}"
ensure_env_var KEA6_CTRL_URL "${KEA6_CTRL_URL:-http://127.0.0.1:8006/}"
ensure_env_var KEA_HOOKS_DIR "${KEA_HOOKS_DIR:-/usr/lib/kea/hooks}"
chmod 600 "$ENV_FILE"

id -u mantis >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin mantis

echo "==> Deploying control plane..."
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/app" "$INSTALL_DIR/venv"
cp -r services/control "$INSTALL_DIR/app"
python3 -m venv "$INSTALL_DIR/venv"
# Installed in place (not editable) but the source tree stays at
# $INSTALL_DIR/app — same layout as the prod Docker image, which relies on
# migrations/ and alembic.ini being siblings of mantis_control/ at the
# process's working directory (see main.py's _run_migrations).
"$INSTALL_DIR/venv/bin/pip" install --no-cache-dir "$INSTALL_DIR/app"
chown -R mantis:mantis "$INSTALL_DIR"

echo "==> Installing systemd unit..."
cp infra/lxc/mantis-control.service /etc/systemd/system/mantis-control.service
systemctl daemon-reload
systemctl enable --now mantis-control
systemctl restart mantis-control

echo "==> Building UI static assets (requires Node from apt above)..."
( cd apps/ui && npm ci --legacy-peer-deps && VITE_API_URL= npm run build )
rm -rf "$UI_ROOT"
mkdir -p "$UI_ROOT"
cp -r apps/ui/dist/. "$UI_ROOT/"

echo "==> Configuring nginx..."
CONTROL_UPSTREAM=127.0.0.1:8000 envsubst '${CONTROL_UPSTREAM}' \
  < apps/ui/nginx.conf.template > /etc/nginx/sites-available/mantis-dns
# The container image's template hardcodes /usr/share/nginx/html as root;
# point it at the native build output instead.
sed -i "s#root /usr/share/nginx/html;#root ${UI_ROOT};#" /etc/nginx/sites-available/mantis-dns
ln -sf /etc/nginx/sites-available/mantis-dns /etc/nginx/sites-enabled/mantis-dns
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx || systemctl restart nginx

echo
echo "Done. UI: http://$(hostname -I | awk '{print $1}')/  API: http://127.0.0.1:8000"
echo "Log in with ADMIN_EMAIL/ADMIN_PASSWORD from ${ENV_FILE}, then rotate the password."
