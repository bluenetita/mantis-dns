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

# Native (no Docker) full-stack install onto a single Rocky Linux 10 host —
# Postgres + control plane + UI + mantis-filter (edge DNS resolver), all on
# one box. Written for a plain unprivileged Proxmox LXC container (no
# nesting/keyctl needed) but works on any Rocky 10 host/VM. Rocky/dnf sibling
# of install.sh (Debian 12); see docs/deploy-lxc.md for the full set of
# deploy options.
#
# Run as root from inside a cloned mantis-dns checkout, e.g.:
#
#   dnf -y install git
#   git clone <repo> /opt/mantis-dns-src && cd /opt/mantis-dns-src
#   CORS_ALLOW_ORIGINS=https://dns.example.com ./infra/lxc/install-rocky.sh
#
# Useful options:
#   ENABLE_HTTPS=1          Generate/use a local self-signed cert and listen on 443
#   INSTALL_FILTER=0        Skip mantis-filter
#   MANTIS_SERVER_NAME=_    nginx server_name value
#
# Re-running this script (e.g. after `git pull` to a new tag) redeploys the
# code and restarts services but reuses the existing Postgres role/secrets in
# /etc/mantis-control/mantis-control.env — delete that file to regenerate.
#
# Set INSTALL_FILTER=0 to skip mantis-filter (control plane + UI only, e.g.
# if this box is management-only and DNS edge nodes live elsewhere).
#
# NOT installed here: Kea. It needs NET_ADMIN + L2 broadcast/relay
# reachability that a single-purpose LXC shouldn't have — run it via
# docker-compose.prod.yml or its own host, pointed at this host's control API.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

: "${CORS_ALLOW_ORIGINS:?set CORS_ALLOW_ORIGINS to the public UI origin for this host, e.g. https://dns.example.com}"
REQUESTED_CORS_ALLOW_ORIGINS="$CORS_ALLOW_ORIGINS"
INSTALL_FILTER=${INSTALL_FILTER:-1}
MANTIS_SERVER_NAME=${MANTIS_SERVER_NAME:-_}
TLS_CERT_FILE=${TLS_CERT_FILE:-/etc/pki/tls/certs/mantis-dns.crt}
TLS_KEY_FILE=${TLS_KEY_FILE:-/etc/pki/tls/private/mantis-dns.key}

if [ -z "${ENABLE_HTTPS:-}" ]; then
  case "$REQUESTED_CORS_ALLOW_ORIGINS" in
    https://*) ENABLE_HTTPS=1 ;;
    *) ENABLE_HTTPS=0 ;;
  esac
fi

INSTALL_DIR=/opt/mantis-dns
UI_ROOT=/var/www/mantis-dns
ENV_DIR=/etc/mantis-control
ENV_FILE="$ENV_DIR/mantis-control.env"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

wait_for_control() {
  for _ in $(seq 1 30); do
    if "$INSTALL_DIR/venv/bin/python" -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2).read()' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

parse_database_url() {
  eval "$(
    DATABASE_URL="$DATABASE_URL" python3 - <<'PY'
from urllib.parse import urlparse
import os
import shlex

url = urlparse(os.environ["DATABASE_URL"])
print(f"POSTGRES_USER={shlex.quote(url.username or '')}")
print(f"POSTGRES_PASSWORD={shlex.quote(url.password or '')}")
print(f"POSTGRES_DB={shlex.quote((url.path or '/').lstrip('/'))}")
PY
  )"
}

sync_postgres_role() {
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
    -v role_name="$POSTGRES_USER" \
    -v role_password="$POSTGRES_PASSWORD" <<'SQL'
SELECT CASE
  WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role_name')
    THEN format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'role_name', :'role_password')
  ELSE format('CREATE ROLE %I LOGIN PASSWORD %L', :'role_name', :'role_password')
END
\gexec
SQL

  if ! runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" | grep -q 1; then
    runuser -u postgres -- createdb -O "$POSTGRES_USER" "$POSTGRES_DB"
  fi
}

echo "==> Enabling CRB + EPEL (needed for some AppStream/devel packages)..."
dnf -y install dnf-plugins-core epel-release
dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null || true

echo "==> Installing packages (postgresql, python3, nodejs, nginx$( [ "$INSTALL_FILTER" = "1" ] && echo ', cargo' ))..."
dnf -y module enable nodejs:20 2>/dev/null || true
PKGS="postgresql-server postgresql-contrib python3 python3-pip nodejs nginx gettext openssl ca-certificates policycoreutils-python-utils firewalld"
if [ "$INSTALL_FILTER" = "1" ]; then
  PKGS="$PKGS cargo"
fi
dnf -y install $PKGS

echo "==> Initializing Postgres (Rocky needs an explicit initdb, unlike Debian's package)..."
if [ ! -s /var/lib/pgsql/data/PG_VERSION ]; then
  postgresql-setup --initdb
fi
systemctl enable --now postgresql

mkdir -p "$ENV_DIR"

if [ -f "$ENV_FILE" ]; then
  echo "==> $ENV_FILE exists — reusing secrets/DB credentials, redeploying code only."
  # shellcheck disable=SC1090
  source "$ENV_FILE"

  if [ "${CORS_ALLOW_ORIGINS:-}" != "$REQUESTED_CORS_ALLOW_ORIGINS" ]; then
    echo "==> Updating CORS_ALLOW_ORIGINS in $ENV_FILE."
    tmp_env="$(mktemp)"
    awk -v value="$REQUESTED_CORS_ALLOW_ORIGINS" '
      BEGIN { updated = 0 }
      /^CORS_ALLOW_ORIGINS=/ {
        print "CORS_ALLOW_ORIGINS=" value
        updated = 1
        next
      }
      { print }
      END {
        if (!updated) {
          print "CORS_ALLOW_ORIGINS=" value
        }
      }
    ' "$ENV_FILE" > "$tmp_env"
    cat "$tmp_env" > "$ENV_FILE"
    rm -f "$tmp_env"
    chmod 600 "$ENV_FILE"
    CORS_ALLOW_ORIGINS="$REQUESTED_CORS_ALLOW_ORIGINS"
  fi

  parse_database_url
  sync_postgres_role
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

  sync_postgres_role

  cat > "$ENV_FILE" <<EOF
MANTIS_ENV=production
DATABASE_URL=postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}
CORS_ALLOW_ORIGINS=${CORS_ALLOW_ORIGINS}
MANTIS_INTERNAL_TOKEN=${MANTIS_INTERNAL_TOKEN}
MANTIS_SERVICE_TOKEN=${MANTIS_SERVICE_TOKEN}
MANTIS_JWT_SECRET=${MANTIS_JWT_SECRET}
MANTIS_WEBHOOK_SECRET_KEY=${MANTIS_WEBHOOK_SECRET_KEY}
MANTIS_FILTER_NODE_IP=${MANTIS_FILTER_NODE_IP:-}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chmod 600 "$ENV_FILE"
  echo "Generated ADMIN_PASSWORD (shown once): ${ADMIN_PASSWORD}"
fi

id -u mantis >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /sbin/nologin mantis

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

echo "==> Installing systemd unit for control plane..."
cp infra/lxc/mantis-control.service /etc/systemd/system/mantis-control.service
systemctl daemon-reload
systemctl enable mantis-control

if ! systemctl restart mantis-control || ! wait_for_control; then
  echo "mantis-control failed to become healthy. Service status and recent logs:"
  systemctl status mantis-control --no-pager || true
  journalctl -u mantis-control -n 120 --no-pager || true
  exit 1
fi

echo "==> Building UI static assets (requires Node from dnf above)..."
( cd apps/ui && npm ci --legacy-peer-deps && VITE_API_URL=/api/v1 npm run build )
rm -rf "$UI_ROOT"
mkdir -p "$UI_ROOT"
cp -r apps/ui/dist/. "$UI_ROOT/"

echo "==> Configuring nginx..."
if [ "$ENABLE_HTTPS" = "1" ]; then
  echo "    HTTPS enabled; configuring nginx for port 443."
  mkdir -p "$(dirname "$TLS_CERT_FILE")" "$(dirname "$TLS_KEY_FILE")"

  if [ ! -s "$TLS_CERT_FILE" ] || [ ! -s "$TLS_KEY_FILE" ]; then
    CERT_CN="$MANTIS_SERVER_NAME"
    if [ "$CERT_CN" = "_" ]; then
      CERT_CN="${HOST_IP:-mantis-dns.local}"
    fi

    SAN_ENTRIES="IP:${HOST_IP:-127.0.0.1}"
    if [ "$MANTIS_SERVER_NAME" != "_" ]; then
      SAN_ENTRIES="${SAN_ENTRIES},DNS:${MANTIS_SERVER_NAME}"
    fi

    openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
      -keyout "$TLS_KEY_FILE" \
      -out "$TLS_CERT_FILE" \
      -subj "/CN=${CERT_CN}" \
      -addext "subjectAltName=${SAN_ENTRIES}"
    chmod 600 "$TLS_KEY_FILE"
  else
    echo "    existing TLS certificate/key found; leaving them untouched."
  fi

  CONTROL_UPSTREAM=127.0.0.1:8000 \
  UI_ROOT="$UI_ROOT" \
  MANTIS_SERVER_NAME="$MANTIS_SERVER_NAME" \
  TLS_CERT_FILE="$TLS_CERT_FILE" \
  TLS_KEY_FILE="$TLS_KEY_FILE" \
    envsubst '${CONTROL_UPSTREAM} ${UI_ROOT} ${MANTIS_SERVER_NAME} ${TLS_CERT_FILE} ${TLS_KEY_FILE}' \
    < apps/ui/nginx.https.conf.template > /etc/nginx/conf.d/mantis-dns.conf
else
  CONTROL_UPSTREAM=127.0.0.1:8000 envsubst '${CONTROL_UPSTREAM}' \
    < apps/ui/nginx.conf.template > /etc/nginx/conf.d/mantis-dns.conf
  # The upstream template hardcodes /usr/share/nginx/html as root; point it at
  # the native build output instead.
  sed -i "s#root /usr/share/nginx/html;#root ${UI_ROOT};#" /etc/nginx/conf.d/mantis-dns.conf
  sed -i "s#server_name _;#server_name ${MANTIS_SERVER_NAME};#" /etc/nginx/conf.d/mantis-dns.conf
fi
rm -f /etc/nginx/conf.d/default.conf

echo "==> SELinux + firewalld (Rocky ships both enforcing/active by default; Debian's install.sh needs neither)..."
# Best-effort: plenty of unprivileged LXC containers report SELinux as
# enforcing (inherited from the host) but can't write the policy store
# themselves ("Cannot set persistent booleans without managed policy"), and
# some minimal templates don't ship firewalld at all. Neither should abort
# the rest of the install — if setsebool/firewalld aren't usable here, nginx
# still needs to come up.
if command -v getenforce >/dev/null && [ "$(getenforce)" != "Disabled" ]; then
  setsebool -P httpd_can_network_connect 1 2>/dev/null \
    || setsebool httpd_can_network_connect 1 2>/dev/null \
    || echo "    could not set httpd_can_network_connect — if nginx's proxy_pass to the control plane gets denied, check 'ausearch -m avc -ts recent'"
  restorecon -Rv "$UI_ROOT" >/dev/null 2>&1 || true
fi
nginx -t
systemctl enable --now nginx
systemctl reload nginx || systemctl restart nginx
if command -v firewall-cmd >/dev/null; then
  systemctl enable --now firewalld
  firewall-cmd --add-service=http --permanent
  if [ "$ENABLE_HTTPS" = "1" ]; then
    firewall-cmd --add-service=https --permanent
  fi
  firewall-cmd --reload
else
  if [ "$ENABLE_HTTPS" = "1" ]; then
    echo "    firewalld not installed — skipping (open ports 80 and 443 some other way if this host has its own firewall)"
  else
    echo "    firewalld not installed — skipping (open port 80 some other way if this host has its own firewall)"
  fi
fi

if [ "$INSTALL_FILTER" = "1" ]; then
  echo "==> Building mantis-filter (Rust, release profile — this takes a few minutes)..."
  # Reuses cargo's default registry cache across re-runs; fine for a single
  # native host (unlike the Docker build, no cross-compile/musl target needed
  # since we're running natively on the same glibc as this host).
  cargo build --release -p mantis-filter

  echo "==> Installing mantis-filter..."
  install -Dm755 target/release/mantis-filter /usr/bin/mantis-filter
  install -Dm644 packaging/filter/mantis-filter.service /etc/systemd/system/mantis-filter.service
  if [ ! -f /etc/mantis-filter/mantis-filter.env ]; then
    install -Dm600 packaging/filter/mantis-filter.env /etc/mantis-filter/mantis-filter.env
    # Point the filter at this same host's control plane and matching
    # service token by default, since it's a full-stack single-box install —
    # override CONTROL_URL in the env file if the edge node should instead
    # report to a different/remote control plane.
    sed -i "s#^CONTROL_URL=.*#CONTROL_URL=http://127.0.0.1:8000#" /etc/mantis-filter/mantis-filter.env
    sed -i "s#^MANTIS_SERVICE_TOKEN=.*#MANTIS_SERVICE_TOKEN=${MANTIS_SERVICE_TOKEN}#" /etc/mantis-filter/mantis-filter.env
  else
    echo "    /etc/mantis-filter/mantis-filter.env exists — leaving it untouched."
  fi
  systemctl daemon-reload
  systemctl enable --now mantis-filter
  systemctl restart mantis-filter
else
  echo "==> INSTALL_FILTER=0 — skipping mantis-filter."
fi

echo
if [ "$ENABLE_HTTPS" = "1" ]; then
  echo "Done. UI: https://${HOST_IP:-127.0.0.1}/  API: http://127.0.0.1:8000"
  echo "The generated certificate is self-signed; trust ${TLS_CERT_FILE} on clients or replace it with a CA-issued certificate."
else
  echo "Done. UI: http://${HOST_IP:-127.0.0.1}/  API: http://127.0.0.1:8000"
fi
if [ "$INSTALL_FILTER" = "1" ]; then
  echo "DNS filter listening on :53 (mantis-filter) — point clients/DHCP at this host's IP."
fi
echo "Log in with ADMIN_EMAIL/ADMIN_PASSWORD from ${ENV_FILE}, then rotate the password."
