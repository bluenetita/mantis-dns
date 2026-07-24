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
#   INSTALL_DHCP=1          Build and run mantis-dhcp (native DHCPv4 server) locally
#   MANTIS_DHCP_SERVER_IP   Required with INSTALL_DHCP=1 — this host's DHCP-serving
#                           interface address (clients echo it back on renewal)
#   INSTALL_DHCP6=1         Build and run mantis-dhcp6 (native DHCPv6 server, RFC 8415) locally
#   MANTIS_DHCP6_SERVER_ID  Required with INSTALL_DHCP6=1 — a stable IPv6 address used only to
#                           derive this server's DUID (never itself handed out to a client)
#   MANTIS_SERVER_NAME=_    nginx server_name value
#
# Re-running this script (e.g. after `git pull` to a new tag) redeploys the
# code and restarts services but reuses the existing Postgres role/secrets in
# /etc/mantis-control/mantis-control.env — delete that file to regenerate.
# On a re-run it also backs up the database (pg_dump to
# /var/backups/mantis-dns/) and keeps the previous app/venv as
# app.previous/venv.previous before deploying, and checks that the new code
# boots before switching traffic to it. If the health check fails, the script
# exits with the exact commands to roll back — see lib-update.sh.
#
# Set INSTALL_FILTER=0 to skip mantis-filter (control plane + UI only, e.g.
# if this box is management-only and DNS edge nodes live elsewhere).
#
# mantis-dhcp/mantis-dhcp6 are opt-in because DHCP service inside LXC needs L2
# broadcast (v4) or multicast (v6) reachability from the container's network
# namespace that a management-only LXC typically shouldn't have.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
# shellcheck source=infra/lxc/lib-update.sh
. infra/lxc/lib-update.sh

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

: "${CORS_ALLOW_ORIGINS:?set CORS_ALLOW_ORIGINS to the public UI origin for this host, e.g. https://dns.example.com}"
REQUESTED_CORS_ALLOW_ORIGINS="$CORS_ALLOW_ORIGINS"
INSTALL_FILTER=${INSTALL_FILTER:-1}
INSTALL_DHCP=${INSTALL_DHCP:-0}
if [ "$INSTALL_DHCP" = "1" ]; then
  : "${MANTIS_DHCP_SERVER_IP:?set MANTIS_DHCP_SERVER_IP to this hosts DHCP-serving interface address (clients echo it back on every renewal)}"
fi
INSTALL_DHCP6=${INSTALL_DHCP6:-0}
if [ "$INSTALL_DHCP6" = "1" ]; then
  : "${MANTIS_DHCP6_SERVER_ID:?set MANTIS_DHCP6_SERVER_ID to a stable IPv6 address identifying this server (used only to derive its DUID -- never itself handed out to a client)}"
fi
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

load_control_env() {
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
}

ensure_env_var() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

set_env_var() {
  key="$1"
  value="$2"
  tmp_env="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    index($0, key "=") == 1 {
      print key "=" value
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' "$ENV_FILE" > "$tmp_env"
  cat "$tmp_env" > "$ENV_FILE"
  rm -f "$tmp_env"
}

ensure_firewalld_service() {
  service="$1"
  if firewall-cmd --permanent --query-service="$service" >/dev/null 2>&1; then
    echo "    firewalld service already enabled: ${service}"
  else
    firewall-cmd --add-service="$service" --permanent
  fi
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

install_local_dhcp() {
  echo "==> Building and installing mantis-dhcp (native DHCPv4 server)..."

  cargo build --release -p mantis-dhcp
  install -Dm755 target/release/mantis-dhcp /usr/bin/mantis-dhcp
  # cap_net_raw is only for SO_BINDTODEVICE (per-interface dispatch when a
  # scope sets `interface`) — a Linux quirk where that setsockopt needs
  # CAP_NET_RAW even on a plain UDP socket, not AF_PACKET/raw-socket packet
  # crafting (see services/dhcp/mantis-dhcp/src/server.rs's module docs).
  setcap cap_net_bind_service,cap_net_raw=+ep /usr/bin/mantis-dhcp

  cat > /etc/systemd/system/mantis-dhcp.service <<EOF
[Unit]
Description=Mantis-DNS native DHCPv4 server
After=network-online.target postgresql.service mantis-control.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=mantis
Group=mantis
EnvironmentFile=${ENV_FILE}
Environment=MANTIS_CTRL_URL=http://127.0.0.1:8000
Environment=MANTIS_DHCP_SERVER_IP=${MANTIS_DHCP_SERVER_IP}
ExecStart=/usr/bin/mantis-dhcp
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable mantis-dhcp
  if ! systemctl restart mantis-dhcp; then
    echo "mantis-dhcp failed to start. Service status and recent logs:"
    systemctl status mantis-dhcp --no-pager || true
    journalctl -u mantis-dhcp -n 120 --no-pager || true
    exit 1
  fi
}

install_local_dhcp6() {
  echo "==> Building and installing mantis-dhcp6 (native DHCPv6 server, RFC 8415)..."

  cargo build --release -p mantis-dhcp
  install -Dm755 target/release/mantis-dhcp6 /usr/bin/mantis-dhcp6
  # No cap_net_raw here — mantis-dhcp6 has no SO_BINDTODEVICE/per-interface
  # dispatch path (see services/dhcp/mantis-dhcp/src/server6.rs), so it only
  # needs CAP_NET_BIND_SERVICE to bind :547.
  setcap cap_net_bind_service=+ep /usr/bin/mantis-dhcp6

  cat > /etc/systemd/system/mantis-dhcp6.service <<EOF
[Unit]
Description=Mantis-DNS native DHCPv6 server (RFC 8415)
After=network-online.target postgresql.service mantis-control.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=mantis
Group=mantis
EnvironmentFile=${ENV_FILE}
Environment=MANTIS_CTRL_URL=http://127.0.0.1:8000
Environment=MANTIS_DHCP6_SERVER_ID=${MANTIS_DHCP6_SERVER_ID}
ExecStart=/usr/bin/mantis-dhcp6
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable mantis-dhcp6
  if ! systemctl restart mantis-dhcp6; then
    echo "mantis-dhcp6 failed to start. Service status and recent logs:"
    systemctl status mantis-dhcp6 --no-pager || true
    journalctl -u mantis-dhcp6 -n 120 --no-pager || true
    exit 1
  fi
}

sync_postgres_role() {
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 \
    -v role_name="$POSTGRES_USER" \
    -v role_password="$POSTGRES_PASSWORD" <<'SQL'
SET password_encryption = 'scram-sha-256';
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

configure_postgres_password_auth() {
  pg_hba="/var/lib/pgsql/data/pg_hba.conf"
  if [ ! -f "$pg_hba" ]; then
    echo "Postgres pg_hba.conf not found at $pg_hba" >&2
    return 1
  fi

  tmp_hba="$(mktemp)"
  awk '
    /^# BEGIN mantis-dns$/ { skip = 1; next }
    /^# END mantis-dns$/ { skip = 0; next }
    !skip { print }
  ' "$pg_hba" > "$tmp_hba"

  {
    echo "# BEGIN mantis-dns"
    echo "host    ${POSTGRES_DB}    ${POSTGRES_USER}    127.0.0.1/32    scram-sha-256"
    echo "host    ${POSTGRES_DB}    ${POSTGRES_USER}    ::1/128         scram-sha-256"
    echo "# END mantis-dns"
    cat "$tmp_hba"
  } > "$pg_hba"
  rm -f "$tmp_hba"

  systemctl reload postgresql
}

echo "==> Enabling CRB + EPEL (needed for some AppStream/devel packages)..."
dnf -y install dnf-plugins-core epel-release
dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null || true

echo "==> Installing packages (postgresql, python3, nodejs, nginx$( { [ "$INSTALL_FILTER" = "1" ] || [ "$INSTALL_DHCP" = "1" ] || [ "$INSTALL_DHCP6" = "1" ]; } && echo ', cargo' ))..."
dnf -y module enable nodejs:20 2>/dev/null || true
PKGS="postgresql-server postgresql-contrib python3 python3-pip nodejs nginx gettext openssl ca-certificates curl jq policycoreutils-python-utils firewalld libcap"
if [ "$INSTALL_FILTER" = "1" ] || [ "$INSTALL_DHCP" = "1" ] || [ "$INSTALL_DHCP6" = "1" ]; then
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
  IS_UPDATE=1
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
  configure_postgres_password_auth
else
  IS_UPDATE=0
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
  configure_postgres_password_auth

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
MANTIS_SIGNING_KEY_PATH=${ENV_DIR}/signing_key.bin
FEED_STORAGE_DIR=${INSTALL_DIR}/data/feed_domains
BUNDLE_STORAGE_DIR=${INSTALL_DIR}/data/bundles
EOF
  chmod 600 "$ENV_FILE"
  echo "Generated ADMIN_PASSWORD (shown once): ${ADMIN_PASSWORD}"
fi
# Must live outside $INSTALL_DIR/app: that directory is wiped and
# recreated from a fresh checkout on every re-run of this script (see
# `rm -rf "$INSTALL_DIR/app"` below), so a signing key stored there would be
# silently regenerated on every reinstall — invalidating every already-running
# filter node's cached public key (they only fetch it once at startup) until
# someone notices bundles are being rejected and restarts them by hand.
ensure_env_var MANTIS_SIGNING_KEY_PATH "${ENV_DIR}/signing_key.bin"
# Same hazard, same fix, as MANTIS_SIGNING_KEY_PATH above: the app's default
# ("feed_domains"/"bundles", relative to CWD) would otherwise resolve inside
# $INSTALL_DIR/app and be wiped by every reinstall. Unlike the signing key,
# there's no loud failure mode here — the DB's last_domain_count/
# bundle_version rows survive (separate storage), so every feed reads back
# as "ingested" while its domains are gone, and compiled bundles silently
# stop blocking anything with no error anywhere. $INSTALL_DIR/data is a
# sibling of app/venv, never touched by the `rm -rf` below.
ensure_env_var FEED_STORAGE_DIR "${INSTALL_DIR}/data/feed_domains"
ensure_env_var BUNDLE_STORAGE_DIR "${INSTALL_DIR}/data/bundles"
chmod 600 "$ENV_FILE"

load_control_env
parse_database_url

id -u mantis >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /sbin/nologin mantis

# The mantis-control.env file itself stays root:root 0600 (systemd reads
# EnvironmentFile as root before dropping privileges — the app never needs to
# read it directly), but the app *does* need to create/read
# MANTIS_SIGNING_KEY_PATH (signing_key.bin) in this directory at runtime as
# the `mantis` user.
chown mantis:mantis "$ENV_DIR"
chmod 750 "$ENV_DIR"

# mantis-dhcp (User=mantis in its unit) needs that user to exist first —
# unlike Kea's RPM, which created its own system user, there's no package
# doing that for us here.
if [ "$INSTALL_DHCP" = "1" ]; then
  install_local_dhcp
else
  echo "==> INSTALL_DHCP=0 — skipping mantis-dhcp."
fi

if [ "$INSTALL_DHCP6" = "1" ]; then
  install_local_dhcp6
else
  echo "==> INSTALL_DHCP6=0 — skipping mantis-dhcp6."
fi

if [ "$IS_UPDATE" = "1" ]; then
  backup_database "${DATABASE_URL:-}"
fi

echo "==> Deploying control plane..."
mkdir -p "$INSTALL_DIR"
# Sibling of app/venv, deliberately outside the `rm -rf` below — holds
# FEED_STORAGE_DIR/BUNDLE_STORAGE_DIR, which must survive reinstalls (see
# the ensure_env_var comment above).
mkdir -p "$INSTALL_DIR/data/feed_domains" "$INSTALL_DIR/data/bundles"
rotate_code_dirs "$INSTALL_DIR"
cp -r services/control "$INSTALL_DIR/app"
python3 -m venv "$INSTALL_DIR/venv"
# Installed in place (not editable) but the source tree stays at
# $INSTALL_DIR/app — same layout as the prod Docker image, which relies on
# migrations/ and alembic.ini being siblings of mantis_control/ at the
# process's working directory (see main.py's _run_migrations).
"$INSTALL_DIR/venv/bin/pip" install --no-cache-dir --disable-pip-version-check "$INSTALL_DIR/app"
chown -R mantis:mantis "$INSTALL_DIR"

echo "==> Installing systemd unit for control plane..."
cp infra/lxc/mantis-control.service /etc/systemd/system/mantis-control.service
systemctl daemon-reload
systemctl enable mantis-control
systemctl stop mantis-control >/dev/null 2>&1 || true

echo "==> Checking control plane startup..."
if ! check_control_startup "$INSTALL_DIR"; then
  echo "mantis-control startup check failed; see the Python traceback above." >&2
  if [ "$IS_UPDATE" = "1" ]; then
    print_rollback_instructions "$INSTALL_DIR" mantis-control
  fi
  exit 1
fi

if ! systemctl restart mantis-control || ! wait_for_control "$INSTALL_DIR"; then
  echo "mantis-control failed to become healthy. Service status and recent logs:"
  systemctl status mantis-control --no-pager || true
  journalctl -u mantis-control -n 120 --no-pager || true
  if [ "$IS_UPDATE" = "1" ]; then
    print_rollback_instructions "$INSTALL_DIR" mantis-control
  fi
  exit 1
fi

if [ "$IS_UPDATE" = "1" ]; then
  discard_previous_generation "$INSTALL_DIR"
fi

echo "==> Building UI static assets (requires Node from dnf above)..."
( cd apps/ui && npm ci --legacy-peer-deps && VITE_API_URL= npm run build )
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
  ensure_firewalld_service http
  if [ "$ENABLE_HTTPS" = "1" ]; then
    ensure_firewalld_service https
  fi
  if [ "$INSTALL_DHCP" = "1" ]; then
    ensure_firewalld_service dhcp || true
  fi
  if [ "$INSTALL_DHCP6" = "1" ]; then
    ensure_firewalld_service dhcpv6 || true
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
if [ "$INSTALL_DHCP" = "1" ]; then
  echo "mantis-dhcp listening on :67 (DHCPv4), serving MANTIS_DHCP_SERVER_IP=${MANTIS_DHCP_SERVER_IP}."
else
  echo "mantis-dhcp not installed here — run it via docker-compose.prod.yml or its own host, pointed at this Postgres directly."
fi
if [ "$INSTALL_DHCP6" = "1" ]; then
  echo "mantis-dhcp6 listening on :547 (DHCPv6), serving MANTIS_DHCP6_SERVER_ID=${MANTIS_DHCP6_SERVER_ID}."
else
  echo "mantis-dhcp6 not installed here — run it via docker-compose.prod.yml or its own host, pointed at this Postgres directly."
fi
echo "Log in with ADMIN_EMAIL/ADMIN_PASSWORD from ${ENV_FILE}, then rotate the password."