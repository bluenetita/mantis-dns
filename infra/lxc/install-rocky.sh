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
#   INSTALL_KEA=1           Install and run ISC Kea DHCP4/DHCP6 locally
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
# Kea is opt-in because DHCP service inside LXC needs NET_ADMIN/NET_RAW and
# L2 broadcast/relay reachability from the container's network namespace.
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
REQUESTED_KEA_CTRL_URL=${KEA_CTRL_URL:-}
REQUESTED_KEA4_CTRL_URL=${KEA4_CTRL_URL:-}
REQUESTED_KEA6_CTRL_URL=${KEA6_CTRL_URL:-}
REQUESTED_KEA_HOOKS_DIR=${KEA_HOOKS_DIR:-}
INSTALL_FILTER=${INSTALL_FILTER:-1}
INSTALL_KEA=${INSTALL_KEA:-0}
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

wait_for_tcp() {
  host="$1"
  port="$2"
  for _ in $(seq 1 20); do
    if python3 - "$host" "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1)
sock.close()
PY
    then
      return 0
    fi
    sleep 1
  done

  return 1
}

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

env_value() {
  key="$1"
  grep -E "^${key}=" "$ENV_FILE" | tail -1 | cut -d= -f2-
}

ensure_firewalld_service() {
  service="$1"
  if firewall-cmd --permanent --query-service="$service" >/dev/null 2>&1; then
    echo "    firewalld service already enabled: ${service}"
  else
    firewall-cmd --add-service="$service" --permanent
  fi
}

refresh_kea_env_var() {
  key="$1"
  requested="$2"
  default="$3"
  current="$(env_value "$key")"
  if [ -n "$requested" ]; then
    set_env_var "$key" "$requested"
  elif [ -z "$current" ] || [ "$current" = "http://kea:8080/" ] || [ "$current" = "http://kea:8004/" ] || [ "$current" = "http://kea:8006/" ] || [ "$current" = "http://127.0.0.1:8004/" ] || [ "$current" = "http://127.0.0.1:8006/" ]; then
    set_env_var "$key" "$default"
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

render_kea_config() {
  src="$1"
  dest="$2"
  hooks_json="$3"

  sed \
    -e "s#__PG_DB__#${POSTGRES_DB}#g" \
    -e "s#__PG_HOST__#127.0.0.1#g" \
    -e "s#__PG_PORT__#5432#g" \
    -e "s#__PG_USER__#${POSTGRES_USER}#g" \
    -e "s#__PG_PASS__#${POSTGRES_PASSWORD}#g" \
    -e "s#__KEA_CTRL_BIND_ADDRESS__#${KEA_CTRL_BIND_ADDRESS:-127.0.0.1}#g" \
    -e "s#__KEA4_CTRL_PORT__#${KEA4_CTRL_PORT:-8004}#g" \
    -e "s#__KEA6_CTRL_PORT__#${KEA6_CTRL_PORT:-8006}#g" \
    -e "s#__HOOKS_LIBRARIES__#${hooks_json}#g" \
    "$src" > "$dest"
}

install_local_kea() {
  echo "==> Installing local ISC Kea DHCP services..."

  if ! command -v kea-dhcp4 >/dev/null || ! command -v kea-admin >/dev/null; then
    # Cloudsmith's bootstrap script content is generated per-distro/version
    # server-side, so there's no fixed release artifact to pin a checksum
    # against — but piping curl straight into bash still means a failed or
    # truncated download (or a MITM'd/downgraded connection) executes
    # whatever bytes happen to arrive, silently, as root. Downloading to a
    # file first lets us fail loudly on a bad/incomplete response instead,
    # and --proto/--tlsv1.2 rule out a protocol downgrade.
    kea_setup_script="$(mktemp)"
    trap 'rm -f "$kea_setup_script"' RETURN
    if ! curl -fsSL --proto '=https' --tlsv1.2 \
        'https://dl.cloudsmith.io/public/isc/kea-3-0/setup.rpm.sh' \
        -o "$kea_setup_script"; then
      echo "Failed to download the Kea repo bootstrap script from Cloudsmith." >&2
      exit 1
    fi
    if [ ! -s "$kea_setup_script" ] || ! head -c2 "$kea_setup_script" | grep -q '^#!'; then
      echo "Kea repo bootstrap script is empty or doesn't look like a shell script; aborting." >&2
      exit 1
    fi
    bash "$kea_setup_script"
    dnf -y install isc-kea-dhcp4 isc-kea-dhcp6 isc-kea-admin isc-kea-hooks isc-kea-pgsql
  fi

  kea_dhcp4_bin="$(command -v kea-dhcp4)"
  kea_dhcp6_bin="$(command -v kea-dhcp6)"
  lease_cmds_lib="$(find /usr/lib64 /usr/lib -name libdhcp_lease_cmds.so -print -quit 2>/dev/null || true)"
  run_script_lib="$(find /usr/lib64 /usr/lib -name libdhcp_run_script.so -print -quit 2>/dev/null || true)"
  pgsql_lib="$(find /usr/lib64 /usr/lib -name libdhcp_pgsql.so -print -quit 2>/dev/null || true)"
  subnet_cmds_lib="$(find /usr/lib64 /usr/lib -name libdhcp_subnet_cmds.so -print -quit 2>/dev/null || true)"

  if [ -z "$lease_cmds_lib" ]; then
    echo "Kea lease_cmds hook not found after installing isc-kea-hooks." >&2
    exit 1
  fi
  if [ -z "$pgsql_lib" ]; then
    echo "Kea PostgreSQL lease-backend hook (libdhcp_pgsql.so) not found after installing isc-kea-pgsql." >&2
    exit 1
  fi
  # The control plane pushes scope changes with subnet4-add/-update/-del
  # (see kea_config.py) rather than config-set, so this hook is mandatory,
  # not optional.
  if [ -z "$subnet_cmds_lib" ]; then
    echo "Kea subnet_cmds hook (libdhcp_subnet_cmds.so) not found after installing isc-kea-hooks." >&2
    exit 1
  fi

  hooks_dir="$(dirname "$lease_cmds_lib")"
  mkdir -p /usr/lib/kea /etc/kea
  ln -sfn "$hooks_dir" /usr/lib/kea/hooks

  # Kea 3.x's run_script hook only allows scripts under /usr/share/kea/scripts
  # (a guarded-path check) — /usr/local/bin is rejected at load time.
  ddns_bridge_dest="/usr/share/kea/scripts/mantis-ddns-bridge.sh"

  hooks4_json='[{"library": "'"$pgsql_lib"'"}, {"library": "'"$lease_cmds_lib"'"}, {"library": "'"$subnet_cmds_lib"'"}'
  if [ -n "$run_script_lib" ] && [ -f services/kea/mantis-ddns-bridge.sh ]; then
    install -Dm755 services/kea/mantis-ddns-bridge.sh "$ddns_bridge_dest"
    hooks4_json="${hooks4_json}, {\"library\": \"${run_script_lib}\", \"parameters\": {\"name\": \"${ddns_bridge_dest}\", \"sync\": false}}"
  fi
  hooks4_json="${hooks4_json}]"
  hooks6_json='[{"library": "'"$pgsql_lib"'"}, {"library": "'"$subnet_cmds_lib"'"}]'

  render_kea_config services/kea/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf "$hooks4_json"
  render_kea_config services/kea/kea-dhcp6.conf /etc/kea/kea-dhcp6.conf "$hooks6_json"
  chmod 640 /etc/kea/kea-dhcp4.conf /etc/kea/kea-dhcp6.conf

  schema_file="/usr/share/kea/scripts/pgsql/dhcpdb_create.pgsql"
  if [ ! -f "$schema_file" ]; then
    echo "Kea PostgreSQL schema not found at $schema_file." >&2
    exit 1
  fi

  if ! PGPASSWORD="$POSTGRES_PASSWORD" psql \
      -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
      -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='schema_version'" | grep -q 1; then
    PGPASSWORD="$POSTGRES_PASSWORD" psql \
      -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
      -v ON_ERROR_STOP=1 -f "$schema_file"
  else
    echo "Kea DB schema already present — running kea-admin db-upgrade to catch it up..."
    kea-admin db-upgrade pgsql \
      -h 127.0.0.1 -u "$POSTGRES_USER" -p "$POSTGRES_PASSWORD" -n "$POSTGRES_DB"
  fi

  cat > /etc/systemd/system/mantis-kea-dhcp4.service <<EOF
[Unit]
Description=Mantis-DNS Kea DHCPv4 daemon
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=kea
Group=kea
EnvironmentFile=${ENV_FILE}
Environment=MANTIS_CTRL_URL=http://127.0.0.1:8000
ExecStart=${kea_dhcp4_bin} -c /etc/kea/kea-dhcp4.conf
Restart=on-failure
RestartSec=2
RuntimeDirectory=kea
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/mantis-kea-dhcp6.service <<EOF
[Unit]
Description=Mantis-DNS Kea DHCPv6 daemon
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=kea
Group=kea
EnvironmentFile=${ENV_FILE}
Environment=MANTIS_CTRL_URL=http://127.0.0.1:8000
ExecStart=${kea_dhcp6_bin} -c /etc/kea/kea-dhcp6.conf
Restart=on-failure
RestartSec=2
RuntimeDirectory=kea
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

  set_env_var KEA_CTRL_URL "http://127.0.0.1:${KEA4_CTRL_PORT:-8004}/"
  set_env_var KEA4_CTRL_URL "http://127.0.0.1:${KEA4_CTRL_PORT:-8004}/"
  set_env_var KEA6_CTRL_URL "http://127.0.0.1:${KEA6_CTRL_PORT:-8006}/"
  # Kea's hooks-libraries path check rejects the /usr/lib/kea/hooks symlink
  # (it validates against the real compiled-in directory, not a symlink
  # target), so the control plane must be given the real path, not the
  # convenience symlink used by the static kea-dhcp{4,6}.conf files.
  set_env_var KEA_HOOKS_DIR "$hooks_dir"

  systemctl daemon-reload
  systemctl enable mantis-kea-dhcp4 mantis-kea-dhcp6
  if ! systemctl restart mantis-kea-dhcp4 mantis-kea-dhcp6 \
      || ! wait_for_tcp 127.0.0.1 "${KEA4_CTRL_PORT:-8004}" \
      || ! wait_for_tcp 127.0.0.1 "${KEA6_CTRL_PORT:-8006}"; then
    echo "Kea failed to start or did not open its local management sockets."
    echo "If the journal shows permission/socket errors, the LXC likely lacks the network capabilities needed for DHCP."
    systemctl status mantis-kea-dhcp4 mantis-kea-dhcp6 --no-pager || true
    journalctl -u mantis-kea-dhcp4 -u mantis-kea-dhcp6 -n 120 --no-pager || true
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

echo "==> Installing packages (postgresql, python3, nodejs, nginx$( [ "$INSTALL_FILTER" = "1" ] && echo ', cargo' ))..."
dnf -y module enable nodejs:20 2>/dev/null || true
PKGS="postgresql-server postgresql-contrib python3 python3-pip nodejs nginx gettext openssl ca-certificates curl jq policycoreutils-python-utils firewalld"
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
KEA_CTRL_URL=${KEA_CTRL_URL:-}
KEA4_CTRL_URL=${KEA4_CTRL_URL:-}
KEA6_CTRL_URL=${KEA6_CTRL_URL:-}
KEA_HOOKS_DIR=${KEA_HOOKS_DIR:-/usr/lib/kea/hooks}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
MANTIS_SIGNING_KEY_PATH=${ENV_DIR}/signing_key.bin
FEED_STORAGE_DIR=${INSTALL_DIR}/data/feed_domains
BUNDLE_STORAGE_DIR=${INSTALL_DIR}/data/bundles
EOF
  chmod 600 "$ENV_FILE"
  echo "Generated ADMIN_PASSWORD (shown once): ${ADMIN_PASSWORD}"
fi
ensure_env_var KEA_CTRL_URL "${KEA_CTRL_URL:-}"
ensure_env_var KEA4_CTRL_URL "${KEA4_CTRL_URL:-}"
ensure_env_var KEA6_CTRL_URL "${KEA6_CTRL_URL:-}"
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
ensure_env_var KEA_HOOKS_DIR "${KEA_HOOKS_DIR:-/usr/lib/kea/hooks}"
refresh_kea_env_var KEA_CTRL_URL "$REQUESTED_KEA_CTRL_URL" ""
refresh_kea_env_var KEA4_CTRL_URL "$REQUESTED_KEA4_CTRL_URL" ""
refresh_kea_env_var KEA6_CTRL_URL "$REQUESTED_KEA6_CTRL_URL" ""
refresh_kea_env_var KEA_HOOKS_DIR "$REQUESTED_KEA_HOOKS_DIR" "/usr/lib/kea/hooks"
chmod 600 "$ENV_FILE"

load_control_env
parse_database_url

if [ "$INSTALL_KEA" = "1" ]; then
  install_local_kea
  load_control_env
else
  echo "==> INSTALL_KEA=0 — skipping local Kea DHCP services."
fi

id -u mantis >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /sbin/nologin mantis

# The mantis-control.env file itself stays root:root 0600 (systemd reads
# EnvironmentFile as root before dropping privileges — the app never needs to
# read it directly), but the app *does* need to create/read
# MANTIS_SIGNING_KEY_PATH (signing_key.bin) in this directory at runtime as
# the `mantis` user.
chown mantis:mantis "$ENV_DIR"
chmod 750 "$ENV_DIR"

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
  if [ "$INSTALL_KEA" = "1" ]; then
    ensure_firewalld_service dhcp || true
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
if [ "$INSTALL_KEA" = "1" ]; then
  echo "Kea DHCP services: mantis-kea-dhcp4 and mantis-kea-dhcp6"
  echo "Kea management sockets listen on 127.0.0.1:${KEA4_CTRL_PORT:-8004} and 127.0.0.1:${KEA6_CTRL_PORT:-8006}."
fi
echo "Kea DHCPv4 management URL: $(env_value KEA4_CTRL_URL)"
if [ "$INSTALL_KEA" != "1" ]; then
  echo "Set KEA4_CTRL_URL/KEA6_CTRL_URL to the Kea host IP when Kea runs outside this LXC."
fi
echo "Log in with ADMIN_EMAIL/ADMIN_PASSWORD from ${ENV_FILE}, then rotate the password."