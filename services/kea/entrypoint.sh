#!/bin/sh

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

set -e

install -d -m 750 /var/run/kea
mkdir -p /var/lib/kea
rm -f /var/run/kea/*.pid

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-mantis}"
PG_PASS="${POSTGRES_PASSWORD:-mantis}"
PG_DB="${POSTGRES_DB:-mantis}"
KEA_ROLE="${KEA_ROLE:-primary}"
KEA_CTRL_BIND_ADDRESS="${KEA_CTRL_BIND_ADDRESS:-0.0.0.0}"
KEA4_CTRL_PORT="${KEA4_CTRL_PORT:-8004}"
KEA6_CTRL_PORT="${KEA6_CTRL_PORT:-8006}"

echo "Waiting for PostgreSQL at ${PG_HOST}:${PG_PORT}..."
until pg_isready -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" 2>/dev/null; do
    sleep 2
done
echo "PostgreSQL ready."

# Initialize Kea lease schema (idempotent) by running dhcpdb_create.pgsql directly.
# kea-admin db-init refuses when any tables already exist (our app tables are there),
# so we check for schema_version ourselves and run the script only if absent.
SCHEMA_EXISTS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
    -tAc "SELECT 1 FROM information_schema.tables WHERE table_name='schema_version' AND table_schema='public';" 2>/dev/null)

if [ "$SCHEMA_EXISTS" != "1" ]; then
    echo "Kea schema_version not found — running dhcpdb_create.pgsql ..."
    PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
        -f /usr/share/kea/scripts/pgsql/dhcpdb_create.pgsql
    echo "Kea DB schema initialised."
else
    echo "Kea DB schema already present — running kea-admin db-upgrade to catch it up to $(kea-dhcp4 -V | head -1)..."
    kea-admin db-upgrade pgsql \
        -h "$PG_HOST" -P "$PG_PORT" -u "$PG_USER" -p "$PG_PASS" -n "$PG_DB"
fi

# Resolve hook library paths (vary by arch / Kea version). Kea 3.x moved the
# PostgreSQL lease backend out of the daemon binaries and into a hook library
# that every daemon using lease-database type "postgresql" must load.
PGSQL_LIB=$(find /usr/lib -name 'libdhcp_pgsql.so' 2>/dev/null | head -1)
RUN_SCRIPT_LIB=$(find /usr/lib -name 'libdhcp_run_script.so' 2>/dev/null | head -1)
LEASE_CMDS_LIB=$(find /usr/lib -name 'libdhcp_lease_cmds.so' 2>/dev/null | head -1)
SUBNET_CMDS_LIB=$(find /usr/lib -name 'libdhcp_subnet_cmds.so' 2>/dev/null | head -1)
HOST_CMDS_LIB=$(find /usr/lib -name 'libdhcp_host_cmds.so' 2>/dev/null | head -1)

if [ -z "$PGSQL_LIB" ]; then
    echo "libdhcp_pgsql.so not found — install isc-kea-pgsql." >&2
    exit 1
fi
# lease_sync.py's lease4-get-all/lease4-get-page calls need this on kea-dhcp4.
if [ -z "$LEASE_CMDS_LIB" ]; then
    echo "libdhcp_lease_cmds.so not found — install isc-kea-hooks." >&2
    exit 1
fi
# The control plane pushes scope changes with subnet4-add/-update/-del and
# subnet6-add/-update/-del, and reservations with reservation-add/-del (see
# kea_config.py/kea_config6.py) rather than config-set, so these hooks are
# mandatory on both daemons.
if [ -z "$SUBNET_CMDS_LIB" ]; then
    echo "libdhcp_subnet_cmds.so not found — install isc-kea-hooks." >&2
    exit 1
fi
if [ -z "$HOST_CMDS_LIB" ]; then
    echo "libdhcp_host_cmds.so not found — install isc-kea-hooks." >&2
    exit 1
fi

HOOKS4_JSON="[{\"library\":\"${PGSQL_LIB}\"}, {\"library\":\"${LEASE_CMDS_LIB}\"}, {\"library\":\"${SUBNET_CMDS_LIB}\"}, {\"library\":\"${HOST_CMDS_LIB}\"}"
HOOKS6_JSON="[{\"library\":\"${PGSQL_LIB}\"}, {\"library\":\"${SUBNET_CMDS_LIB}\"}, {\"library\":\"${HOST_CMDS_LIB}\"}"

if [ -n "$RUN_SCRIPT_LIB" ] && [ -f /usr/share/kea/scripts/mantis-ddns-bridge.sh ]; then
    echo "run_script hook found at ${RUN_SCRIPT_LIB} — DDNS bridge active."
    HOOKS4_JSON="${HOOKS4_JSON}, {\"library\":\"${RUN_SCRIPT_LIB}\",\"parameters\":{\"name\":\"/usr/share/kea/scripts/mantis-ddns-bridge.sh\",\"sync\":false}}"
    HOOKS6_JSON="${HOOKS6_JSON}, {\"library\":\"${RUN_SCRIPT_LIB}\",\"parameters\":{\"name\":\"/usr/share/kea/scripts/mantis-ddns-bridge.sh\",\"sync\":false}}"
else
    echo "run_script hook not found — DDNS bridge disabled."
fi
HOOKS4_JSON="${HOOKS4_JSON}]"
HOOKS6_JSON="${HOOKS6_JSON}]"

# Write DHCPv4 runtime config.
sed \
    -e "s/__PG_HOST__/${PG_HOST}/g" \
    -e "s/__PG_PORT__/${PG_PORT}/g" \
    -e "s/__PG_USER__/${PG_USER}/g" \
    -e "s/__PG_PASS__/${PG_PASS}/g" \
    -e "s/__PG_DB__/${PG_DB}/g" \
    -e "s/__KEA_CTRL_BIND_ADDRESS__/${KEA_CTRL_BIND_ADDRESS}/g" \
    -e "s/__KEA4_CTRL_PORT__/${KEA4_CTRL_PORT}/g" \
    /etc/kea/kea-dhcp4.conf \
    | sed "s|__HOOKS_LIBRARIES__|${HOOKS4_JSON}|g" \
    > /var/run/kea/kea-dhcp4-runtime.conf

# Write DHCPv6 runtime config.
sed \
    -e "s/__PG_HOST__/${PG_HOST}/g" \
    -e "s/__PG_PORT__/${PG_PORT}/g" \
    -e "s/__PG_USER__/${PG_USER}/g" \
    -e "s/__PG_PASS__/${PG_PASS}/g" \
    -e "s/__PG_DB__/${PG_DB}/g" \
    -e "s/__KEA_CTRL_BIND_ADDRESS__/${KEA_CTRL_BIND_ADDRESS}/g" \
    -e "s/__KEA6_CTRL_PORT__/${KEA6_CTRL_PORT}/g" \
    /etc/kea/kea-dhcp6.conf \
    | sed "s|__HOOKS_LIBRARIES__|${HOOKS6_JSON}|g" \
    > /var/run/kea/kea-dhcp6-runtime.conf

echo "Starting Kea as role: ${KEA_ROLE}"

# Start DHCPv6 daemon in background (secondary nodes skip DHCPv4/v6 port binding
# to avoid conflict — HA handles failover via lease sync, not dual listeners).
if [ "$KEA_ROLE" = "primary" ]; then
    kea-dhcp6 -c /var/run/kea/kea-dhcp6-runtime.conf &
fi

# Start DHCPv4 daemon in foreground.
exec kea-dhcp4 -c /var/run/kea/kea-dhcp4-runtime.conf
