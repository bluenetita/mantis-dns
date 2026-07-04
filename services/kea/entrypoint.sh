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

mkdir -p /run/kea /var/lib/kea
rm -f /run/kea/*.pid

PG_HOST="${POSTGRES_HOST:-postgres}"
PG_PORT="${POSTGRES_PORT:-5432}"
PG_USER="${POSTGRES_USER:-mantis}"
PG_PASS="${POSTGRES_PASSWORD:-mantis}"
PG_DB="${POSTGRES_DB:-mantis}"
KEA_ROLE="${KEA_ROLE:-primary}"

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
    echo "Kea DB schema already present, skipping init."
fi

# Resolve run_script hook library path (varies by arch / Kea version).
RUN_SCRIPT_LIB=$(find /usr/lib -name 'libdhcp_run_script.so' 2>/dev/null | head -1)

if [ -n "$RUN_SCRIPT_LIB" ] && [ -f /usr/local/bin/mantis-ddns-bridge.sh ]; then
    echo "run_script hook found at ${RUN_SCRIPT_LIB} — DDNS bridge active."
    HOOKS_JSON="[{\"library\":\"${RUN_SCRIPT_LIB}\",\"parameters\":{\"name\":\"/usr/local/bin/mantis-ddns-bridge.sh\",\"sync\":false}}]"
else
    echo "run_script hook not found — DDNS bridge disabled."
    HOOKS_JSON="[]"
fi

# Write DHCPv4 runtime config.
sed \
    -e "s/__PG_HOST__/${PG_HOST}/g" \
    -e "s/__PG_PORT__/${PG_PORT}/g" \
    -e "s/__PG_USER__/${PG_USER}/g" \
    -e "s/__PG_PASS__/${PG_PASS}/g" \
    -e "s/__PG_DB__/${PG_DB}/g" \
    /etc/kea/kea-dhcp4.conf \
    | sed "s|__HOOKS_LIBRARIES__|${HOOKS_JSON}|g" \
    > /run/kea/kea-dhcp4-runtime.conf

# Write DHCPv6 runtime config.
sed \
    -e "s/__PG_HOST__/${PG_HOST}/g" \
    -e "s/__PG_PORT__/${PG_PORT}/g" \
    -e "s/__PG_USER__/${PG_USER}/g" \
    -e "s/__PG_PASS__/${PG_PASS}/g" \
    -e "s/__PG_DB__/${PG_DB}/g" \
    /etc/kea/kea-dhcp6.conf \
    > /run/kea/kea-dhcp6-runtime.conf

echo "Starting Kea as role: ${KEA_ROLE}"

# Start Control Agent in background (exposes REST API on :8080).
kea-ctrl-agent -c /etc/kea/kea-ctrl-agent.conf &

# Start DHCPv6 daemon in background (secondary nodes skip DHCPv4/v6 port binding
# to avoid conflict — HA handles failover via lease sync, not dual listeners).
if [ "$KEA_ROLE" = "primary" ]; then
    kea-dhcp6 -c /run/kea/kea-dhcp6-runtime.conf &
fi

# Start DHCPv4 daemon in foreground.
exec kea-dhcp4 -c /run/kea/kea-dhcp4-runtime.conf
