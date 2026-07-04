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

# Kea run_script hook — fires for each lease event and notifies the Mantis
# control plane so it can create/remove DNS A records for DDNS-enabled scopes.
#
# Called by kea-dhcp4 as: /usr/local/bin/mantis-ddns-bridge.sh
# Kea sets CALLOUT_NAME and per-callout env vars before exec.

CTRL_URL="${MANTIS_CTRL_URL:-http://control:8000}"
TOKEN="${MANTIS_INTERNAL_TOKEN:-}"

_post() {
    curl -sf -X POST "${CTRL_URL}/api/v1/internal/dhcp-event" \
        -H "Content-Type: application/json" \
        -H "X-Internal-Token: ${TOKEN}" \
        -d "$1" >/dev/null 2>&1 || true
}

case "${CALLOUT_NAME}" in
    leases4_committed)
        N=0
        while [ "${N}" -lt "${LEASES4_SIZE:-0}" ]; do
            eval "ADDR=\${LEASES4_AT${N}_ADDRESS}"
            eval "HOSTNAME=\${LEASES4_AT${N}_HOSTNAME}"
            eval "HWADDR=\${LEASES4_AT${N}_HWADDR}"
            eval "SUBNET_ID=\${LEASES4_AT${N}_SUBNET_ID}"
            eval "STATE=\${LEASES4_AT${N}_STATE}"
            # State 0 = active; only create DDNS records for live leases
            if [ "${STATE}" = "0" ] && [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
                _post "{\"event\":\"add\",\"ip\":\"${ADDR}\",\"hostname\":\"${HOSTNAME}\",\"mac\":\"${HWADDR}\",\"subnet_id\":${SUBNET_ID:-0}}"
            fi
            N=$((N + 1))
        done
        ;;
    lease4_expire)
        ADDR="${LEASE4_ADDRESS:-}"
        HOSTNAME="${LEASE4_HOSTNAME:-}"
        HWADDR="${LEASE4_HWADDR:-}"
        if [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "{\"event\":\"expire\",\"ip\":\"${ADDR}\",\"hostname\":\"${HOSTNAME}\",\"mac\":\"${HWADDR}\",\"subnet_id\":${LEASE4_SUBNET_ID:-0}}"
        fi
        ;;
    lease4_recover)
        # Lease recovered from expired-reclaimed — same treatment as active
        ADDR="${LEASE4_ADDRESS:-}"
        HOSTNAME="${LEASE4_HOSTNAME:-}"
        HWADDR="${LEASE4_HWADDR:-}"
        if [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "{\"event\":\"add\",\"ip\":\"${ADDR}\",\"hostname\":\"${HOSTNAME}\",\"mac\":\"${HWADDR}\",\"subnet_id\":${LEASE4_SUBNET_ID:-0}}"
        fi
        ;;
esac
