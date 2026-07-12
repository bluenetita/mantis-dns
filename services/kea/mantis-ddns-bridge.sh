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
# control plane so it can create/remove DNS A/AAAA records for DDNS-enabled
# scopes. Wired into both kea-dhcp4 and kea-dhcp6 (see entrypoint.sh).
#
# Called by kea-dhcp4/kea-dhcp6 as: /usr/local/bin/mantis-ddns-bridge.sh
# Kea sets CALLOUT_NAME and per-callout env vars before exec.

CTRL_URL="${MANTIS_CTRL_URL:-http://control:8000}"
TOKEN="${MANTIS_INTERNAL_TOKEN:-}"

# Every field below (hostname in particular) comes straight from a DHCP
# client's own option data — fully attacker-controlled. Building JSON by hand
# with string interpolation let a hostname containing a stray `"` inject
# extra keys (e.g. a second "ip") that clobber the ones set here, since
# json.loads keeps the last occurrence of a duplicate key. `jq -n --arg`
# escapes each value properly regardless of content, so a malicious hostname
# can only ever end up as the value of the "hostname" key.
#
# family "4" identifies by mac (hwaddr); family "6" identifies by duid —
# DHCPv6 leases are DUID-keyed, not MAC-keyed (see dhcp_internal_routers.py).
_post() {
    event="$1" family="$2" addr="$3" hostname="$4" identifier="$5" subnet_id="$6"
    if [ "${family}" = "6" ]; then
        payload="$(jq -nc \
            --arg event "${event}" \
            --arg ip "${addr}" \
            --arg hostname "${hostname}" \
            --arg duid "${identifier}" \
            --argjson subnet_id "${subnet_id:-0}" \
            '{event:$event, ip:$ip, hostname:$hostname, family:"6", duid:$duid, subnet_id:$subnet_id}' \
            2>/dev/null)" || return 0
    else
        payload="$(jq -nc \
            --arg event "${event}" \
            --arg ip "${addr}" \
            --arg hostname "${hostname}" \
            --arg mac "${identifier}" \
            --argjson subnet_id "${subnet_id:-0}" \
            '{event:$event, ip:$ip, hostname:$hostname, family:"4", mac:$mac, subnet_id:$subnet_id}' \
            2>/dev/null)" || return 0
    fi
    curl -sf -X POST "${CTRL_URL}/api/v1/internal/dhcp-event" \
        -H "Content-Type: application/json" \
        -H "X-Internal-Token: ${TOKEN}" \
        -d "${payload}" >/dev/null 2>&1 || true
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
                _post "add" "4" "${ADDR}" "${HOSTNAME}" "${HWADDR}" "${SUBNET_ID:-0}"
            fi
            N=$((N + 1))
        done
        ;;
    lease4_expire)
        ADDR="${LEASE4_ADDRESS:-}"
        HOSTNAME="${LEASE4_HOSTNAME:-}"
        HWADDR="${LEASE4_HWADDR:-}"
        if [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "expire" "4" "${ADDR}" "${HOSTNAME}" "${HWADDR}" "${LEASE4_SUBNET_ID:-0}"
        fi
        ;;
    lease4_recover)
        # Lease recovered from expired-reclaimed — same treatment as active
        ADDR="${LEASE4_ADDRESS:-}"
        HOSTNAME="${LEASE4_HOSTNAME:-}"
        HWADDR="${LEASE4_HWADDR:-}"
        if [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "add" "4" "${ADDR}" "${HOSTNAME}" "${HWADDR}" "${LEASE4_SUBNET_ID:-0}"
        fi
        ;;
    leases6_committed)
        N=0
        while [ "${N}" -lt "${LEASES6_SIZE:-0}" ]; do
            eval "ADDR=\${LEASES6_AT${N}_ADDRESS}"
            eval "HOSTNAME=\${LEASES6_AT${N}_HOSTNAME}"
            eval "DUID=\${LEASES6_AT${N}_DUID}"
            eval "SUBNET_ID=\${LEASES6_AT${N}_SUBNET_ID}"
            eval "STATE=\${LEASES6_AT${N}_STATE}"
            eval "TYPE=\${LEASES6_AT${N}_TYPE}"
            # State 0 = active; only IA_NA leases map to a single host address
            # — IA_PD (prefix delegation) has no single-host meaning for DDNS.
            if [ "${STATE}" = "0" ] && [ "${TYPE}" = "IA_NA" ] \
                && [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
                _post "add" "6" "${ADDR}" "${HOSTNAME}" "${DUID}" "${SUBNET_ID:-0}"
            fi
            N=$((N + 1))
        done
        ;;
    lease6_expire)
        ADDR="${LEASE6_ADDRESS:-}"
        HOSTNAME="${LEASE6_HOSTNAME:-}"
        DUID="${LEASE6_DUID:-}"
        TYPE="${LEASE6_TYPE:-}"
        if [ "${TYPE}" = "IA_NA" ] && [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "expire" "6" "${ADDR}" "${HOSTNAME}" "${DUID}" "${LEASE6_SUBNET_ID:-0}"
        fi
        ;;
    lease6_recover)
        ADDR="${LEASE6_ADDRESS:-}"
        HOSTNAME="${LEASE6_HOSTNAME:-}"
        DUID="${LEASE6_DUID:-}"
        TYPE="${LEASE6_TYPE:-}"
        if [ "${TYPE}" = "IA_NA" ] && [ -n "${HOSTNAME}" ] && [ -n "${ADDR}" ]; then
            _post "add" "6" "${ADDR}" "${HOSTNAME}" "${DUID}" "${LEASE6_SUBNET_ID:-0}"
        fi
        ;;
esac
