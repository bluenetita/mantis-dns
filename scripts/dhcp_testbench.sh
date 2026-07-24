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
#
# Drives the standalone DHCP testbench (testbench/dhcp/docker-compose.yml) --
# builds mantis-dhcp/mantis-dhcp6/control from source, exercises DHCPv4,
# DHCPv6, HA, DDNS (incl. a real control-plane outage), conflict detection,
# relay, PXE, and lease-expiry against them (design.md §22), and reports a
# pass/fail summary.
#
# Usage: scripts/dhcp_testbench.sh [--keep] [--skip-v6]
#   --keep      don't tear the stack down on exit (for poking at it after)
#   --skip-v6   skip the DHCPv6 phase (only useful if this Docker host can't
#               do an IPv6-enabled bridge network -- older Docker Desktop/
#               daemon configs without ipv6 support)

set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE_DIR="testbench/dhcp"
FAILED=0
KEEP=0
SKIP_V6=0

for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --skip-v6) SKIP_V6=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

dc() { docker compose -f "$COMPOSE_DIR/docker-compose.yml" -p dhcp-testbench "$@"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo "==> --keep set: leaving the stack up. Tear it down with:"
    echo "    docker compose --project-directory $COMPOSE_DIR -f $COMPOSE_DIR/docker-compose.yml --profile ha down -v"
    return
  fi
  echo "==> Tearing down the testbench stack..."
  dc --profile ha down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_phase() {
  local phase="$1"
  echo "==> Running phase: $phase"
  if ! dc exec -T runner python run_all.py --phase "$phase"; then
    FAILED=1
  fi
}

echo "==> Cleaning previous run state..."
mkdir -p "$COMPOSE_DIR/state"
rm -f "$COMPOSE_DIR/state/run.json"

echo "==> Building and starting postgres/control/dhcp/dhcp6/squatter/runner..."
dc up -d --build postgres control dhcp dhcp6 squatter runner

health_of() {
  docker inspect --format '{{.State.Health.Status}}' "$(dc ps -q "$1")" 2>/dev/null || true
}

echo "==> Waiting for control plane to become healthy..."
for _ in $(seq 1 60); do
  [ "$(health_of control)" = "healthy" ] && break
  sleep 2
done
if [ "$(health_of control)" != "healthy" ]; then
  echo "control plane never became healthy -- check: docker compose -f $COMPOSE_DIR/docker-compose.yml logs control"
  exit 1
fi
echo "    control is up."

run_phase setup
if [ "$FAILED" -eq 1 ]; then
  echo "setup phase failed -- nothing downstream can work without it, stopping here."
  exit 1
fi

run_phase core

if [ "$SKIP_V6" -eq 0 ]; then
  run_phase v6
else
  echo "==> Skipping DHCPv6 phase (--skip-v6)"
fi

echo "==> Starting the second mantis-dhcp instance for the HA phase..."
dc --profile ha up -d --build dhcp-ha
sleep 12  # let it load its own initial snapshot
run_phase ha
echo "==> Stopping the second instance (keeps later broadcast-based phases single-server)..."
dc stop dhcp-ha

echo "==> Stopping control plane to exercise the DDNS-outage retry path..."
dc stop control
run_phase ddns-trigger

echo "==> Restarting control plane..."
dc start control
for _ in $(seq 1 60); do
  [ "$(health_of control)" = "healthy" ] && break
  sleep 2
done
run_phase ddns-verify

run_phase expiry

echo
if [ "$FAILED" -eq 0 ]; then
  echo "PASS: all DHCP testbench phases passed."
  exit 0
else
  echo "FAIL: see phase output above for the failing checks."
  exit 1
fi
