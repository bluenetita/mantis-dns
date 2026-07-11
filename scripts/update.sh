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

# In-place update for a docker-compose.prod.yml deployment brought up with
# scripts/bootstrap.sh --prod. Backs up the database before touching
# anything, pulls new images, brings the stack up, and health-checks the
# control plane before declaring success. On failure it prints the exact
# commands to roll back — it never restores a backup automatically, since
# that's a destructive action only an operator should confirm.
#
# Usage (from a checkout that already has .env from bootstrap.sh --prod):
#   MANTIS_VERSION=v0.2.0 ./scripts/update.sh
#
# MANTIS_VERSION defaults to "latest" (docker-compose.prod.yml's own
# default) if unset.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

COMPOSE_FILE=docker-compose.prod.yml
BACKUP_DIR=${MANTIS_BACKUP_DIR:-./backups}

if [ ! -f .env ]; then
  echo ".env not found — this doesn't look like an existing install. Run scripts/bootstrap.sh --prod first." >&2
  exit 1
fi

CONTROL_CONTAINER="$(docker compose -f "$COMPOSE_FILE" ps -q control 2>/dev/null)"
if [ -z "$CONTROL_CONTAINER" ]; then
  echo "The 'control' service isn't currently running under $COMPOSE_FILE — nothing to update in place." >&2
  echo "Run 'docker compose -f $COMPOSE_FILE up -d' for a first bring-up instead." >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a; . ./.env; set +a

# docker compose images has no per-field template output, so read the
# currently-running container's actual image tag via `docker inspect`.
CURRENT_IMAGE="$(docker inspect --format '{{.Config.Image}}' "$CONTROL_CONTAINER" 2>/dev/null || true)"
PREVIOUS_VERSION="${CURRENT_IMAGE##*:}"
PREVIOUS_VERSION=${PREVIOUS_VERSION:-${MANTIS_VERSION:-latest}}
TARGET_VERSION=${MANTIS_VERSION:-latest}

echo "==> Backing up database before updating (currently running: ${PREVIOUS_VERSION}, target: ${TARGET_VERSION})..."
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/$(date -u +%Y%m%dT%H%M%SZ).dump"
if ! docker compose -f "$COMPOSE_FILE" exec -T postgres \
    pg_dump -Fc -U "${POSTGRES_USER:-mantis}" -d "${POSTGRES_DB:-mantis}" > "$BACKUP_FILE"; then
  rm -f "$BACKUP_FILE"
  echo "Database backup failed — aborting update before any changes are made." >&2
  exit 1
fi
echo "    Backup saved to $BACKUP_FILE"

print_rollback() {
  echo >&2
  echo "==> Update failed. Nothing has been deleted." >&2
  echo "To roll back to the previous image version:" >&2
  echo "    MANTIS_VERSION=$PREVIOUS_VERSION docker compose -f $COMPOSE_FILE up -d" >&2
  echo "If a database migration ran and needs to be rolled back too:" >&2
  echo "    docker compose -f $COMPOSE_FILE exec -T postgres pg_restore --clean --if-exists -U ${POSTGRES_USER:-mantis} -d ${POSTGRES_DB:-mantis} < $BACKUP_FILE" >&2
  echo "Check logs first: docker compose -f $COMPOSE_FILE logs --tail 120 control" >&2
}

echo "==> Pulling images for MANTIS_VERSION=${TARGET_VERSION}..."
if ! MANTIS_VERSION="$TARGET_VERSION" docker compose -f "$COMPOSE_FILE" pull; then
  echo "Image pull failed — the running stack is untouched." >&2
  exit 1
fi

echo "==> Bringing up the stack on the new images..."
MANTIS_VERSION="$TARGET_VERSION" docker compose -f "$COMPOSE_FILE" up -d

echo "==> Waiting for the control plane to become healthy..."
healthy=0
for _ in $(seq 1 30); do
  if docker compose -f "$COMPOSE_FILE" exec -T control \
      python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2).read()' >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
done

if [ "$healthy" -ne 1 ]; then
  echo "Control plane did not become healthy after update." >&2
  docker compose -f "$COMPOSE_FILE" logs --tail 120 control >&2 || true
  print_rollback
  exit 1
fi

echo
echo "Done. Updated to MANTIS_VERSION=${TARGET_VERSION}. Database backup kept at $BACKUP_FILE."
