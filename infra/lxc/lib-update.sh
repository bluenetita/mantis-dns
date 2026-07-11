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

# Shared backup/rollback helpers for infra/lxc/install.sh and
# install-rocky.sh's update path (re-running the installer against an
# existing /etc/mantis-control/mantis-control.env). Sourced, not executed —
# no shebang, no set -e of its own (inherits the caller's `set -euo pipefail`).

MANTIS_BACKUP_DIR=${MANTIS_BACKUP_DIR:-/var/backups/mantis-dns}

# Dumps the current DB to $MANTIS_BACKUP_DIR before an update touches
# anything. No-op (prints nothing, sets MANTIS_DB_BACKUP_FILE empty) on a
# fresh install — there's nothing to back up yet, and $DATABASE_URL's role
# may not exist.
backup_database() {
  database_url="$1"
  MANTIS_DB_BACKUP_FILE=""

  if [ -z "$database_url" ]; then
    return 0
  fi

  if ! command -v pg_dump >/dev/null 2>&1; then
    echo "==> pg_dump not found — skipping pre-update database backup." >&2
    return 0
  fi

  eval "$(
    DATABASE_URL="$database_url" python3 - <<'PY'
from urllib.parse import urlparse
import os
import shlex

url = urlparse(os.environ["DATABASE_URL"])
print(f"_BK_USER={shlex.quote(url.username or '')}")
print(f"_BK_PASSWORD={shlex.quote(url.password or '')}")
print(f"_BK_HOST={shlex.quote(url.hostname or '127.0.0.1')}")
print(f"_BK_PORT={shlex.quote(str(url.port or 5432))}")
print(f"_BK_DB={shlex.quote((url.path or '/').lstrip('/'))}")
PY
  )"

  mkdir -p "$MANTIS_BACKUP_DIR"
  chmod 700 "$MANTIS_BACKUP_DIR"
  backup_file="$MANTIS_BACKUP_DIR/$(date -u +%Y%m%dT%H%M%SZ).dump"

  echo "==> Backing up database '$_BK_DB' to $backup_file before updating..."
  if PGPASSWORD="$_BK_PASSWORD" pg_dump -Fc \
      -h "$_BK_HOST" -p "$_BK_PORT" -U "$_BK_USER" -d "$_BK_DB" \
      -f "$backup_file"; then
    chmod 600 "$backup_file"
    MANTIS_DB_BACKUP_FILE="$backup_file"
  else
    echo "Database backup failed — aborting update before any changes are made." >&2
    exit 1
  fi
}

# Keeps exactly one prior code generation so a failed update can be rolled
# back before the previous, known-good code is gone. No-op on a fresh
# install ($install_dir/app and venv don't exist yet).
rotate_code_dirs() {
  install_dir="$1"

  if [ ! -d "$install_dir/app" ] && [ ! -d "$install_dir/venv" ]; then
    return 0
  fi

  rm -rf "$install_dir/app.previous" "$install_dir/venv.previous"
  [ -d "$install_dir/app" ] && mv "$install_dir/app" "$install_dir/app.previous"
  [ -d "$install_dir/venv" ] && mv "$install_dir/venv" "$install_dir/venv.previous"
}

# Called only after a health check confirms the new code is good — drops the
# prior generation kept by rotate_code_dirs.
discard_previous_generation() {
  install_dir="$1"
  rm -rf "$install_dir/app.previous" "$install_dir/venv.previous"
}

# Polls the control plane's /health endpoint via the venv's own Python (no
# extra dependency on curl/wget being installed).
wait_for_control() {
  install_dir="$1"
  for _ in $(seq 1 30); do
    if "$install_dir/venv/bin/python" -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2).read()' >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Imports the app and runs its startup lifespan (migrations, signing key,
# feed seed) once as the `mantis` user, without binding a port — catches a
# broken migration/import before systemd ever restarts the real service.
check_control_startup() {
  install_dir="$1"
  (
    cd "$install_dir/app"
    runuser -u mantis --preserve-environment -- "$install_dir/venv/bin/python" - <<'PY'
import asyncio

from mantis_control.main import app, _lifespan


async def main() -> None:
    async with _lifespan(app):
        pass


asyncio.run(main())
PY
  )
}

# Prints exact, ready-to-run recovery commands on a failed update. Never
# executes them itself — restoring a database is destructive and an operator
# must confirm it deliberately.
print_rollback_instructions() {
  install_dir="$1"
  service_name="$2"

  echo
  echo "==> Update failed. The previous code generation was kept; nothing has been deleted." >&2
  if [ -n "${MANTIS_DB_BACKUP_FILE:-}" ]; then
    echo "    Database backup taken before this update: $MANTIS_DB_BACKUP_FILE" >&2
  else
    echo "    No database backup was taken (fresh install, or pg_dump unavailable)." >&2
  fi
  echo "To roll back the code:" >&2
  echo "    systemctl stop $service_name" >&2
  echo "    rm -rf $install_dir/app $install_dir/venv" >&2
  echo "    mv $install_dir/app.previous $install_dir/app" >&2
  echo "    mv $install_dir/venv.previous $install_dir/venv" >&2
  echo "    systemctl start $service_name" >&2
  if [ -n "${MANTIS_DB_BACKUP_FILE:-}" ]; then
    echo "If the database also needs to be rolled back (only if a migration ran and broke data):" >&2
    echo "    pg_restore --clean --if-exists -h 127.0.0.1 -U <db user> -d <db name> \"$MANTIS_DB_BACKUP_FILE\"" >&2
  fi
  echo "Check logs first: journalctl -u $service_name -n 120 --no-pager" >&2
}
