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

# Wrapper invoked by the Wazuh "command" wodle (see ossec.conf.snippet.xml).
# Keeps MANTIS_EMAIL/MANTIS_PASSWORD out of ossec.conf (which Wazuh treats
# as config, not secret storage) by sourcing them from a restricted env
# file instead.
set -euo pipefail

ENV_FILE="${MANTIS_ENV_FILE:-/etc/mantis/wazuh-integration.env}"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
else
    echo "run-mantis-pull: env file $ENV_FILE not found" >&2
    exit 1
fi

PYTHON_BIN="${MANTIS_PYTHON_BIN:-/var/ossec/framework/python/bin/python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python3"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$PYTHON_BIN" "$SCRIPT_DIR/mantis_siem_pull.py"
