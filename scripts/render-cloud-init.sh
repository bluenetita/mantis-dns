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

# Renders infra/cloud-init/user-data.yaml.tmpl into a ready-to-paste
# cloud-init user-data document: embeds the current docker-compose.prod.yml
# and a .env pre-filled with your CORS origin / image registry / version
# (secrets are left for the instance to generate at first boot — see the
# template's runcmd). Single source of truth stays docker-compose.prod.yml
# and .env.example; nothing is duplicated by hand here.
set -euo pipefail
cd "$(dirname "$0")/.."

CORS_ALLOW_ORIGINS=""
IMAGE_PREFIX="ghcr.io/mantis-dns/mantis-dns"
MANTIS_VERSION="latest"
OUTPUT="infra/cloud-init/user-data.yaml"

while [ $# -gt 0 ]; do
  case "$1" in
    --cors) CORS_ALLOW_ORIGINS="$2"; shift 2 ;;
    --image-prefix) IMAGE_PREFIX="$2"; shift 2 ;;
    --version) MANTIS_VERSION="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$CORS_ALLOW_ORIGINS" ]; then
  echo "Usage: $0 --cors https://dns.example.com [--image-prefix ghcr.io/<you>/mantis-dns] [--version v0.1.0] [--output path]" >&2
  exit 1
fi

TEMPLATE="infra/cloud-init/user-data.yaml.tmpl"
COMPOSE_FILE="docker-compose.prod.yml"
ENV_TEMPLATE=".env.example"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# .env to embed: CORS + MANTIS_ENV filled in, secrets left as whatever
# .env.example has (blank/dev-default) — runcmd overwrites them with
# per-instance random values on first boot.
sed \
  -e "s#^CORS_ALLOW_ORIGINS=.*#CORS_ALLOW_ORIGINS=${CORS_ALLOW_ORIGINS}#" \
  -e "s#^MANTIS_ENV=.*#MANTIS_ENV=production#" \
  "$ENV_TEMPLATE" > "$WORKDIR/env_content"
{
  echo "IMAGE_PREFIX=${IMAGE_PREFIX}"
  echo "MANTIS_VERSION=${MANTIS_VERSION}"
} >> "$WORKDIR/env_content"

cp "$COMPOSE_FILE" "$WORKDIR/compose_content"

# Splices $2's lines in place of the line in $1 matching marker $3, each
# indented to match the marker line's own leading whitespace. Line-by-line
# with IFS= read -r so no backslash/whitespace munging touches file content.
splice() {
  local in="$1" content_file="$2" marker="$3" line trimmed indent
  while IFS= read -r line || [ -n "$line" ]; do
    trimmed="${line#"${line%%[! $'\t']*}"}"
    if [ "$trimmed" = "$marker" ]; then
      indent="${line%%"$trimmed"}"
      while IFS= read -r content_line || [ -n "$content_line" ]; do
        if [ -z "$content_line" ]; then
          printf '\n'
        else
          printf '%s%s\n' "$indent" "$content_line"
        fi
      done < "$content_file"
    else
      printf '%s\n' "$line"
    fi
  done < "$in"
}

splice "$TEMPLATE" "$WORKDIR/compose_content" "__COMPOSE_FILE_CONTENT__" > "$WORKDIR/pass1"
splice "$WORKDIR/pass1" "$WORKDIR/env_content" "__ENV_FILE_CONTENT__" > "$OUTPUT"

echo "Wrote $OUTPUT"
echo "Paste its contents into your provider's user-data / cloud-init field when launching the VM."
