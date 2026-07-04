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

# One-shot install: generates a .env with real secrets (if missing) and
# brings the stack up via docker compose.
#
# Dev mode (default): builds images from source, Vite dev server on :5173.
# Prod mode (--prod):  pulls published GHCR images (docker-compose.prod.yml),
#                       generates a strong ADMIN_PASSWORD too, sets
#                       MANTIS_ENV=production. You must still set
#                       CORS_ALLOW_ORIGINS (and IMAGE_PREFIX/MANTIS_VERSION if
#                       not using the default registry) in .env yourself.
set -euo pipefail
cd "$(dirname "$0")/.."

PROD=0
for arg in "$@"; do
  case "$arg" in
    --prod) PROD=1 ;;
  esac
done

if [ -f .env ]; then
  echo ".env already exists — leaving it as-is. Delete it to regenerate secrets."
else
  echo "Creating .env with generated secrets..."
  cp .env.example .env
  MANTIS_INTERNAL_TOKEN=$(openssl rand -hex 32)
  MANTIS_SERVICE_TOKEN=$(openssl rand -hex 32)
  MANTIS_JWT_SECRET=$(openssl rand -hex 32)
  MANTIS_WEBHOOK_SECRET_KEY=$(openssl rand -hex 32)
  POSTGRES_PASSWORD=$(openssl rand -hex 16)

  sed -i.bak \
    -e "s/^MANTIS_INTERNAL_TOKEN=.*/MANTIS_INTERNAL_TOKEN=${MANTIS_INTERNAL_TOKEN}/" \
    -e "s/^MANTIS_SERVICE_TOKEN=.*/MANTIS_SERVICE_TOKEN=${MANTIS_SERVICE_TOKEN}/" \
    -e "s/^MANTIS_JWT_SECRET=.*/MANTIS_JWT_SECRET=${MANTIS_JWT_SECRET}/" \
    -e "s/^MANTIS_WEBHOOK_SECRET_KEY=.*/MANTIS_WEBHOOK_SECRET_KEY=${MANTIS_WEBHOOK_SECRET_KEY}/" \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" \
    .env

  if [ "$PROD" -eq 1 ]; then
    ADMIN_PASSWORD=$(openssl rand -hex 16)
    sed -i.bak \
      -e "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=${ADMIN_PASSWORD}/" \
      -e "s/^MANTIS_ENV=.*/MANTIS_ENV=production/" \
      .env
    echo "Secrets generated, including ADMIN_PASSWORD (shown once): ${ADMIN_PASSWORD}"
    echo "Before starting: set CORS_ALLOW_ORIGINS in .env to your UI's public origin(s)."
  else
    echo "Secrets generated. ADMIN_PASSWORD is still 'change-me-now' — change it after first login."
  fi
  rm -f .env.bak
fi

if [ "$PROD" -eq 1 ]; then
  echo "Pulling images and starting stack (docker compose -f docker-compose.prod.yml up -d)..."
  docker compose -f docker-compose.prod.yml pull
  docker compose -f docker-compose.prod.yml up -d
  echo
  echo "Done. UI: http://localhost/  API: http://localhost:8000"
else
  echo "Starting stack (docker compose up --build -d)..."
  docker compose up --build -d
  echo
  echo "Done. UI: http://localhost:5173  API: http://localhost:8000"
fi
echo "Log in with ADMIN_EMAIL / ADMIN_PASSWORD from .env, then rotate the password."
