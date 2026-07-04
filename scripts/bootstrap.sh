#!/usr/bin/env bash
# One-shot local install: generates a .env with real secrets (if missing)
# and brings the whole stack up via docker compose.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo ".env already exists — leaving it as-is. Delete it to regenerate secrets."
else
  echo "Creating .env with generated secrets..."
  cp .env.example .env
  AEGIS_INTERNAL_TOKEN=$(openssl rand -hex 32)
  AEGIS_SERVICE_TOKEN=$(openssl rand -hex 32)
  AEGIS_JWT_SECRET=$(openssl rand -hex 32)
  AEGIS_WEBHOOK_SECRET_KEY=$(openssl rand -hex 32)
  POSTGRES_PASSWORD=$(openssl rand -hex 16)

  sed -i.bak \
    -e "s/^AEGIS_INTERNAL_TOKEN=.*/AEGIS_INTERNAL_TOKEN=${AEGIS_INTERNAL_TOKEN}/" \
    -e "s/^AEGIS_SERVICE_TOKEN=.*/AEGIS_SERVICE_TOKEN=${AEGIS_SERVICE_TOKEN}/" \
    -e "s/^AEGIS_JWT_SECRET=.*/AEGIS_JWT_SECRET=${AEGIS_JWT_SECRET}/" \
    -e "s/^AEGIS_WEBHOOK_SECRET_KEY=.*/AEGIS_WEBHOOK_SECRET_KEY=${AEGIS_WEBHOOK_SECRET_KEY}/" \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" \
    .env
  rm -f .env.bak
  echo "Secrets generated. ADMIN_PASSWORD is still 'change-me-now' — change it after first login."
fi

echo "Starting stack (docker compose up --build -d)..."
docker compose up --build -d

echo
echo "Done. UI: http://localhost:5173  API: http://localhost:8000"
echo "Log in with ADMIN_EMAIL / ADMIN_PASSWORD from .env, then rotate the password."
