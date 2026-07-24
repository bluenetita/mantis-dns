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

# End-to-end regression test, on the real docker-compose stack, for the
# "compiled bundle silently blocks nothing" bug: _category_bloom()
# (mantis_control/compiler/build_policy_bundle.py) embeds an EMPTY bloom
# filter for a blocked category if its feed's last_domain_count is NULL —
# which only becomes non-NULL after an actual feed *ingest*, not just
# creating/enabling the feed. "Test a domain" doesn't hit this gate (it reads
# the domain file straight off disk), so it can say BLOCK while real DNS
# traffic sails through, no matter how many times you compile+publish.
#
# This script proves both halves on a live filter node answering real DNS
# queries, using a throwaway category id + feed (never touches any real
# category/feed data already in your DB):
#   1. category=BLOCK, feed created but never ingested -> test domain
#      resolves (bug: empty bloom filter blocks nothing).
#   2. same feed, but with last_domain_count populated (simulating a
#      completed ingest) -> test domain is NXDOMAIN (fixed).
#
# Requires: docker, docker compose. Uses this repo's docker-compose.yml
# (postgres/control/filter), building images from source if needed — the
# first run takes a few minutes. Does NOT touch any pre-existing tenant,
# group, policy, or feed — everything it creates is deleted again on exit.
#
# Usage: scripts/test_category_bloom_docker.sh

set -euo pipefail
cd "$(dirname "$0")/.."

API="http://localhost:8000/api/v1"
COOKIEJAR="$(mktemp)"
RUN_ID="$(python -c 'import uuid; print(uuid.uuid4().hex[:8])')"
TENANT_NAME="e2e-category-bloom-test-$RUN_ID"
GROUP_NAME="e2e-group"
CATEGORY_ID="e2e-test-category-$RUN_ID"
FEED_ID="e2e-test-feed-$RUN_ID"
TEST_DOMAIN="example.com"
FAILED=0

cleanup() {
  if [ -n "${TENANT_ID:-}" ]; then
    echo "==> Cleaning up test tenant ${TENANT_ID}..."
    curl -s -b "$COOKIEJAR" -H "x-mantis-csrf-token: ${CSRF_TOKEN:-}" \
      -X DELETE "$API/tenants/$TENANT_ID" >/dev/null || true
  fi
  # Feeds are global (not tenant-scoped), so deleting the tenant above
  # doesn't remove this — clean it up explicitly so reruns/crashes don't
  # leave orphaned throwaway feeds behind. Must run before the cookie jar
  # is removed, or these requests go out unauthenticated and silently no-op.
  curl -s -b "$COOKIEJAR" -H "x-mantis-csrf-token: ${CSRF_TOKEN:-}" \
    -X DELETE "$API/feeds/$FEED_ID" >/dev/null || true
  # DELETE /feeds only removes the DB row, not the domains file this test
  # wrote directly on disk.
  docker compose exec -T control sh -c "rm -f feed_domains/$FEED_ID.domains.txt" >/dev/null 2>&1 || true
  rm -f "$COOKIEJAR"
}
trap cleanup EXIT

pyjson() {
  # Extracts a top-level JSON field from stdin, or prints the raw body and
  # fails loudly if the field isn't there (e.g. an error response).
  python -c "
import json, sys
body = sys.stdin.read()
try:
    print(json.loads(body)$1)
except Exception:
    print(\"unexpected API response, expected field $1:\", file=sys.stderr)
    print(body, file=sys.stderr)
    sys.exit(1)
"
}

echo "==> Bringing up postgres/control (building from source if needed)..."
docker compose up -d --build control

echo "==> Waiting for control plane to become healthy..."
for _ in $(seq 1 60); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
if ! curl -sf http://localhost:8000/health >/dev/null 2>&1; then
  echo "control plane never became healthy — check: docker compose logs control"
  exit 1
fi
echo "    control is up."

echo "==> Logging in as the seeded dev admin..."
LOGIN_RESP=$(curl -s -c "$COOKIEJAR" -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mantis.local","password":"change-me-now"}')
CSRF_TOKEN=$(echo "$LOGIN_RESP" | pyjson "['csrf_token']")
echo "    logged in."

api_post() {
  curl -s -w '\n%{http_code}' -b "$COOKIEJAR" -H "x-mantis-csrf-token: $CSRF_TOKEN" -H "Content-Type: application/json" \
    -X POST "$API$1" -d "$2"
}
api_put() {
  curl -s -w '\n%{http_code}' -b "$COOKIEJAR" -H "x-mantis-csrf-token: $CSRF_TOKEN" -H "Content-Type: application/json" \
    -X PUT "$API$1" -d "$2"
}

# Splits the `curl -w '\n%{http_code}'` output into body/status and fails
# loudly (printing the body) if status isn't 2xx.
check_2xx() {
  local resp="$1" label="$2"
  local status="${resp##*$'\n'}"
  local body="${resp%$'\n'*}"
  if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
    echo "$label failed (HTTP $status): $body" >&2
    exit 1
  fi
  echo "$body"
}

echo "==> Creating throwaway tenant/group..."
TENANT_ID=$(check_2xx "$(api_post "/tenants" "{\"name\":\"$TENANT_NAME\"}")" "create tenant" | pyjson "['id']")
GROUP_ID=$(check_2xx "$(api_post "/tenants/$TENANT_ID/groups" "{\"name\":\"$GROUP_NAME\"}")" "create group" | pyjson "['id']")
echo "    tenant_id=$TENANT_ID group_id=$GROUP_ID"

echo "==> Starting the filter node in single-tenant mode for this group..."
GROUP_ID="$GROUP_ID" docker compose up -d --build filter
echo "    waiting for it to fetch an initial (empty) bundle..."
sleep 8

echo "==> Setting policy: category '$CATEGORY_ID' = ACTION_BLOCK..."
check_2xx "$(api_put "/groups/$GROUP_ID/policy" \
  "{\"on_load_failure\":\"FAIL_OPEN\",\"category_toggles\":[{\"category_id\":\"$CATEGORY_ID\",\"action\":\"ACTION_BLOCK\"}],\"overrides\":[]}")" \
  "set policy" >/dev/null

echo "==> Creating feed '$FEED_ID' for category '$CATEGORY_ID' (NOT ingesting it yet)..."
check_2xx "$(api_post "/feeds" \
  "{\"id\":\"$FEED_ID\",\"category_id\":\"$CATEGORY_ID\",\"url\":\"https://example.com/e2e-nonexistent-list.txt\",\"format\":\"domain-list\",\"enabled\":true}")" \
  "create feed" >/dev/null

echo "==> Compiling & publishing bundle (feed never ingested — last_domain_count is NULL)..."
check_2xx "$(api_post "/groups/$GROUP_ID/bundle" "")" "compile bundle" >/dev/null
echo "    waiting for the filter node's next poll tick (default BUNDLE_POLL_INTERVAL_SECS=10)..."
sleep 12

net_of() { docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$(docker compose ps -q "$1")"; }
FILTER_NET="$(net_of filter)"

dig_full() {
  # Full dig output (not +short) via a throwaway container on the same
  # docker network as `filter` (no dig on this host) — lets us tell a real
  # NXDOMAIN (blocked) apart from a timeout/SERVFAIL (unrelated network
  # issue), which +short alone can't distinguish.
  docker run --rm --network "$FILTER_NET" alpine sh -c \
    "apk add --no-cache bind-tools >/dev/null 2>&1 && dig +time=3 +tries=1 @filter -p 1053 '$1'" 2>&1 || true
}

status_of() {
  echo "$1" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}

echo "==> [1/2] Querying $TEST_DOMAIN through the filter node (feed never ingested)..."
DIG_BEFORE="$(dig_full "$TEST_DOMAIN")"
STATUS_BEFORE="$(status_of "$DIG_BEFORE")"
echo "    status: ${STATUS_BEFORE:-<no response>}"
if [ "$STATUS_BEFORE" = "NOERROR" ]; then
  echo "    ALLOWED — matches the bug: empty bloom filter blocks nothing."
elif [ "$STATUS_BEFORE" = "NXDOMAIN" ]; then
  echo "    BLOCKED — unexpected at this stage; either the bug is already fixed here, or"
  echo "    something else (not the empty-bloom gate) is blocking this domain."
  FAILED=1
else
  echo "    Unexpected/no response — this is a network/resolution problem, not the bug"
  echo "    under test. Full dig output:"
  echo "$DIG_BEFORE"
  FAILED=1
fi

echo "==> Simulating a completed ingest (writing feed_domains file + last_domain_count directly —"
echo "    same end-state fetch_and_ingest() would leave; this test isn't exercising the HTTP"
echo "    fetch/SSRF-guard path itself, only what the compiler does with an ingested feed)..."
docker compose exec -T control sh -c \
  "mkdir -p feed_domains && printf '%s\n' '$TEST_DOMAIN' > feed_domains/$FEED_ID.domains.txt"
docker compose exec -T control python -c "
from mantis_control.db.session import SessionLocal
from mantis_control.db.models import Feed
db = SessionLocal()
feed = db.get(Feed, '$FEED_ID')
assert feed is not None, 'feed $FEED_ID not found in DB — create-feed step must have failed'
feed.last_domain_count = 1
db.commit()
print('last_domain_count set for', feed.id)
"

echo "==> Compiling & publishing bundle again (feed now has last_domain_count set)..."
check_2xx "$(api_post "/groups/$GROUP_ID/bundle" "")" "recompile bundle" >/dev/null
echo "    waiting for the filter node's next poll tick (default BUNDLE_POLL_INTERVAL_SECS=10)..."
sleep 12

echo "==> [2/2] Querying $TEST_DOMAIN through the filter node (feed now 'ingested')..."
DIG_AFTER="$(dig_full "$TEST_DOMAIN")"
STATUS_AFTER="$(status_of "$DIG_AFTER")"
echo "    status: ${STATUS_AFTER:-<no response>}"
if [ "$STATUS_AFTER" = "NXDOMAIN" ]; then
  echo "    BLOCKED — confirms the category now blocks once the feed is actually ingested."
else
  echo "    NOT blocked (status: ${STATUS_AFTER:-<no response>}) — expected NXDOMAIN after ingest."
  FAILED=1
fi

echo
if [ "$FAILED" -eq 0 ] && [ "$STATUS_BEFORE" = "NOERROR" ] && [ "$STATUS_AFTER" = "NXDOMAIN" ]; then
  echo "PASS: reproduced the bug (allowed pre-ingest) and confirmed the fix (blocked post-ingest)."
  echo "      Root cause: a category's bloom filter stays empty until its feed is explicitly"
  echo "      ingested (POST /feeds/{id}/ingest) — enabling/toggling alone is not enough, and"
  echo "      re-compiling repeatedly does not help without an ingest in between."
  exit 0
else
  echo "FAIL: see above — behavior didn't match the expected before/after."
  exit 1
fi
