#!/usr/bin/env python3
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

"""Pulls Mantis DNS SIEM events (design.md §20.3) and appends them, one JSON
object per line, to a log file that Wazuh's `<localfile>` json log_format
can tail natively. Meant to run periodically as a Wazuh `<wodle
name="command">` (see ossec.conf.snippet.xml) or a plain cron job — Wazuh
has no generic inbound webhook receiver, so pull is the integration path
that requires zero changes on the Wazuh side. See README.md in this
directory for full setup.

Cursor handling: the last-seen `next_cursor` is persisted to --state-file
between runs (design.md §20.3: "SIEM pollers should store next_cursor
durably between poll cycles to avoid re-processing on restart"). The cursor
is only advanced after the corresponding events have been fsync'd to the
output log, so a crash mid-run re-fetches at most one page, never loses one.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def login(api_base: str, email: str, password: str) -> str:
    data = _post_json(f"{api_base}/auth/login", {"email": email, "password": password})
    token = data.get("access_token") or data.get("token")
    if not token:
        raise RuntimeError(f"login response had no access token: {sorted(data.keys())}")
    return token


def read_cursor(state_file: Path) -> str | None:
    try:
        cursor = state_file.read_text().strip()
        return cursor or None
    except FileNotFoundError:
        return None


def write_cursor(state_file: Path, cursor: str) -> None:
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(cursor)
    tmp.replace(state_file)  # atomic — a crash never leaves a half-written cursor


def append_events(output_file: Path, events: list[dict]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output_file), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        with os.fdopen(fd, "a") as f:
            for event in events:
                f.write(json.dumps(event, separators=(",", ":")))
                f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    finally:
        pass  # os.fdopen's context manager already closed fd


def run(args: argparse.Namespace) -> int:
    api_base = args.api_url.rstrip("/")
    token = args.token or login(api_base, args.email, args.password)
    state_file = Path(args.state_file)
    output_file = Path(args.output_file)

    cursor = read_cursor(state_file)
    total = 0
    pages = 0
    while True:
        params = {"limit": args.limit, "format": "json"}
        if cursor:
            params["after_id"] = cursor
        if args.tenant_id:
            params["tenant_id"] = args.tenant_id
        if args.decision:
            params["decision"] = args.decision
        url = f"{api_base}/siem/events?{urllib.parse.urlencode(params)}"

        try:
            page = _get_json(url, token)
        except urllib.error.HTTPError as e:
            if e.code == 401 and not args.token:
                # Token expired mid-run (12h TTL) — re-login once and retry this page.
                token = login(api_base, args.email, args.password)
                continue
            raise

        events = page["events"]
        if events:
            append_events(output_file, events)
            total += len(events)

        next_cursor = page.get("next_cursor")
        if next_cursor:
            write_cursor(state_file, next_cursor)
            cursor = next_cursor
            pages += 1
            if pages >= args.max_pages:
                break
            continue
        break

    if args.verbose:
        print(f"mantis_siem_pull: wrote {total} event(s) across {pages} page(s)", file=sys.stderr)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api-url", default=os.environ.get("MANTIS_API_URL", ""),
                    help="e.g. https://control.internal:8443/api/v1")
    p.add_argument("--token", default=os.environ.get("MANTIS_TOKEN", ""),
                    help="pre-issued bearer token; skips login if set")
    p.add_argument("--email", default=os.environ.get("MANTIS_EMAIL", ""),
                    help="operator/admin account used to obtain a bearer token")
    p.add_argument("--password", default=os.environ.get("MANTIS_PASSWORD", ""))
    p.add_argument("--state-file", default=os.environ.get(
        "MANTIS_STATE_FILE", "/var/ossec/var/mantis/cursor.txt"))
    p.add_argument("--output-file", default=os.environ.get(
        "MANTIS_OUTPUT_FILE", "/var/ossec/logs/mantis/siem-events.json"))
    p.add_argument("--tenant-id", default=os.environ.get("MANTIS_TENANT_ID", ""))
    p.add_argument("--decision", default=os.environ.get("MANTIS_DECISION", ""),
                    choices=["", "allow", "block"])
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--max-pages", type=int, default=20,
                    help="cap pages drained per run so one invocation can't run forever on a backlog")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    if not args.api_url:
        p.error("--api-url or MANTIS_API_URL is required")
    if not args.token and not (args.email and args.password):
        p.error("either --token/MANTIS_TOKEN or --email+--password/MANTIS_EMAIL+MANTIS_PASSWORD is required")
    return args


if __name__ == "__main__":
    try:
        sys.exit(run(parse_args(sys.argv[1:])))
    except Exception as e:
        print(f"mantis_siem_pull: {e}", file=sys.stderr)
        sys.exit(1)
