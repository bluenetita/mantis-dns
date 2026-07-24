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

"""Stdlib-only self-check for mantis_siem_pull.py's cursor/relogin logic —
not wired into the services/control pytest suite (this script ships and
runs on the Wazuh manager host, outside that venv). Run directly:
`python3 test_mantis_siem_pull.py`.
"""

from __future__ import annotations

import argparse
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import mantis_siem_pull as pull


def _args(**overrides) -> argparse.Namespace:
    defaults = dict(
        api_url="https://control.internal/api/v1",
        token="fixed-token",
        email="",
        password="",
        state_file="",
        output_file="",
        tenant_id="",
        decision="",
        limit=500,
        max_pages=20,
        verbose=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class CursorCheckpointTest(unittest.TestCase):
    def test_single_page_run_persists_cursor(self):
        """The whole backlog fitting in one page (has_more == False, so the
        server's next_cursor is null) is the common case — the cursor must
        still be checkpointed, or the next run re-fetches everything."""
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "cursor.txt"
            output_file = Path(tmp) / "events.json"
            page = {
                "events": [{"seq": 1, "qname": "a.example"}, {"seq": 2, "qname": "b.example"}],
                "next_cursor": None,
                "total_in_window": 2,
            }
            with patch.object(pull, "_get_json", return_value=page):
                rc = pull.run(_args(state_file=str(state_file), output_file=str(output_file)))

            self.assertEqual(rc, 0)
            self.assertEqual(state_file.read_text().strip(), "2")

    def test_multi_page_run_checkpoints_after_every_page(self):
        pages = [
            {"events": [{"seq": 1}], "next_cursor": "1", "total_in_window": 1},
            {"events": [{"seq": 2}], "next_cursor": None, "total_in_window": 1},
        ]
        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "cursor.txt"
            output_file = Path(tmp) / "events.json"
            with patch.object(pull, "_get_json", side_effect=pages):
                pull.run(_args(state_file=str(state_file), output_file=str(output_file)))
            self.assertEqual(state_file.read_text().strip(), "2")

    def test_relogin_on_401_is_attempted_only_once(self):
        unauthorized = urllib.error.HTTPError("url", 401, "unauthorized", {}, None)
        calls = {"get": 0, "login": 0}

        def fake_get(url, token):
            calls["get"] += 1
            raise unauthorized

        def fake_login(api_base, email, password):
            calls["login"] += 1
            return "new-token"

        with TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "cursor.txt"
            output_file = Path(tmp) / "events.json"
            args = _args(
                token="",
                email="admin@example.test",
                password="pw",
                state_file=str(state_file),
                output_file=str(output_file),
            )
            with patch.object(pull, "_get_json", side_effect=fake_get), \
                 patch.object(pull, "login", side_effect=fake_login), \
                 self.assertRaises(urllib.error.HTTPError):
                pull.run(args)

        # One login to obtain the initial token, then one 401 -> one relogin
        # -> one retry that also 401s and is allowed to propagate, instead
        # of looping forever.
        self.assertEqual(calls["get"], 2)
        self.assertEqual(calls["login"], 2)


if __name__ == "__main__":
    unittest.main()
