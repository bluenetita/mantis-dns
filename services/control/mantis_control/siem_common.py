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

"""Shared retry/backoff constants and helpers for the SIEM export sinks
(webhook: siem_delivery.py, syslog: siem_syslog_delivery.py). Both sinks
poll QueryEvent on their own cursor and their own scheduler tick, but share
the same backoff ladder and failure-count threshold so an operator sees
consistent behavior regardless of which sink is failing.
"""

from __future__ import annotations

from datetime import datetime, timezone

BACKOFF_SECONDS = [5, 30, 120, 600, 3600]
MAX_CONSECUTIVE_FAILURES = 6


def as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
