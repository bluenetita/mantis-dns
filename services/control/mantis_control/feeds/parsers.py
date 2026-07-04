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

"""Parsers for raw feed text into a normalized domain set.

design.md §18.3: normalize step — lowercase, strip www, drop comments/blank
lines. IDN->punycode is a known gap, tracked for when a feed actually needs it.
"""

from __future__ import annotations

import re

_HOSTFILE_LINE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)")
_PLAIN_DOMAIN_LINE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _normalize_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def parse_hostfile(text: str) -> set[str]:
    """Parses '0.0.0.0 domain.tld' / '127.0.0.1 domain.tld' style hosts files
    (StevenBlack, URLhaus hostfile format)."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _HOSTFILE_LINE.match(line)
        if not match:
            continue
        domain = _normalize_domain(match.group(1))
        if domain and domain not in ("localhost", "local"):
            domains.add(domain)
    return domains


def parse_domain_list(text: str) -> set[str]:
    """Parses a plain newline-delimited domain list (one domain per line, no IP
    prefix). Strips trailing '# comment' annotations some maintainers append
    after the domain (e.g. ShadowWhisperer's 'domain.com   #Gore')."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        domain = _normalize_domain(line)
        if domain and _PLAIN_DOMAIN_LINE.match(domain):
            domains.add(domain)
    return domains


PARSERS = {
    "hostfile": parse_hostfile,
    "domain-list": parse_domain_list,
}
