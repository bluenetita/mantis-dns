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
    """Parses a plain newline-delimited domain list (one domain per line, no IP prefix)."""
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = _normalize_domain(line)
        if domain and _PLAIN_DOMAIN_LINE.match(domain):
            domains.add(domain)
    return domains


PARSERS = {
    "hostfile": parse_hostfile,
    "domain-list": parse_domain_list,
}
