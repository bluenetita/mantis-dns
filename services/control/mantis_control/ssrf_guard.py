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

"""SSRF guard: validates URLs before server-side fetch.

Blocks RFC-1918, loopback, and link-local targets; rejects non-HTTP(S) schemes.
DNS resolution is performed at validation time so hostnames that map to internal
addresses are caught.

`check_url_safe` / `check_host_safe` are point-in-time checks — a hostname could
re-resolve to a different (unsafe) address between validation and the actual
connect (DNS rebinding). `resolve_pinned_url` closes that gap for outbound HTTP
fetches: it validates and resolves once, then returns a URL with the host
replaced by the validated IP literal, plus the original hostname to use as the
`Host` header and TLS SNI (`extensions={"sni_hostname": ...}`) — the connection
goes to the IP we checked, not to whatever the resolver returns a second time.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),      # RFC-1918
    ipaddress.ip_network("172.16.0.0/12"),   # RFC-1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC-1918
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / GCP metadata adjacency
    ipaddress.ip_network("0.0.0.0/8"),       # "this" network
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),        # IPv6 unique-local (ULA)
]


def _ip_is_blocked(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block
    return any(addr in net for net in _BLOCKED_NETWORKS)


# Narrower blocklist for admin-configured DNS resolver probe targets, where
# RFC-1918/ULA addresses are a legitimate, common configuration (private
# upstream resolvers). Only loopback and link-local/cloud-metadata ranges are
# blocked — those are never a legitimate DNS resolver, only useful for
# attacking the control-plane host itself or a cloud metadata endpoint.
_LOOPBACK_AND_METADATA_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _ip_is_loopback_or_metadata(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return any(addr in net for net in _LOOPBACK_AND_METADATA_NETWORKS)


def check_probe_target_safe(host: str) -> None:
    """Raise ValueError if *host* is a loopback or link-local/metadata address.

    Used for admin-configured DNS resolver probe targets — see module note
    above for why this is deliberately narrower than `check_host_safe`.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_loopback_or_metadata(str(literal)):
            raise ValueError(f"host {host!r} is a loopback or link-local/metadata address")
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise ValueError(f"host {host!r} could not be resolved — refusing probe")

    for _family, _type, _proto, _canon, sockaddr in infos:
        if _ip_is_loopback_or_metadata(str(sockaddr[0])):
            raise ValueError(
                f"host {host!r} resolves to a loopback or link-local/metadata address"
            )


def _safe_resolved_ips(host: str) -> list[tuple[socket.AddressFamily, str]]:
    """Resolves *host*, returning (family, ip) pairs that pass the blocklist.

    Raises ValueError if resolution fails or every address is blocked.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise ValueError(f"host {host!r} could not be resolved — refusing fetch")

    safe = [
        (family, str(sockaddr[0]))
        for family, _type, _proto, _canon, sockaddr in infos
        if not _ip_is_blocked(str(sockaddr[0]))
    ]
    if not safe:
        raise ValueError(f"host {host!r} resolves only to private/reserved addresses")
    return safe


def check_host_safe(host: str) -> None:
    """Raise ValueError if *host* (bare hostname or IP literal, no scheme) is
    unsafe to connect to — used for non-HTTP targets like DNS resolver
    addresses (do53/DoT) that aren't full URLs."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_blocked(str(literal)):
            raise ValueError(f"host {host!r} is a private or reserved address")
        return

    _safe_resolved_ips(host)  # raises if unresolvable / all-blocked


def check_url_safe(url: str) -> None:
    """Raise ValueError if *url* is unsafe for server-side HTTP fetch.

    Checks enforced:
    - scheme must be ``http`` or ``https``
    - host must not be a private/loopback/link-local IP literal
    - if host is a name, all resolved addresses must be public
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"unparseable URL: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL scheme {parsed.scheme!r} is not allowed; only http and https are permitted"
        )

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host component")

    check_host_safe(host)


def resolve_pinned_url(url: str) -> tuple[str, str]:
    """Validates *url* like `check_url_safe`, then returns
    `(pinned_url, original_host)`: *pinned_url* has its host replaced with one
    validated-safe resolved IP literal (or is unchanged if the host was
    already an IP literal). Callers should send the request to *pinned_url*
    with a `Host: {original_host}` header and, for https, pass
    `extensions={"sni_hostname": original_host}` so TLS SNI/certificate
    verification still targets the real hostname.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"unparseable URL: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL scheme {parsed.scheme!r} is not allowed; only http and https are permitted"
        )

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host component")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_blocked(str(literal)):
            raise ValueError(f"URL host {host!r} is a private or reserved address")
        return url, host

    family, ip_str = _safe_resolved_ips(host)[0]
    pinned_host = f"[{ip_str}]" if family == socket.AF_INET6 else ip_str

    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    port_part = f":{parsed.port}" if parsed.port else ""
    new_netloc = f"{userinfo}{pinned_host}{port_part}"

    pinned_url = urlunparse(parsed._replace(netloc=new_netloc))
    return pinned_url, host
