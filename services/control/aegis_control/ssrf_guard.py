"""SSRF guard: validates URLs before server-side fetch.

Blocks RFC-1918, loopback, and link-local targets; rejects non-HTTP(S) schemes.
DNS resolution is performed at validation time so hostnames that map to internal
addresses are caught. This is not immune to DNS-rebinding attacks but eliminates
the most common SSRF vectors (misconfigured feed/webhook URLs pointing at internal
services or cloud metadata endpoints).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

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

    # Fast path: host is a numeric IP literal — no DNS needed.
    literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass

    if literal is not None:
        if _ip_is_blocked(str(literal)):
            raise ValueError(f"URL host {host!r} is a private or reserved address")
        return

    # Hostname: resolve and check every address returned.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        raise ValueError(f"URL host {host!r} could not be resolved — refusing fetch")

    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = str(sockaddr[0])
        if _ip_is_blocked(ip_str):
            raise ValueError(
                f"URL host {host!r} resolves to private/reserved address {ip_str!r}"
            )
