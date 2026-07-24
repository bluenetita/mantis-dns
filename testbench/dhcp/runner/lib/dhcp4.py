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

"""DHCPv4 client helper: builds/sends/receives real DORA (+RELEASE/DECLINE/
INFORM) packets against mantis-dhcp over plain UDP sockets.

mantis-dhcp never needs a raw socket itself (server.rs's module docs: OFFER/
ACK go out as plain broadcast or unicast UDP, RFC 2131 §4.1) — so a plain
`socket.SOCK_DGRAM` client exercises exactly the same code path a real one
does. scapy's BOOTP/DHCP layers are used only as a wire-format (en/de)coder.
"""
from __future__ import annotations

import random
import socket
import struct
import threading
import time

from scapy.layers.dhcp import BOOTP, DHCP

# DHCP message-type option (53) values (RFC 2131 §9.6) -- scapy decodes this
# option to its raw int, not the "discover"/"offer"/... name it accepts on
# encode, so replies are matched against these.
DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)


def random_mac() -> str:
    # 02:xx:... -- locally administered, unicast -- never collides with a
    # real vendor OUI a container/host NIC might also be using.
    octets = [0x02] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{o:02x}" for o in octets)


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


class Client:
    """One simulated DHCP client identity (its own MAC + xid stream)."""

    def __init__(self, mac: str | None = None):
        self.mac = mac or random_mac()
        self.chaddr = mac_to_bytes(self.mac) + b"\x00" * 10  # chaddr is a fixed 16 bytes

    def _xid(self) -> int:
        return random.randint(1, 0xFFFFFFFF)

    def _base(self, msg_type: str, xid: int, *, ciaddr="0.0.0.0", giaddr="0.0.0.0", options=None):
        opts = [("message-type", msg_type)]
        if options:
            opts.extend(options)
        opts.append("end")
        pkt = BOOTP(
            op=1, htype=1, hlen=6, xid=xid, ciaddr=ciaddr, giaddr=giaddr, chaddr=self.chaddr,
        ) / DHCP(options=opts)
        return pkt

    def discover(self, xid: int | None = None, giaddr="0.0.0.0", options=None) -> tuple[int, bytes]:
        xid = xid or self._xid()
        return xid, bytes(self._base("discover", xid, giaddr=giaddr, options=options))

    def request(self, xid: int, *, requested_ip=None, server_id=None, ciaddr="0.0.0.0",
                giaddr="0.0.0.0", options=None) -> bytes:
        opts = list(options or [])
        if requested_ip:
            opts.append(("requested_addr", requested_ip))
        if server_id:
            opts.append(("server_id", server_id))
        return bytes(self._base("request", xid, ciaddr=ciaddr, giaddr=giaddr, options=opts))

    def release(self, ciaddr: str, server_id: str) -> bytes:
        return bytes(self._base("release", self._xid(), ciaddr=ciaddr, options=[("server_id", server_id)]))

    def decline(self, requested_ip: str, server_id: str) -> bytes:
        return bytes(self._base(
            "decline", self._xid(), options=[("requested_addr", requested_ip), ("server_id", server_id)]
        ))

    def inform(self, ciaddr: str) -> bytes:
        return bytes(self._base("inform", self._xid(), ciaddr=ciaddr))


def _decode(data: bytes):
    pkt = BOOTP(data)
    dhcp = pkt.getlayer(DHCP)
    opts = {}
    if dhcp is not None:
        for opt in dhcp.options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                # scapy represents a multi-value option (e.g. two DNS
                # servers) as a flat variadic tuple, ('name_server', ip1,
                # ip2) -- always stored as a list here so callers don't have
                # to special-case the single-value ('router', ip) shape.
                opts[opt[0]] = list(opt[1:]) if len(opt) > 2 else opt[1]
    return pkt, opts


def exchange(payload: bytes, dest: tuple[str, int], xid: int, listen_addr: tuple[str, int],
             timeout: float = 3.0, attempts: int = 3):
    """Sends `payload` to `dest`, listens on `listen_addr` for a reply whose
    BOOTP xid matches, retrying `attempts` times (UDP, no delivery guarantee).
    Returns (BOOTP packet, {option_name: value}) or (None, {}) on timeout."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(listen_addr)
        s.settimeout(timeout)
        for _ in range(attempts):
            s.sendto(payload, dest)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                s.settimeout(max(remaining, 0.01))
                try:
                    data, _src = s.recvfrom(2048)
                except socket.timeout:
                    break
                if len(data) < 240:
                    continue
                got_xid = struct.unpack("!I", data[4:8])[0]
                if got_xid != xid:
                    continue
                return _decode(data)
        return None, {}


class Responder:
    """One shared listener multiplexing many concurrent clients over a
    single UDP socket, matched by BOOTP xid -- needed because mantis-dhcp
    always broadcasts its reply to port 68 regardless of the request's
    source port (server.rs's `reply_dest`), so many simulated clients in one
    container can't each bind their own port 68 and expect to be the one the
    kernel happens to deliver a given reply to. Used by the HA phase, where
    testing real cross-instance concurrency needs many in-flight requests at
    once."""

    def __init__(self, listen_addr: tuple[str, int] = ("0.0.0.0", 68)):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(listen_addr)
        self.sock.settimeout(0.5)
        self._waiters: dict[int, tuple[threading.Event, list]] = {}
        self._lock = threading.Lock()
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running:
            try:
                data, _src = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 240:
                continue
            xid = struct.unpack("!I", data[4:8])[0]
            with self._lock:
                waiter = self._waiters.get(xid)
            if waiter is not None:
                event, box = waiter
                box[0] = _decode(data)
                event.set()

    def request(self, payload: bytes, dest: tuple[str, int], xid: int, timeout: float = 3.0, attempts: int = 5):
        event = threading.Event()
        box = [None]
        with self._lock:
            self._waiters[xid] = (event, box)
        try:
            for _ in range(attempts):
                self.sock.sendto(payload, dest)
                if event.wait(timeout / attempts):
                    return box[0]
            return None, {}
        finally:
            with self._lock:
                self._waiters.pop(xid, None)

    def close(self) -> None:
        self._running = False
        self._thread.join(timeout=2)
        self.sock.close()
