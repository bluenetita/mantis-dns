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

"""DHCPv6 (RFC 8415) client helper for mantis-dhcp6. Plain UDP/IPv6 sockets
only -- server6.rs always replies straight back to whoever sent the UDP
datagram (unicast, no giaddr-style dest computation, see its module docs),
so no multicast join is needed on the client side either: a direct unicast
SOLICIT to the server's bound [::]:547 gets a direct unicast reply on the
same socket. scapy's DHCP6 layers are used only as a wire-format codec."""
from __future__ import annotations

import random
import socket

from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_Confirm,
    DHCP6_Decline,
    DHCP6_InfoRequest,
    DHCP6_RelayForward,
    DHCP6_RelayReply,
    DHCP6_Release,
    DHCP6_Renew,
    DHCP6_Rebind,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptElapsedTime,
    DHCP6OptIA_NA,
    DHCP6OptIA_PD,
    DHCP6OptIAAddress,
    DHCP6OptIAPrefix,
    DHCP6OptRelayMsg,
    DHCP6OptServerId,
    DHCP6OptStatusCode,
    DUID_LL,
)
from scapy.packet import Raw


def random_duid() -> DUID_LL:
    mac = [0x02] + [random.randint(0, 255) for _ in range(5)]
    return DUID_LL(lladdr=":".join(f"{o:02x}" for o in mac))


class Client:
    """One simulated DHCPv6 client identity (its own DUID + IAID stream)."""

    def __init__(self, duid: DUID_LL | None = None, iaid: int | None = None):
        self.duid = duid or random_duid()
        self.cid = DHCP6OptClientId(duid=self.duid)
        self.iaid = iaid or random.randint(1, 0xFFFFFFFF)
        self.server_id_bytes: bytes | None = None  # captured from the first ADVERTISE/REPLY

    def _sid_opt(self):
        assert self.server_id_bytes is not None, "call solicit() (or set server_id_bytes) before this"
        return DHCP6OptServerId(duid=Raw(load=self.server_id_bytes))

    def solicit(self, want_na: bool = True, want_pd: bool = False, trid: int | None = None) -> bytes:
        trid = trid if trid is not None else random.randint(0, 0xFFFFFF)
        pkt = DHCP6_Solicit(trid=trid) / self.cid / DHCP6OptElapsedTime()
        if want_na:
            pkt /= DHCP6OptIA_NA(iaid=self.iaid)
        if want_pd:
            pkt /= DHCP6OptIA_PD(iaid=self.iaid)
        return bytes(pkt)

    def request_like(self, msg_cls, *, want_addr: str | None = None, want_prefix: tuple[str, int] | None = None,
                      include_ia_na: bool = True, include_ia_pd: bool = False, trid: int | None = None) -> bytes:
        trid = trid if trid is not None else random.randint(0, 0xFFFFFF)
        pkt = msg_cls(trid=trid) / self.cid / self._sid_opt() / DHCP6OptElapsedTime()
        if include_ia_na:
            na = DHCP6OptIA_NA(iaid=self.iaid)
            if want_addr:
                na.ianaopts = [DHCP6OptIAAddress(addr=want_addr)]
            pkt /= na
        if include_ia_pd:
            pd = DHCP6OptIA_PD(iaid=self.iaid)
            if want_prefix:
                prefix, plen = want_prefix
                pd.iapdopt = [DHCP6OptIAPrefix(prefix=prefix, plen=plen)]
            pkt /= pd
        return bytes(pkt)

    def request(self, **kw) -> bytes:
        return self.request_like(DHCP6_Request, **kw)

    def renew(self, **kw) -> bytes:
        return self.request_like(DHCP6_Renew, **kw)

    def rebind(self, **kw) -> bytes:
        # RFC 8415 §18.2.5: REBIND carries no Server Identifier (the client
        # no longer trusts/hears its old server) -- unlike REQUEST/RENEW.
        trid = random.randint(0, 0xFFFFFF)
        pkt = DHCP6_Rebind(trid=trid) / self.cid / DHCP6OptElapsedTime() / DHCP6OptIA_NA(iaid=self.iaid)
        return bytes(pkt)

    def release(self) -> bytes:
        trid = random.randint(0, 0xFFFFFF)
        pkt = DHCP6_Release(trid=trid) / self.cid / self._sid_opt() / DHCP6OptElapsedTime() / DHCP6OptIA_NA(iaid=self.iaid)
        return bytes(pkt)

    def decline(self, addr: str) -> bytes:
        trid = random.randint(0, 0xFFFFFF)
        na = DHCP6OptIA_NA(iaid=self.iaid, ianaopts=[DHCP6OptIAAddress(addr=addr)])
        pkt = DHCP6_Decline(trid=trid) / self.cid / self._sid_opt() / DHCP6OptElapsedTime() / na
        return bytes(pkt)

    def information_request(self) -> bytes:
        trid = random.randint(0, 0xFFFFFF)
        return bytes(DHCP6_InfoRequest(trid=trid) / self.cid / DHCP6OptElapsedTime())

    def confirm(self, addr: str) -> bytes:
        trid = random.randint(0, 0xFFFFFF)
        na = DHCP6OptIA_NA(iaid=self.iaid, ianaopts=[DHCP6OptIAAddress(addr=addr)])
        return bytes(DHCP6_Confirm(trid=trid) / self.cid / DHCP6OptElapsedTime() / na)

    def remember_server_id(self, reply_pkt) -> None:
        opt = reply_pkt.getlayer(DHCP6OptServerId)
        if opt is not None:
            self.server_id_bytes = bytes(opt.duid)


def wrap_relay(inner: bytes, link_addr: str, peer_addr: str, hop_count: int = 0) -> bytes:
    """Wraps a client message as a single-hop RELAY-FORW -- the "an admin's
    relay agent forwarded this" case (design.md §22.7/§22.9). The reply
    always comes back RELAY-REPL-wrapped around the same hop (server6.rs's
    `wrap_relay_reply`) and unwraps with `unwrap_relay_reply` below."""
    return bytes(DHCP6_RelayForward(hopcount=hop_count, linkaddr=link_addr, peeraddr=peer_addr) / DHCP6OptRelayMsg(message=inner))


def unwrap_relay_reply(data: bytes) -> bytes | None:
    pkt = DHCP6_RelayReply(data)
    msg = pkt.getlayer(DHCP6OptRelayMsg)
    if msg is None:
        return None
    # scapy auto-decodes RelayMsg's payload into a typed Packet (based on its
    # own msgtype byte) rather than leaving it as raw bytes -- reserialize so
    # callers get the same bytes-in/bytes-out shape `decode()` elsewhere uses.
    return bytes(msg.message)


# msgtype byte -> reply class, for decoding a raw response of unknown type.
_REPLY_CLASSES = {
    2: DHCP6_Advertise,
    7: DHCP6_Reply,
    13: DHCP6_RelayReply,
}


def decode(data: bytes):
    if not data:
        return None
    cls = _REPLY_CLASSES.get(data[0])
    if cls is None:
        return None
    return cls(data)


def status_of(ia_layer) -> tuple[int | None, str]:
    """Reads STATUS_CODE (0 = Success when absent, per RFC 8415 §21.13) out
    of an IA_NA/IA_PD option's nested options."""
    sc = ia_layer.getlayer(DHCP6OptStatusCode)
    if sc is None:
        return None, ""
    msg = sc.statusmsg
    return int(sc.statuscode), (msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg))


def send_recv(payload: bytes, dest: tuple[str, int], local_addr: tuple[str, int, int, int],
              timeout: float = 3.0, attempts: int = 3) -> bytes | None:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(local_addr)
        s.settimeout(timeout)
        for _ in range(attempts):
            s.sendto(payload, dest)
            try:
                data, _src = s.recvfrom(2048)
                return data
            except socket.timeout:
                continue
        return None
