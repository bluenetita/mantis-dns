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

"""DHCP testbench test runner (design.md §22). Invoked per-phase by
scripts/dhcp_testbench.sh, e.g.:

    docker compose run --rm runner python run_all.py --phase core

Phases share state (created tenant/zone/scope ids, etc.) via /state/run.json
-- a bind mount, so it survives across the separate container runs each
phase is (`docker compose run` starts a fresh container every time).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from lib import api as api_mod, dhcp4, dhcp6  # noqa: E402

DHCP_IP = os.environ["DHCP_IP"]
DHCP_HA_IP = os.environ.get("DHCP_HA_IP", "")
DHCP6_IP = os.environ["DHCP6_IP"]
METRICS_URL = os.environ["METRICS_URL"]
METRICS_HA_URL = os.environ.get("METRICS_HA_URL", "")
METRICS6_URL = os.environ["METRICS6_URL"]
RUNNER_IPV4 = os.environ["RUNNER_IPV4"]
RUNNER_IPV6 = os.environ["RUNNER_IPV6"]

STATE_PATH = Path("/state/run.json")
CONFIG_REFRESH_WAIT_S = 12  # mantis-dhcp/6 re-read scopes/reservations/etc. every 10s


def load_state() -> dict:
    return json.loads(STATE_PATH.read_text())


def save_state(d: dict) -> None:
    STATE_PATH.write_text(json.dumps(d, indent=2))


# ── tiny pass/fail framework ────────────────────────────────────────────────

_results: list[tuple[str, bool, str]] = []


def check(name: str, fn) -> None:
    try:
        fn()
        _results.append((name, True, ""))
        print(f"  PASS  {name}")
    except AssertionError as e:
        _results.append((name, False, str(e)))
        print(f"  FAIL  {name}: {e}")
    except Exception as e:  # noqa: BLE001 - want every failure recorded, not just AssertionError
        _results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"  ERROR {name}: {type(e).__name__}: {e}")


def summary_and_exit() -> None:
    failed = [r for r in _results if not r[1]]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} passed")
    for name, _, msg in failed:
        print(f"  - {name}: {msg}")
    sys.exit(1 if failed else 0)


# ── Prometheus text-exposition helpers ──────────────────────────────────────

def fetch_metrics(url: str) -> str:
    import requests
    return requests.get(url, timeout=5).text


def counter_value(text: str, name: str) -> int:
    m = re.search(rf"^{re.escape(name)} (\d+)$", text, re.MULTILINE)
    assert m, f"metric {name} not found in:\n{text}"
    return int(m.group(1))


def gauge_for_label(text: str, name: str, label_substr: str) -> int:
    for line in text.splitlines():
        if line.startswith(f"{name}{{") and label_substr in line:
            return int(line.rsplit(" ", 1)[1])
    raise AssertionError(f"no {name} line containing {label_substr!r} in:\n{text}")


# ── v4 helpers ───────────────────────────────────────────────────────────────

V4_BROADCAST = ("255.255.255.255", 67)


def v4_dora(client: dhcp4.Client, *, giaddr="0.0.0.0", request_options=None, discover_options=None):
    """Full DISCOVER->OFFER->REQUEST->ACK/NAK over broadcast. Returns
    (offer_pkt, offer_opts, ack_pkt, ack_opts)."""
    xid, disc = client.discover(giaddr=giaddr, options=discover_options)
    offer_pkt, offer_opts = dhcp4.exchange(disc, V4_BROADCAST, xid, ("0.0.0.0", 68))
    assert offer_pkt is not None, "no OFFER received"
    assert offer_opts.get("message-type") == dhcp4.OFFER, f"expected OFFER, got {offer_opts.get('message-type')}"

    req = client.request(
        xid, requested_ip=offer_pkt.yiaddr, server_id=offer_opts["server_id"],
        giaddr=giaddr, options=request_options,
    )
    ack_pkt, ack_opts = dhcp4.exchange(req, V4_BROADCAST, xid, ("0.0.0.0", 68))
    return offer_pkt, offer_opts, ack_pkt, ack_opts


# ── setup ────────────────────────────────────────────────────────────────────

def phase_setup() -> None:
    a = api_mod.Api()
    a.login()

    tenant_id = a.create_tenant("dhcp-testbench")
    zone_id = a.create_zone(tenant_id, "dhcptest.local")

    scope = a.create_scope(
        tenant_id=tenant_id, name="scope-a", subnet="172.30.0.0/24",
        range_start="172.30.0.100", range_end="172.30.0.140",
        router_ip="172.30.0.1", dns_servers=["8.8.8.8", "1.1.1.1"],
        domain_name="dhcptest.local", lease_time_s=60,
        ddns_enabled=True, ddns_zone_id=zone_id, ddns_ttl_s=120,
        pxe_next_server="172.30.0.6", pxe_boot_filename="pxelinux.0",
        pxe_uefi_boot_filename="shimx64.efi",
    )
    reservation = a.create_reservation(
        scope["id"], mac_address="02:00:00:00:00:01", ip_address="172.30.0.150",
        hostname="reserved-host", next_server="172.30.0.7", uefi_boot_filename="custom-uefi.efi",
    )
    a.create_option(scope["id"], option_code=15, value="override.local")
    a.create_option(scope["id"], option_code=224, value="0xdeadbeef", always_send=True)
    a.create_option(scope["id"], option_code=66, value="tftp.dhcptest.local")

    v6_duid = dhcp6.random_duid()  # reuse below as the reserved v6 client's fixed identity
    v6_duid_hex = bytes(v6_duid).hex()
    scope6 = a.create_scope6(
        tenant_id=tenant_id, name="scope-a6", subnet="fd00:6d61:6e74:6973::/64",
        pool_start="fd00:6d61:6e74:6973::100", pool_end="fd00:6d61:6e74:6973::1ff",
        pd_prefix="fd00:6d61:6e74:beef::", pd_prefix_len=64,
        dns_servers=["fd00:6d61:6e74:6973::53"], domain_name="dhcptest6.local",
        preferred_lifetime_s=60, valid_lifetime_s=90,
        ddns_enabled=True, ddns_zone_id=zone_id, ddns_ttl_s=120,
    )
    reservation6 = a.create_reservation6(
        scope6["id"], duid=v6_duid_hex, ip_address="fd00:6d61:6e74:6973::150", hostname="reserved-host6",
    )

    save_state({
        "tenant_id": tenant_id,
        "zone_id": zone_id,
        "scope_id": scope["id"],
        "reservation_mac": "02:00:00:00:00:01",
        "reservation_ip": "172.30.0.150",
        "scope6_id": scope6["id"],
        "reservation6_duid_hex": v6_duid_hex,
        "reservation6_ip": "fd00:6d61:6e74:6973::150",
    })
    print(f"waiting {CONFIG_REFRESH_WAIT_S}s for mantis-dhcp/6's config-refresh tick...")
    time.sleep(CONFIG_REFRESH_WAIT_S)
    print("setup complete:", json.dumps(load_state(), indent=2))


# ── core (DHCPv4) ────────────────────────────────────────────────────────────

def phase_core() -> None:
    st = load_state()
    a = api_mod.Api()
    a.login()
    scope_id = st["scope_id"]

    def t_conflict_detection():
        c = dhcp4.Client()
        xid, disc = c.discover()
        offer, opts = dhcp4.exchange(disc, V4_BROADCAST, xid, ("0.0.0.0", 68))
        assert offer is not None, "no OFFER received"
        assert offer.yiaddr != "172.30.0.100", "squatted address was offered -- conflict probe didn't exclude it"
        declined = a.list_leases(scope_id, state=1)
        assert any(r["ip_address"] == "172.30.0.100" for r in declined), \
            f"172.30.0.100 not recorded as declined: {declined}"

    def t_basic_dora_and_options():
        c = dhcp4.Client()
        offer, offer_opts, ack, ack_opts = v4_dora(c, request_options=[("hostname", "client-a")])
        assert ack_opts.get("message-type") == dhcp4.ACK, f"expected ACK, got {ack_opts}"
        assert ack.yiaddr == offer.yiaddr
        assert offer_opts["subnet_mask"] == "255.255.255.0"
        assert offer_opts["router"] == "172.30.0.1"
        assert set(offer_opts["name_server"]) == {"8.8.8.8", "1.1.1.1"}
        assert offer_opts["domain"] == b"override.local", \
            f"scope-level custom option 15 should override domain_name, got {offer_opts.get('domain')!r}"
        assert offer_opts["lease_time"] == 60
        assert offer_opts["renewal_time"] == 30
        assert offer_opts["rebinding_time"] == 52  # 60*7/8, truncated (server.rs uses integer math)
        assert offer_opts["server_id"] == DHCP_IP
        assert offer_opts[224] == bytes.fromhex("deadbeef")
        assert offer_opts["tftp_server_name"] == b"tftp.dhcptest.local"

        leases = a.list_leases(scope_id, state=0)
        assert any(r["ip_address"] == ack.yiaddr and r["mac_address"] == c.mac for r in leases), \
            f"no active lease for {c.mac}/{ack.yiaddr}: {leases}"

        record = _poll(lambda: _find_record(a, st["zone_id"], "client-a", "A"), timeout=10)
        assert record is not None, "DDNS A record for client-a was never created"
        assert record["data"] == ack.yiaddr

        st["client_a_mac"] = c.mac
        st["client_a_ip"] = ack.yiaddr
        save_state(st)

    def t_ddns_ownership_hijack_rejected():
        c2 = dhcp4.Client()
        _offer, _oo, ack2, ack2_opts = v4_dora(c2, request_options=[("hostname", "client-a")])
        assert ack2_opts.get("message-type") == dhcp4.ACK
        assert ack2.yiaddr != st["client_a_ip"], "second client must get a different dynamic address"
        record = _find_record(a, st["zone_id"], "client-a", "A")
        assert record is not None
        assert record["data"] == st["client_a_ip"], \
            f"DDNS record was hijacked by a second client's REQUEST (now {record['data']!r})"

    def t_release_deletes_lease_and_ddns_record():
        c = dhcp4.Client(mac=st["client_a_mac"])
        release_pkt = c.release(st["client_a_ip"], DHCP_IP)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(release_pkt, (DHCP_IP, 67))
        record = _poll(lambda: None if _find_record(a, st["zone_id"], "client-a", "A") else True, timeout=10)
        assert record, "DDNS A record for client-a was not removed after RELEASE"
        leases = a.list_leases(scope_id, state=0)
        assert not any(r["mac_address"] == st["client_a_mac"] for r in leases), \
            "lease still active after RELEASE"

    def t_decline_moves_lease_to_state1():
        c = dhcp4.Client()
        _offer, _oo, ack, ack_opts = v4_dora(c)
        assert ack_opts.get("message-type") == dhcp4.ACK
        decline_pkt = c.decline(ack.yiaddr, DHCP_IP)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(decline_pkt, (DHCP_IP, 67))
        time.sleep(1)
        active = a.list_leases(scope_id, state=0)
        assert not any(r["ip_address"] == ack.yiaddr for r in active), "declined ip still shows active"
        declined = a.list_leases(scope_id, state=1)
        assert any(r["ip_address"] == ack.yiaddr for r in declined), "declined ip not recorded as state=1"

    def t_renew_extends_existing_lease():
        c = dhcp4.Client()
        _offer, _oo, ack, ack_opts = v4_dora(c)
        assert ack_opts.get("message-type") == dhcp4.ACK
        c2 = dhcp4.Client(mac=c.mac)
        # RENEWING per db::allocate's "no requested IP -> renew existing row"
        # path: no requested_addr option and no ciaddr means `want=None`
        # server-side, which is what actually selects this path -- ciaddr
        # would normally carry it too, but our client never configures the
        # address at the OS level, so a real ciaddr-addressed unicast reply
        # would go nowhere; broadcast (the ciaddr=0 default) is what a
        # scriptable client without a live IP can actually receive.
        xid2 = c2._xid()
        renew = c2.request(xid2)
        xid = struct_xid(renew)
        renew_ack, renew_opts = dhcp4.exchange(renew, V4_BROADCAST, xid, ("0.0.0.0", 68))
        assert renew_opts.get("message-type") == dhcp4.ACK, f"RENEW rejected: {renew_opts}"
        assert renew_ack.yiaddr == ack.yiaddr, "RENEW returned a different address than the existing lease"

    def t_pxe_scope_defaults_bios_and_uefi():
        bios = dhcp4.Client()
        offer_b, _, ack_b, ackopt_b = v4_dora(bios)
        assert ackopt_b.get("message-type") == dhcp4.ACK
        assert _bootfile(ack_b) == "pxelinux.0"
        assert ack_b.siaddr == "172.30.0.6"

        uefi = dhcp4.Client()
        offer_u, _, ack_u, ackopt_u = v4_dora(uefi, discover_options=[(93, b"\x00\x09")],
                                               request_options=[(93, b"\x00\x09")])
        assert ackopt_u.get("message-type") == dhcp4.ACK
        assert _bootfile(ack_u) == "shimx64.efi"

    def t_pxe_reservation_overrides():
        res = dhcp4.Client(mac=st["reservation_mac"])
        offer, offer_opts, ack, ack_opts = v4_dora(res)
        assert ack.yiaddr == st["reservation_ip"], "reserved mac did not get its reserved ip"
        assert ack.siaddr == "172.30.0.7", "reservation next_server did not override scope default"
        assert _bootfile(ack) == "pxelinux.0", \
            "reservation has no BIOS boot_filename set -- must fall back to the scope default unchanged"

        res_uefi = dhcp4.Client(mac=st["reservation_mac"])
        _o, _oo, ack_u, ackopt_u = v4_dora(res_uefi, discover_options=[(93, b"\x00\x09")],
                                            request_options=[(93, b"\x00\x09")])
        assert ack_u.yiaddr == st["reservation_ip"]
        assert _bootfile(ack_u) == "custom-uefi.efi", "reservation uefi_boot_filename did not override the scope's"

    def t_request_mismatched_ip_for_reservation_is_naked():
        c = dhcp4.Client(mac=st["reservation_mac"])
        xid, disc = c.discover()
        offer, offer_opts = dhcp4.exchange(disc, V4_BROADCAST, xid, ("0.0.0.0", 68))
        assert offer.yiaddr == st["reservation_ip"]
        req = c.request(xid, requested_ip="172.30.0.111", server_id=offer_opts["server_id"])
        reply, reply_opts = dhcp4.exchange(req, V4_BROADCAST, xid, ("0.0.0.0", 68))
        assert reply_opts.get("message-type") == dhcp4.NAK, \
            f"expected NAK when a reserved mac REQUESTs a different ip, got {reply_opts}"

    def t_request_out_of_pool_is_naked():
        c = dhcp4.Client()
        xid = c._xid()
        req = c.request(xid, requested_ip="172.30.0.5", server_id=DHCP_IP)
        reply, reply_opts = dhcp4.exchange(req, V4_BROADCAST, xid, ("0.0.0.0", 68))
        assert reply_opts.get("message-type") == dhcp4.NAK, \
            f"expected NAK for an out-of-pool REQUEST, got {reply_opts}"

    def t_relay_subnet_fallback_before_any_relay_config():
        c = dhcp4.Client()
        xid, disc = c.discover(giaddr=RUNNER_IPV4)
        offer, offer_opts = dhcp4.exchange(disc, (DHCP_IP, 67), xid, (RUNNER_IPV4, 67))
        assert offer is not None, "relayed DISCOVER (subnet-containment fallback) got no OFFER"
        assert offer_opts.get("message-type") == dhcp4.OFFER

    def t_relay_allowlist():
        before = counter_value(fetch_metrics(METRICS_URL), "dhcp_offer_total")
        relay = a.create_relay(scope_id, relay_ip=RUNNER_IPV4, description="testbench relay")
        st["relay_id"] = relay["id"]
        save_state(st)
        time.sleep(CONFIG_REFRESH_WAIT_S)

        # Allow-listed giaddr still gets served.
        c1 = dhcp4.Client()
        xid1, disc1 = c1.discover(giaddr=RUNNER_IPV4)
        offer1, opts1 = dhcp4.exchange(disc1, (DHCP_IP, 67), xid1, (RUNNER_IPV4, 67))
        assert offer1 is not None and opts1.get("message-type") == dhcp4.OFFER, \
            "allow-listed relay giaddr was rejected"

        # A different giaddr on the same subnet, with an allow-list now
        # configured, must be rejected outright -- not matched via the
        # subnet-containment fallback (design.md §22.12). No listener owns
        # .21 so absence-of-reply alone wouldn't prove rejection; the
        # dhcp_offer_total counter is the unambiguous signal instead.
        c2 = dhcp4.Client()
        xid2, disc2 = c2.discover(giaddr="172.30.0.21")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(disc2, (DHCP_IP, 67))
        time.sleep(1)
        after = counter_value(fetch_metrics(METRICS_URL), "dhcp_offer_total")
        assert after == before + 1, \
            f"unauthorised relay giaddr got served (offer_total {before}->{after}, expected +1 from the allow-listed request only)"

    def t_relay_circuit_remote_id_enforcement():
        a.update_relay_via_replace(
            scope_id, st["relay_id"], relay_ip=RUNNER_IPV4,
            circuit_id_hex="0x0102", remote_id_hex="0xaabb",
        )
        time.sleep(CONFIG_REFRESH_WAIT_S)

        before = counter_value(fetch_metrics(METRICS_URL), "dhcp_offer_total")
        c1 = dhcp4.Client()
        xid1, disc1 = c1.discover(giaddr=RUNNER_IPV4)  # no option 82 at all
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(disc1, (DHCP_IP, 67))
        time.sleep(1)
        after = counter_value(fetch_metrics(METRICS_URL), "dhcp_offer_total")
        assert after == before, "relay_ip match alone served a request that required a circuit/remote id"

        rai_mismatch = bytes([1, 2, 0x01, 0x02, 2, 2, 0xff, 0xff])  # wrong remote id
        c2 = dhcp4.Client()
        xid2, disc2 = c2.discover(giaddr=RUNNER_IPV4, options=[(82, rai_mismatch)])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(disc2, (DHCP_IP, 67))
        time.sleep(1)
        after2 = counter_value(fetch_metrics(METRICS_URL), "dhcp_offer_total")
        assert after2 == before, "mismatched option-82 remote-id was accepted"

        rai_match = bytes([1, 2, 0x01, 0x02, 2, 2, 0xaa, 0xbb])
        c3 = dhcp4.Client()
        xid3, disc3 = c3.discover(giaddr=RUNNER_IPV4, options=[(82, rai_match)])
        offer3, opts3 = dhcp4.exchange(disc3, (DHCP_IP, 67), xid3, (RUNNER_IPV4, 67))
        assert offer3 is not None and opts3.get("message-type") == dhcp4.OFFER, \
            "matching relay_ip + circuit/remote id was rejected"

    def t_inform_reply():
        c = dhcp4.Client()
        pkt = c.inform(RUNNER_IPV4)
        xid = struct_xid(pkt)
        reply, opts = dhcp4.exchange(pkt, (DHCP_IP, 67), xid, ("0.0.0.0", 68))
        assert reply is not None and opts.get("message-type") == dhcp4.ACK, f"INFORM got {opts}"
        assert opts.get("subnet_mask") == "255.255.255.0"

    def t_metrics_endpoint():
        text = fetch_metrics(METRICS_URL)
        for name in ("dhcp_discover_total", "dhcp_offer_total", "dhcp_request_total", "dhcp_ack_total",
                     "dhcp_nak_total", "dhcp_release_total", "dhcp_decline_total", "dhcp_inform_total",
                     "dhcp_ddns_retry_queue_depth"):
            assert re.search(rf"^{name}[ {{]", text, re.MULTILINE), f"{name} missing from /metrics"
        assert counter_value(text, "dhcp_discover_total") > 0
        assert gauge_for_label(text, "dhcp_pool_assigned", f'scope_id="{scope_id}"') >= 0

    def t_expiry_lease_created_for_later_phase():
        c = dhcp4.Client()
        _offer, _oo, ack, ack_opts = v4_dora(c, request_options=[("hostname", "expiry-host")])
        assert ack_opts.get("message-type") == dhcp4.ACK
        st["expiry_mac"] = c.mac
        st["expiry_ip"] = ack.yiaddr
        save_state(st)

    check("conflict_detection", t_conflict_detection)
    check("basic_dora_and_options", t_basic_dora_and_options)
    check("ddns_ownership_hijack_rejected", t_ddns_ownership_hijack_rejected)
    check("release_deletes_lease_and_ddns_record", t_release_deletes_lease_and_ddns_record)
    check("decline_moves_lease_to_state1", t_decline_moves_lease_to_state1)
    check("renew_extends_existing_lease", t_renew_extends_existing_lease)
    check("pxe_scope_defaults_bios_and_uefi", t_pxe_scope_defaults_bios_and_uefi)
    check("pxe_reservation_overrides", t_pxe_reservation_overrides)
    check("request_mismatched_ip_for_reservation_is_naked", t_request_mismatched_ip_for_reservation_is_naked)
    check("request_out_of_pool_is_naked", t_request_out_of_pool_is_naked)
    check("relay_subnet_fallback_before_any_relay_config", t_relay_subnet_fallback_before_any_relay_config)
    check("relay_allowlist", t_relay_allowlist)
    check("relay_circuit_remote_id_enforcement", t_relay_circuit_remote_id_enforcement)
    check("inform_reply", t_inform_reply)
    check("metrics_endpoint", t_metrics_endpoint)
    check("expiry_lease_created_for_later_phase", t_expiry_lease_created_for_later_phase)


def _bootfile(pkt) -> str:
    return pkt.file.rstrip(b"\x00").decode()


def struct_xid(payload: bytes) -> int:
    import struct
    return struct.unpack("!I", payload[4:8])[0]


def _find_record(a: api_mod.Api, zone_id: str, name: str, rtype: str):
    for r in a.list_records(zone_id):
        if r["name"] == name and r["record_type"] == rtype:
            return r
    return None


def _poll(fn, timeout: float, interval: float = 1.0):
    deadline = time.monotonic() + timeout
    result = None
    while time.monotonic() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    return result


# ── DHCPv6 ───────────────────────────────────────────────────────────────────

V6_LOCAL = (RUNNER_IPV6, 0, 0, 0)
V6_DEST = (DHCP6_IP, 547)


def phase_v6() -> None:
    st = load_state()
    a = api_mod.Api()
    a.login()
    scope6_id = st["scope6_id"]

    def send(payload: bytes):
        return dhcp6.send_recv(payload, V6_DEST, V6_LOCAL)

    def t_solicit_advertise_ia_na():
        c = dhcp6.Client()
        sol = c.solicit(want_na=True)
        data = send(sol)
        assert data is not None, "no ADVERTISE received"
        adv = dhcp6.decode(data)
        assert adv.msgtype == 2, f"expected ADVERTISE(2), got {adv.msgtype}"
        ia = adv.getlayer(dhcp6.DHCP6OptIA_NA)
        assert ia is not None
        status, _ = dhcp6.status_of(ia)
        assert status in (None, 0), f"unexpected status on ADVERTISE: {status}"
        addr = ia.getlayer(dhcp6.DHCP6OptIAAddress)
        assert addr is not None, "ADVERTISE IA_NA carried no address"
        assert addr.addr.startswith("fd00:6d61:6e74:6973:"), f"address not in pool subnet: {addr.addr}"
        assert ia.T1 == 30 and ia.T2 == 48, f"T1/T2 not the expected 0.5/0.8 fractions of preferred=60: {ia.T1}/{ia.T2}"
        c.remember_server_id(adv)
        st["v6_probe_addr"] = addr.addr
        st["v6_probe_server_id"] = c.server_id_bytes.hex()
        save_state(st)

    def t_request_reply_commits_lease():
        c = dhcp6.Client()
        sol = c.solicit(want_na=True)
        adv = dhcp6.decode(send(sol))
        c.remember_server_id(adv)
        addr = adv.getlayer(dhcp6.DHCP6OptIAAddress).addr

        req = c.request(want_addr=addr)
        data = send(req)
        assert data is not None, "no REPLY received"
        reply = dhcp6.decode(data)
        assert reply.msgtype == 7, f"expected REPLY(7), got {reply.msgtype}"
        ia = reply.getlayer(dhcp6.DHCP6OptIA_NA)
        got = ia.getlayer(dhcp6.DHCP6OptIAAddress)
        assert got is not None and got.addr == addr, "REPLY committed a different address than requested"

        leases = a.list_leases6(scope6_id, state=0)
        assert any(r["ip_address"] == addr for r in leases), f"no active v6 lease for {addr}: {leases}"

        st["client_v6_duid_hex"] = bytes(c.duid).hex()
        st["client_v6_iaid"] = c.iaid
        st["client_v6_addr"] = addr
        st["client_v6_server_id"] = c.server_id_bytes.hex()
        save_state(st)

    def t_renew_extends():
        c = _client_from_state(st)  # same identity request_reply_commits_lease committed
        renew = c.renew(want_addr=st["client_v6_addr"])
        data = send(renew)
        reply = dhcp6.decode(data)
        assert reply.msgtype == 7
        ia = reply.getlayer(dhcp6.DHCP6OptIA_NA)
        addr = ia.getlayer(dhcp6.DHCP6OptIAAddress)
        assert addr is not None and addr.addr == st["client_v6_addr"], "RENEW returned a different address"

    def t_rebind_no_server_id_needed():
        c = _client_from_state(st)
        rebind = c.rebind()  # RFC 8415 §18.2.5: no Server Identifier on REBIND
        data = send(rebind)
        reply = dhcp6.decode(data)
        assert reply.msgtype == 7, f"REBIND (no server id) should still get a REPLY, got {reply}"
        ia = reply.getlayer(dhcp6.DHCP6OptIA_NA)
        addr = ia.getlayer(dhcp6.DHCP6OptIAAddress)
        assert addr is not None and addr.addr == st["client_v6_addr"]

    def t_rebind_unknown_binding_gets_nobinding():
        c = dhcp6.Client()
        rebind = c.rebind()
        data = send(rebind)
        reply = dhcp6.decode(data)
        ia = reply.getlayer(dhcp6.DHCP6OptIA_NA)
        status, _ = dhcp6.status_of(ia)
        assert status == 3, f"expected NoBinding(3) for an unknown IA_NA on REBIND, got {status}"  # RFC 8415 §21.13

    def t_reservation_binding_and_ddns_aaaa():
        c = dhcp6.Client(duid=_duid_from_hex(st["reservation6_duid_hex"]))
        sol = c.solicit(want_na=True)
        adv = dhcp6.decode(send(sol))
        c.remember_server_id(adv)
        offered = adv.getlayer(dhcp6.DHCP6OptIAAddress).addr
        assert offered == st["reservation6_ip"], f"reserved DUID was not offered its reserved address: {offered}"

        req = c.request(want_addr=offered)
        reply = dhcp6.decode(send(req))
        assert reply.msgtype == 7
        got = reply.getlayer(dhcp6.DHCP6OptIA_NA).getlayer(dhcp6.DHCP6OptIAAddress).addr
        assert got == st["reservation6_ip"]

        # A different requested address while a reservation exists must be NoAddrsAvail.
        c2 = dhcp6.Client(duid=_duid_from_hex(st["reservation6_duid_hex"]))
        sol2 = c2.solicit(want_na=True)
        adv2 = dhcp6.decode(send(sol2))
        c2.remember_server_id(adv2)
        req2 = c2.request(want_addr="fd00:6d61:6e74:6973::199")
        reply2 = dhcp6.decode(send(req2))
        status, _ = dhcp6.status_of(reply2.getlayer(dhcp6.DHCP6OptIA_NA))
        assert status == 2, f"expected NoAddrsAvail(2) for a mismatched requested address, got {status}"

        record = _poll(lambda: _find_record(a, st["zone_id"], "reserved-host6", "AAAA"), timeout=10)
        assert record is not None, "DDNS AAAA record for the reserved v6 host was never created"
        assert record["data"] == st["reservation6_ip"]

    def t_release_removes_lease():
        c = _client_from_state(st)
        release = c.release()
        reply = dhcp6.decode(send(release))
        assert reply.msgtype == 7
        status, _ = dhcp6.status_of(reply.getlayer(dhcp6.DHCP6OptIA_NA))
        assert status == 0, f"expected Success(0) on RELEASE, got {status}"
        leases = a.list_leases6(scope6_id, state=0)
        assert not any(r["ip_address"] == st["client_v6_addr"] for r in leases), "v6 lease still active after RELEASE"

    def t_decline_moves_to_state1():
        c = dhcp6.Client()
        sol = c.solicit(want_na=True)
        adv = dhcp6.decode(send(sol))
        c.remember_server_id(adv)
        addr = adv.getlayer(dhcp6.DHCP6OptIAAddress).addr
        req = c.request(want_addr=addr)
        reply = dhcp6.decode(send(req))
        assert reply.msgtype == 7

        decline = c.decline(addr)
        reply2 = dhcp6.decode(send(decline))
        status, _ = dhcp6.status_of(reply2.getlayer(dhcp6.DHCP6OptIA_NA))
        assert status == 0

        active = a.list_leases6(scope6_id, state=0)
        assert not any(r["ip_address"] == addr for r in active)
        declined = a.list_leases6(scope6_id, state=1)
        assert any(r["ip_address"] == addr for r in declined), "declined v6 address not recorded as state=1"

    def t_ia_pd_delegation_and_single_slot():
        c = dhcp6.Client()
        sol = c.solicit(want_na=False, want_pd=True)
        adv = dhcp6.decode(send(sol))
        c.remember_server_id(adv)
        pd = adv.getlayer(dhcp6.DHCP6OptIA_PD)
        assert pd is not None
        prefix_opt = pd.getlayer(dhcp6.DHCP6OptIAPrefix)
        assert prefix_opt is not None, "no prefix offered"
        assert prefix_opt.prefix == "fd00:6d61:6e74:beef::"
        assert prefix_opt.plen == 64

        req = c.request(include_ia_na=False, include_ia_pd=True, want_prefix=("fd00:6d61:6e74:beef::", 64))
        reply = dhcp6.decode(send(req))
        got = reply.getlayer(dhcp6.DHCP6OptIA_PD).getlayer(dhcp6.DHCP6OptIAPrefix)
        assert got is not None and got.prefix == "fd00:6d61:6e74:beef::"

        # The scope has exactly one pd_prefix -- a second, different DUID
        # asking for IA_PD while it's held must get NoPrefixAvail.
        c2 = dhcp6.Client()
        sol2 = c2.solicit(want_na=False, want_pd=True)
        adv2 = dhcp6.decode(send(sol2))
        pd2 = adv2.getlayer(dhcp6.DHCP6OptIA_PD)
        status, _ = dhcp6.status_of(pd2)
        assert status == 6, f"expected NoPrefixAvail(6) once the scope's single pd_prefix is held, got {status}"

    def t_information_request():
        c = dhcp6.Client()
        info = c.information_request()
        data = send(info)
        reply = dhcp6.decode(data)
        assert reply.msgtype == 7
        assert reply.getlayer(dhcp6.DHCP6OptIA_NA) is None, "INFORMATION-REQUEST reply must not carry an IA_NA"
        from scapy.layers.dhcp6 import DHCP6OptDNSServers
        dns = reply.getlayer(DHCP6OptDNSServers)
        assert dns is not None and "fd00:6d61:6e74:6973::53" in dns.dnsservers

    def t_confirm_on_link_and_not_on_link():
        c = dhcp6.Client()
        ok = dhcp6.decode(send(c.confirm("fd00:6d61:6e74:6973::abcd")))
        status_ok, _ = dhcp6.status_of(ok)
        assert status_ok == 0, f"CONFIRM for an on-link address should be Success, got {status_ok}"

        bad = dhcp6.decode(send(c.confirm("2001:db8:dead::1")))
        status_bad, _ = dhcp6.status_of(bad)
        assert status_bad == 4, f"CONFIRM for a foreign address should be NotOnLink(4), got {status_bad}"

    def t_relay_forward_wrap_and_unwrap():
        c = dhcp6.Client()
        inner = c.solicit(want_na=True)
        wrapped = dhcp6.wrap_relay(inner, link_addr="fd00:6d61:6e74:6973::1", peer_addr="fe80::1")
        data = send(wrapped)
        assert data is not None
        assert data[0] == 13, f"expected a RELAY-REPL (13), got msg type {data[0]}"
        unwrapped = dhcp6.unwrap_relay_reply(data)
        assert unwrapped is not None and unwrapped[0] == 2, \
            f"relay-unwrapped message should be an ADVERTISE, got {unwrapped!r}"

    def t_metrics6_endpoint():
        text = fetch_metrics(METRICS6_URL)
        for name in ("dhcp6_solicit_total", "dhcp6_advertise_total", "dhcp6_request_total",
                     "dhcp6_reply_total", "dhcp6_release_total", "dhcp6_decline_total",
                     "dhcp_ddns_retry_queue_depth"):
            assert re.search(rf"^{name}[ {{]", text, re.MULTILINE), f"{name} missing from v6 /metrics"
        assert counter_value(text, "dhcp6_solicit_total") > 0

    check("solicit_advertise_ia_na", t_solicit_advertise_ia_na)
    check("request_reply_commits_lease", t_request_reply_commits_lease)
    check("renew_extends", t_renew_extends)
    check("rebind_no_server_id_needed", t_rebind_no_server_id_needed)
    check("rebind_unknown_binding_gets_nobinding", t_rebind_unknown_binding_gets_nobinding)
    check("reservation_binding_and_ddns_aaaa", t_reservation_binding_and_ddns_aaaa)
    check("decline_moves_to_state1", t_decline_moves_to_state1)
    check("release_removes_lease", t_release_removes_lease)
    check("ia_pd_delegation_and_single_slot", t_ia_pd_delegation_and_single_slot)
    check("information_request", t_information_request)
    check("confirm_on_link_and_not_on_link", t_confirm_on_link_and_not_on_link)
    check("relay_forward_wrap_and_unwrap", t_relay_forward_wrap_and_unwrap)
    check("metrics6_endpoint", t_metrics6_endpoint)


def _client_from_state(st: dict) -> dhcp6.Client:
    c = dhcp6.Client(duid=_duid_from_hex(st["client_v6_duid_hex"]), iaid=st["client_v6_iaid"])
    c.server_id_bytes = bytes.fromhex(st["client_v6_server_id"])
    return c


def _duid_from_hex(hex_str: str):
    from scapy.packet import Raw
    return Raw(load=bytes.fromhex(hex_str))


# ── HA (two independent mantis-dhcp instances, one Postgres) ────────────────

def phase_ha() -> None:
    assert DHCP_HA_IP, "DHCP_HA_IP not set -- run with the 'ha' compose profile"
    st = load_state()
    a = api_mod.Api()
    a.login()
    scope_id = st["scope_id"]

    n = 8
    results: list[tuple[str, str | None]] = [("", None)] * n
    lock = threading.Lock()
    responder = dhcp4.Responder(("0.0.0.0", 68))

    def worker(i: int):
        # OFFER is non-binding (a bare DISCOVER peek, no DB write) -- with
        # several clients hammering both instances at once, *every* one of
        # them legitimately gets offered the same free address (nothing has
        # claimed it yet), and only one REQUEST for it actually wins
        # (claim_specific NAKs the rest) -- a real thundering herd, same as
        # real DHCP clients hitting one server hit. A real client's answer
        # to a NAK is a fresh DISCOVER with a randomized backoff (RFC 2131
        # §4.1's retransmission jitter) so the herd spreads out instead of
        # re-colliding on whatever the next single free address is; this
        # does the same rather than retrying in lockstep.
        target = DHCP_IP if i % 2 == 0 else DHCP_HA_IP
        c = dhcp4.Client()
        got_ip = None
        for attempt in range(8):
            if attempt:
                time.sleep(random.uniform(0.05, 0.3) * attempt)
            xid = c._xid()
            _, disc = c.discover(xid=xid)
            offer, offer_opts = responder.request(disc, (target, 67), xid, timeout=10.0, attempts=1)
            if offer is None:
                continue
            req = c.request(xid, requested_ip=offer.yiaddr, server_id=offer_opts["server_id"])
            ack, ack_opts = responder.request(req, (target, 67), xid, timeout=10.0, attempts=1)
            if ack is not None and ack_opts.get("message-type") == dhcp4.ACK:
                got_ip = ack.yiaddr
                break
        with lock:
            results[i] = (c.mac, got_ip)

    def t_concurrent_allocation_across_two_instances_never_collides():
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=90)

        macs_ips = [(mac, ip) for mac, ip in results if ip is not None]
        assert len(macs_ips) == n, f"only {len(macs_ips)}/{n} clients got an ACK: {results}"
        ips = [ip for _mac, ip in macs_ips]
        assert len(set(ips)) == n, f"two instances allocated a duplicate address: {ips}"

        leases = a.list_leases(scope_id, state=0)
        lease_by_mac = {r["mac_address"]: r["ip_address"] for r in leases}
        for mac, ip in macs_ips:
            assert lease_by_mac.get(mac) == ip, \
                f"control-plane lease view disagrees with what {mac} was ACKed ({ip}): {lease_by_mac.get(mac)}"

    try:
        check("concurrent_allocation_across_two_instances_never_collides",
              t_concurrent_allocation_across_two_instances_never_collides)
    finally:
        responder.close()


# ── DDNS outage / retry queue ────────────────────────────────────────────────

def phase_ddns_trigger() -> None:
    """Run while `control` is stopped (scripts/dhcp_testbench.sh orchestrates
    that) -- the ACK still succeeds (allocation never touches control plane),
    but the DDNS POST fails and must be queued for retry (design.md §22.4)."""
    st = load_state()

    def t_ddns_event_fails_and_gets_queued():
        c = dhcp4.Client()
        before = counter_value(fetch_metrics(METRICS_URL), "dhcp_ack_total")
        _offer, _oo, ack, ack_opts = v4_dora(c, request_options=[("hostname", "outage-host")])
        assert ack_opts.get("message-type") == dhcp4.ACK, \
            "lease allocation must still succeed while control is down (it never calls control)"
        after = counter_value(fetch_metrics(METRICS_URL), "dhcp_ack_total")
        assert after == before + 1

        def queued():
            text = fetch_metrics(METRICS_URL)
            m = re.search(r"^dhcp_ddns_retry_queue_depth (\d+)$", text, re.MULTILINE)
            return m is not None and int(m.group(1)) >= 1

        assert _poll(lambda: True if queued() else None, timeout=15, interval=2), \
            "DDNS event was not queued for retry while control was down"

        st["outage_mac"] = c.mac
        st["outage_ip"] = ack.yiaddr
        save_state(st)

    check("ddns_event_fails_and_gets_queued", t_ddns_event_fails_and_gets_queued)


def phase_ddns_verify() -> None:
    """Run once `control` is back up (orchestrator restarts it before this
    phase) -- the queued retry should drain and the DDNS record should land."""
    st = load_state()
    a = api_mod.Api()
    a.login()

    def t_retry_drains_and_record_lands():
        def depth_zero():
            text = fetch_metrics(METRICS_URL)
            m = re.search(r"^dhcp_ddns_retry_queue_depth (\d+)$", text, re.MULTILINE)
            return m is not None and int(m.group(1)) == 0
        drained = _poll(lambda: True if depth_zero() else None, timeout=90, interval=5)
        assert drained, "DDNS retry queue never drained to 0 after control plane came back"

        record = _poll(lambda: _find_record(a, st["zone_id"], "outage-host", "A"), timeout=20)
        assert record is not None, "DDNS record for the outage-triggered lease never landed"
        assert record["data"] == st["outage_ip"]

    check("retry_drains_and_record_lands", t_retry_drains_and_record_lands)


# ── lease expiry sweep ───────────────────────────────────────────────────────

def phase_expiry() -> None:
    st = load_state()
    a = api_mod.Api()
    scope_id = st["scope_id"]

    def t_expired_lease_is_swept_and_ddns_record_removed():
        def gone():
            leases = a.list_leases(scope_id, state=0)
            return not any(r["ip_address"] == st["expiry_ip"] for r in leases)
        swept = _poll(lambda: True if gone() else None, timeout=120, interval=5)
        assert swept, f"lease for {st['expiry_ip']} was not swept within 90s"

    a.login()
    check("expired_lease_is_swept_and_ddns_record_removed", t_expired_lease_is_swept_and_ddns_record_removed)


PHASES = {
    "setup": phase_setup,
    "core": phase_core,
    "v6": phase_v6,
    "ha": phase_ha,
    "ddns-trigger": phase_ddns_trigger,
    "ddns-verify": phase_ddns_verify,
    "expiry": phase_expiry,
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=sorted(PHASES))
    args = parser.parse_args()
    print(f"=== phase: {args.phase} ===")
    PHASES[args.phase]()
    summary_and_exit()


if __name__ == "__main__":
    main()
