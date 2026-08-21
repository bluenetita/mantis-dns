/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Integration test for multi-tenant source-IP routing (router.rs).
//! Two "tenants" with different policies, distinguished only by source IP —
//! using distinct loopback addresses (127.0.0.2, 127.0.0.3) as a stand-in for
//! distinct OpenVPN client subnets, since the whole 127.0.0.0/8 block is
//! loopback on both Linux and Windows.

use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use mantis_bundle::gen::FailurePolicy;
use mantis_bundle::Bundle;
use mantis_filter::{run_router_udp_server, Forwarder, LookupOutcome, TenantRouter};
use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use prost::Message as _;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

struct MockForwarder;

#[async_trait::async_trait]
impl Forwarder for MockForwarder {
    async fn lookup(&self, qname: &str, qtype: RecordType, _categories: &[String]) -> anyhow::Result<LookupOutcome> {
        if qtype == RecordType::A {
            let name: Name = qname.parse().unwrap_or_else(|_| "example.com.".parse().unwrap());
            Ok(vec![Record::from_rdata(
                name,
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
            )]
            .into())
        } else {
            Ok(vec![].into())
        }
    }
}

struct FixedForwarder(Ipv4Addr);

#[async_trait::async_trait]
impl Forwarder for FixedForwarder {
    async fn lookup(
        &self,
        qname: &str,
        qtype: RecordType,
        _categories: &[String],
    ) -> anyhow::Result<LookupOutcome> {
        if qtype != RecordType::A {
            return Ok(vec![].into());
        }
        Ok(vec![Record::from_rdata(
            qname.parse()?,
            60,
            RData::A(A(self.0)),
        )]
        .into())
    }
}

struct CountingForwarder(AtomicUsize);

#[async_trait::async_trait]
impl Forwarder for CountingForwarder {
    async fn lookup(
        &self,
        qname: &str,
        _qtype: RecordType,
        _categories: &[String],
    ) -> anyhow::Result<LookupOutcome> {
        let call = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(vec![Record::from_rdata(
            qname.parse()?,
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, call as u8))),
        )]
        .into())
    }
}

fn signed_bundle(signing_key: &SigningKey, group_id: &str, deny_domain: &str) -> Bundle {
    signed_bundle_for_tenant(signing_key, "t", group_id, deny_domain)
}

fn signed_bundle_for_tenant(
    signing_key: &SigningKey,
    tenant_id: &str,
    group_id: &str,
    deny_domain: &str,
) -> Bundle {
    let mut bundle = Bundle {
        tenant_id: tenant_id.into(),
        group_id: group_id.into(),
        version: 1,
        deny_overrides: vec![deny_domain.into()],
        on_load_failure: FailurePolicy::FailOpen as i32,
        categories: vec![],
        ..Default::default()
    };
    let bytes = bundle.encode_to_vec();
    let sig = signing_key.sign(&bytes);
    bundle.signature = sig.to_bytes().to_vec();
    bundle
}

async fn query_a(
    client_addr: &str,
    server: std::net::SocketAddr,
    domain: &str,
) -> Ipv4Addr {
    let client = UdpSocket::bind(client_addr).await.unwrap();
    let mut msg = Message::new();
    msg.set_id(8);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    client.send_to(&msg.to_bytes().unwrap(), server).await.unwrap();
    let mut buf = [0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    let response = Message::from_bytes(&buf[..len]).unwrap();
    match response.answers()[0].data() {
        RData::A(address) => address.0,
        other => panic!("expected A answer, got {other:?}"),
    }
}

async fn query_from(client_addr: &str, server: std::net::SocketAddr, domain: &str) -> ResponseCode {
    let client = UdpSocket::bind(client_addr).await.unwrap();

    let mut msg = Message::new();
    msg.set_id(7);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), RecordType::A));

    client.send_to(&msg.to_bytes().unwrap(), server).await.unwrap();

    let mut buf = [0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    Message::from_bytes(&buf[..len]).unwrap().response_code()
}

#[tokio::test]
async fn routes_different_source_ips_to_different_tenant_policies() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let public_key = signing_key.verifying_key();

    let router = Arc::new(TenantRouter::new(public_key, Box::new(MockForwarder)));

    // Manually wire two routes + bundles, bypassing the control-plane HTTP
    // fetch (same pattern as dns_server.rs's in-memory bundle tests).
    mantis_filter::test_support::inject_route(
        &router,
        "127.0.0.2/32".parse().unwrap(),
        "group-a",
        signed_bundle(&signing_key, "group-a", "blocked-for-a.example.com"),
        &public_key,
    );
    mantis_filter::test_support::inject_route(
        &router,
        "127.0.0.3/32".parse().unwrap(),
        "group-b",
        signed_bundle(&signing_key, "group-b", "blocked-for-b.example.com"),
        &public_key,
    );

    assert_eq!(router.route_count(), 2);

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        run_router_udp_server(socket, router).await.ok();
    });

    // group-a's source IP: its own deny-listed domain is blocked...
    assert_eq!(
        query_from("127.0.0.2:0", server_addr, "blocked-for-a.example.com").await,
        ResponseCode::NXDomain
    );
    // ...but group-b's deny-listed domain is NOT blocked for group-a (wrong tenant's rule).
    assert_eq!(
        query_from("127.0.0.2:0", server_addr, "blocked-for-b.example.com").await,
        ResponseCode::NoError
    );

    // And it's symmetric from group-b's source IP.
    assert_eq!(
        query_from("127.0.0.3:0", server_addr, "blocked-for-b.example.com").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        query_from("127.0.0.3:0", server_addr, "blocked-for-a.example.com").await,
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn unmatched_source_ip_fails_open_to_servfail() {
    let signing_key = SigningKey::from_bytes(&[12u8; 32]);
    let public_key = signing_key.verifying_key();
    let router = Arc::new(TenantRouter::new(public_key, Box::new(MockForwarder)));
    // No routes injected — every source IP is unmatched.

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        run_router_udp_server(socket, router).await.ok();
    });

    assert_eq!(
        query_from("127.0.0.4:0", server_addr, "anything.example.com").await,
        ResponseCode::ServFail
    );
}

#[tokio::test]
async fn tenant_routes_isolate_upstream_forwarders_and_caches() {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let public_key = signing_key.verifying_key();
    let router = Arc::new(TenantRouter::new(public_key, Box::new(MockForwarder)));

    mantis_filter::test_support::inject_route_with_forwarder(
        &router,
        "127.0.0.5/32".parse().unwrap(),
        "group-a",
        signed_bundle_for_tenant(&signing_key, "tenant-a", "group-a", "never.example.net"),
        &public_key,
        Arc::new(FixedForwarder(Ipv4Addr::new(192, 0, 2, 10))),
    );
    mantis_filter::test_support::inject_route_with_forwarder(
        &router,
        "127.0.0.6/32".parse().unwrap(),
        "group-b",
        signed_bundle_for_tenant(&signing_key, "tenant-b", "group-b", "never.example.net"),
        &public_key,
        Arc::new(FixedForwarder(Ipv4Addr::new(192, 0, 2, 20))),
    );

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        run_router_udp_server(socket, router).await.ok();
    });

    // Query the exact same cache key from both tenants. A shared cache or
    // shared forwarder would make the second answer equal the first.
    assert_eq!(
        query_a("127.0.0.5:0", server_addr, "same.example.com").await,
        Ipv4Addr::new(192, 0, 2, 10)
    );
    assert_eq!(
        query_a("127.0.0.6:0", server_addr, "same.example.com").await,
        Ipv4Addr::new(192, 0, 2, 20)
    );
}

#[tokio::test]
async fn groups_in_one_tenant_do_not_share_cached_answers() {
    let signing_key = SigningKey::from_bytes(&[14u8; 32]);
    let public_key = signing_key.verifying_key();
    let router = Arc::new(TenantRouter::new(
        public_key,
        Box::new(CountingForwarder(AtomicUsize::new(0))),
    ));

    for (cidr, group) in [("127.0.0.7/32", "group-a"), ("127.0.0.8/32", "group-b")] {
        mantis_filter::test_support::inject_route(
            &router,
            cidr.parse().unwrap(),
            group,
            signed_bundle_for_tenant(&signing_key, "same-tenant", group, "never.example.net"),
            &public_key,
        );
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        run_router_udp_server(socket, router).await.ok();
    });

    assert_eq!(
        query_a("127.0.0.7:0", server_addr, "same.example.com").await,
        Ipv4Addr::new(192, 0, 2, 1)
    );
    assert_eq!(
        query_a("127.0.0.8:0", server_addr, "same.example.com").await,
        Ipv4Addr::new(192, 0, 2, 2)
    );
}
