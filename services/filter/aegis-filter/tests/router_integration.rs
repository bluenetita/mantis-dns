//! Integration test for multi-tenant source-IP routing (router.rs).
//! Two "tenants" with different policies, distinguished only by source IP —
//! using distinct loopback addresses (127.0.0.2, 127.0.0.3) as a stand-in for
//! distinct OpenVPN client subnets, since the whole 127.0.0.0/8 block is
//! loopback on both Linux and Windows.

use std::sync::Arc;

use aegis_bundle::gen::FailurePolicy;
use aegis_bundle::Bundle;
use aegis_filter::{run_router_udp_server, Forwarder, TenantRouter};
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
    async fn lookup(&self, qname: &str, qtype: RecordType, _categories: &[String]) -> anyhow::Result<Vec<Record>> {
        if qtype == RecordType::A {
            let name: Name = qname.parse().unwrap_or_else(|_| "example.com.".parse().unwrap());
            Ok(vec![Record::from_rdata(
                name,
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
            )])
        } else {
            Ok(vec![])
        }
    }
}

fn signed_bundle(signing_key: &SigningKey, group_id: &str, deny_domain: &str) -> Bundle {
    let mut bundle = Bundle {
        tenant_id: "t".into(),
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
    aegis_filter::test_support::inject_route(
        &router,
        "127.0.0.2/32".parse().unwrap(),
        "group-a",
        signed_bundle(&signing_key, "group-a", "blocked-for-a.example"),
        &public_key,
    );
    aegis_filter::test_support::inject_route(
        &router,
        "127.0.0.3/32".parse().unwrap(),
        "group-b",
        signed_bundle(&signing_key, "group-b", "blocked-for-b.example"),
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
        query_from("127.0.0.2:0", server_addr, "blocked-for-a.example").await,
        ResponseCode::NXDomain
    );
    // ...but group-b's deny-listed domain is NOT blocked for group-a (wrong tenant's rule).
    assert_eq!(
        query_from("127.0.0.2:0", server_addr, "blocked-for-b.example").await,
        ResponseCode::NoError
    );

    // And it's symmetric from group-b's source IP.
    assert_eq!(
        query_from("127.0.0.3:0", server_addr, "blocked-for-b.example").await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        query_from("127.0.0.3:0", server_addr, "blocked-for-a.example").await,
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
        query_from("127.0.0.4:0", server_addr, "anything.example").await,
        ResponseCode::ServFail
    );
}
