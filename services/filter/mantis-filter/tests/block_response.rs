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

//! Integration test: the block-response mode (proto `BlockResponse`) drives the
//! DNS answer for a blocked query — NXDOMAIN (default), 0.0.0.0 (ZERO_IP), or a
//! configured redirect IP (REDIRECT). Sends real wire packets at the UDP server
//! and inspects the answer records, not just the rcode.

use std::net::Ipv4Addr;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use mantis_bundle::gen::FailurePolicy;
use mantis_bundle::{BlockMode, BlockResponse, Bundle};
use mantis_filter::{run_udp_server, AppState, Forwarder};
use prost::Message as _;
use tokio::net::UdpSocket;

struct MockForwarder;

#[async_trait::async_trait]
impl Forwarder for MockForwarder {
    async fn lookup(
        &self,
        qname: &str,
        qtype: RecordType,
        _categories: &[String],
    ) -> anyhow::Result<Vec<Record>> {
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

fn signed_bundle(signing_key: &SigningKey, block: Option<BlockResponse>) -> Bundle {
    let mut bundle = Bundle {
        tenant_id: "t".into(),
        group_id: "g".into(),
        version: 1,
        deny_overrides: vec!["blocked.example".into()],
        on_load_failure: FailurePolicy::FailOpen as i32,
        block_response: block,
        ..Default::default()
    };
    let bytes = bundle.encode_to_vec();
    bundle.signature = signing_key.sign(&bytes).to_bytes().to_vec();
    bundle
}

async fn start_server(block: Option<BlockResponse>) -> std::net::SocketAddr {
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let public_key = signing_key.verifying_key();
    let state = Arc::new(AppState::with_forwarder(public_key, Box::new(MockForwarder)));
    state
        .store
        .try_publish(signed_bundle(&signing_key, block), &public_key)
        .unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        run_udp_server(socket, state).await.ok();
    });
    addr
}

async fn query(server: std::net::SocketAddr, domain: &str, qtype: RecordType) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = Message::new();
    msg.set_id(42);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_ascii(domain).unwrap(), qtype));
    client.send_to(&msg.to_bytes().unwrap(), server).await.unwrap();

    let mut buf = [0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    Message::from_bytes(&buf[..len]).unwrap()
}

fn redirect(v4: &str, v6: &str, ttl: u32) -> BlockResponse {
    BlockResponse {
        mode: BlockMode::Redirect as i32,
        redirect_ipv4: v4.into(),
        redirect_ipv6: v6.into(),
        ttl_seconds: ttl,
    }
}

#[tokio::test]
async fn default_block_is_nxdomain() {
    let server = start_server(None).await;
    let resp = query(server, "blocked.example", RecordType::A).await;
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    assert_eq!(resp.answer_count(), 0);
}

#[tokio::test]
async fn redirect_mode_returns_configured_a_record() {
    let server = start_server(Some(redirect("10.0.0.53", "", 30))).await;
    let resp = query(server, "blocked.example", RecordType::A).await;

    assert_eq!(resp.response_code(), ResponseCode::NoError);
    let answers = resp.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].ttl(), 30);
    match answers[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(10, 0, 0, 53)),
        other => panic!("expected A record, got {other:?}"),
    }
}

#[tokio::test]
async fn redirect_aaaa_without_v6_is_nodata_not_nxdomain() {
    // A missing AAAA must be NODATA (NOERROR, no answer), never NXDOMAIN — an
    // NXDOMAIN would tell dual-stack stubs the whole name doesn't exist and
    // poison the A lookup that carries the redirect.
    let server = start_server(Some(redirect("10.0.0.53", "", 30))).await;
    let resp = query(server, "blocked.example", RecordType::AAAA).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answer_count(), 0);
}

#[tokio::test]
async fn zero_ip_mode_returns_unspecified_address() {
    let server = start_server(Some(BlockResponse {
        mode: BlockMode::ZeroIp as i32,
        ttl_seconds: 30,
        ..Default::default()
    }))
    .await;
    let resp = query(server, "blocked.example", RecordType::A).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[tokio::test]
async fn redirect_non_address_qtype_is_nodata() {
    // MX/TXT/etc under REDIRECT: the name "exists" (sinkholed) but has no such
    // record — NODATA, so only web navigations (A/AAAA) reach the block page.
    let server = start_server(Some(redirect("10.0.0.53", "", 30))).await;
    let resp = query(server, "blocked.example", RecordType::MX).await;
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answer_count(), 0);
}

#[tokio::test]
async fn allowed_domain_unaffected_by_redirect_mode() {
    let server = start_server(Some(redirect("10.0.0.53", "", 30))).await;
    let resp = query(server, "allowed.example", RecordType::A).await;
    // Resolves through the mock forwarder, not the redirect IP.
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    match resp.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(198, 51, 100, 1)),
        other => panic!("expected forwarded A, got {other:?}"),
    }
}
