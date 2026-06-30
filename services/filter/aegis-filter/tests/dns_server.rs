//! Integration test: spins up the real UDP DNS listener against an in-memory
//! signed bundle (no control-plane HTTP involved) and sends actual DNS wire
//! packets at it, asserting on the response codes.

use std::sync::Arc;

use aegis_bundle::gen::{Action, BloomParams, FailurePolicy};
use aegis_bundle::{Bundle, CategorySet};
use aegis_filter::{run_udp_server, AppState, Forwarder};
use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use prost::Message as _;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

/// Deterministic stand-in for real upstream resolution — no network/port 853
/// dependency in tests. Always "resolves" to a fixed test-net IP.
struct MockForwarder;

#[async_trait::async_trait]
impl Forwarder for MockForwarder {
    async fn lookup_a(&self, _qname: &str) -> anyhow::Result<(Vec<Ipv4Addr>, u32)> {
        Ok((vec![Ipv4Addr::new(198, 51, 100, 1)], 60))
    }
}

fn signed_test_bundle(signing_key: &SigningKey) -> Bundle {
    let mut bundle = Bundle {
        tenant_id: "t".into(),
        group_id: "g".into(),
        version: 1,
        allow_overrides: vec!["allowed-explicitly.example".into()],
        deny_overrides: vec!["blocked-explicitly.example".into()],
        on_load_failure: FailurePolicy::FailOpen as i32,
        categories: vec![CategorySet {
            category_id: "adult".into(),
            source_feed_id: "".into(),
            feed_version: "".into(),
            license: "".into(),
            bloom: Some(BloomParams {
                num_hashes: 4,
                num_bits: 4096,
                seed: 1234,
            }),
            bloom_bits: build_bloom_with("category-blocked.example"),
            action: Action::Block as i32,
        }],
        ..Default::default()
    };

    let bytes = bundle.encode_to_vec();
    let sig = signing_key.sign(&bytes);
    bundle.signature = sig.to_bytes().to_vec();
    bundle
}

/// Builds a bloom bitset containing exactly one domain, using the same
/// scheme as aegis-policy (mirrors bloom.py — see lib.rs doc comment there).
fn build_bloom_with(domain: &str) -> Vec<u8> {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash = FNV_OFFSET;
        for &b in bytes {
            hash ^= b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let num_bits: u64 = 4096;
    let num_hashes: u64 = 4;
    let seed: u64 = 1234;
    let seed_bytes = seed.to_le_bytes();
    let domain_bytes = domain.as_bytes();

    let mut buf1 = seed_bytes.to_vec();
    buf1.extend_from_slice(domain_bytes);
    let mut buf2 = domain_bytes.to_vec();
    buf2.extend_from_slice(&seed_bytes);
    let (h1, h2) = (fnv1a(&buf1), fnv1a(&buf2));

    let mut bits = vec![0u8; (num_bits / 8) as usize];
    for i in 0..num_hashes {
        let bit_index = h1.wrapping_add(i.wrapping_mul(h2)) % num_bits;
        bits[(bit_index / 8) as usize] |= 1 << (bit_index % 8);
    }
    bits
}

async fn start_test_server() -> (std::net::SocketAddr, SigningKey) {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let public_key = signing_key.verifying_key();

    let state = Arc::new(AppState::with_forwarder(public_key, Box::new(MockForwarder)));
    let bundle = signed_test_bundle(&signing_key);
    state.store.try_publish(bundle, &public_key).unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        run_udp_server(socket, state).await.ok();
    });

    (addr, signing_key)
}

async fn query(server: std::net::SocketAddr, domain: &str) -> ResponseCode {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut msg = Message::new();
    msg.set_id(42);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let name = Name::from_ascii(domain).unwrap();
    msg.add_query(Query::query(name, RecordType::A));

    let bytes = msg.to_bytes().unwrap();
    client.send_to(&bytes, server).await.unwrap();

    let mut buf = [0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    let response = Message::from_bytes(&buf[..len]).unwrap();
    response.response_code()
}

#[tokio::test]
async fn allow_override_wins() {
    let (server, _) = start_test_server().await;
    assert_eq!(
        query(server, "allowed-explicitly.example").await,
        ResponseCode::NoError
    );
}

#[tokio::test]
async fn deny_override_blocks() {
    let (server, _) = start_test_server().await;
    assert_eq!(
        query(server, "blocked-explicitly.example").await,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn category_bloom_blocks() {
    let (server, _) = start_test_server().await;
    assert_eq!(
        query(server, "category-blocked.example").await,
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn unknown_domain_allowed_by_default() {
    let (server, _) = start_test_server().await;
    assert_eq!(
        query(server, "totally-unrelated.example").await,
        ResponseCode::NoError
    );
}
