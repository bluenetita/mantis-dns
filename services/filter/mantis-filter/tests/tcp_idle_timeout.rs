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

//! Integration test: a TCP DNS client that connects but sends nothing must be
//! closed by the server after its idle timeout rather than holding a
//! connection-limit permit (`MAX_TCP_CONNECTIONS`) forever — a handful of
//! such connections used to exhaust the whole listener's capacity for every
//! other client. Uses tokio's virtual clock (`start_paused = true`) so this
//! runs in milliseconds instead of waiting out the real timeout.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::rr::{Record, RecordType};
use mantis_bundle::gen::FailurePolicy;
use mantis_bundle::Bundle;
use mantis_filter::{run_tcp_server, AppState, Forwarder};
use prost::Message as _;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

struct MockForwarder;

#[async_trait::async_trait]
impl Forwarder for MockForwarder {
    async fn lookup(
        &self,
        _qname: &str,
        _qtype: RecordType,
        _categories: &[String],
    ) -> anyhow::Result<Vec<Record>> {
        Ok(vec![])
    }
}

// Must match mantis_filter::lib.rs's TCP_IDLE_TIMEOUT (30s) — that constant
// is pub(crate), not visible to this external integration test crate.
const SERVER_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(start_paused = true)]
async fn idle_tcp_connection_is_closed_after_the_idle_timeout() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let public_key = signing_key.verifying_key();

    let mut bundle = Bundle {
        tenant_id: "t".into(),
        group_id: "g".into(),
        version: 1,
        on_load_failure: FailurePolicy::FailOpen as i32,
        ..Default::default()
    };
    let bytes = bundle.encode_to_vec();
    let sig = signing_key.sign(&bytes);
    bundle.signature = sig.to_bytes().to_vec();

    let state = Arc::new(AppState::with_forwarder(public_key, Box::new(MockForwarder)));
    state.store.try_publish(bundle, &public_key).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_tcp_server(listener, state).await.ok();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    // Deliberately never send anything — this is the slowloris case.

    tokio::time::advance(SERVER_TCP_IDLE_TIMEOUT + Duration::from_secs(1)).await;

    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "expected EOF — server must have closed the idle connection");
}

#[tokio::test(start_paused = true)]
async fn connection_that_sends_promptly_is_not_closed_by_the_idle_timer() {
    // A well-behaved client that sends its query well within the idle
    // window must not be affected by the timeout at all — regression guard
    // against the timeout firing too eagerly.
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let public_key = signing_key.verifying_key();

    let mut bundle = Bundle {
        tenant_id: "t".into(),
        group_id: "g".into(),
        version: 1,
        on_load_failure: FailurePolicy::FailOpen as i32,
        ..Default::default()
    };
    let bytes = bundle.encode_to_vec();
    let sig = signing_key.sign(&bytes);
    bundle.signature = sig.to_bytes().to_vec();

    let state = Arc::new(AppState::with_forwarder(public_key, Box::new(MockForwarder)));
    state.store.try_publish(bundle, &public_key).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_tcp_server(listener, state).await.ok();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::Name;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::io::AsyncWriteExt;

    let mut msg = Message::new();
    msg.set_id(7);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_ascii("still-alive.example.").unwrap(), RecordType::A));
    let wire = msg.to_bytes().unwrap();

    client.write_u16(wire.len() as u16).await.unwrap();
    client.write_all(&wire).await.unwrap();

    let resp_len = client.read_u16().await.unwrap() as usize;
    let mut resp_buf = vec![0u8; resp_len];
    client.read_exact(&mut resp_buf).await.unwrap();
    let response = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(response.id(), 7, "must receive the real answer, not a timeout-induced close");
}
