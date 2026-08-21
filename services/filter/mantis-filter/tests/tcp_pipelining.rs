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

//! Integration test: C3 / RFC 7766 §6.2.1.1 — two queries pipelined on one
//! TCP connection must not be serialized behind each other. A slow query
//! sent first must not delay a fast query sent right after it; the fast
//! answer must come off the wire before the slow one, and each answer must
//! still carry its own query's ID (the actual regression risk of dispatching
//! per-query tasks concurrently instead of one at a time).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use mantis_bundle::gen::FailurePolicy;
use mantis_bundle::Bundle;
use mantis_filter::{run_tcp_server, AppState, Forwarder, LookupOutcome};
use prost::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Sleeps 100ms before answering a query for "slow.example.com.", answers
/// everything else immediately — the gap needs to be large relative to
/// scheduling jitter, not razor-precise, since this runs on the real clock.
struct DelayedForwarder;

#[async_trait::async_trait]
impl Forwarder for DelayedForwarder {
    async fn lookup(
        &self,
        qname: &str,
        _qtype: RecordType,
        _categories: &[String],
    ) -> anyhow::Result<LookupOutcome> {
        if qname.trim_end_matches('.') == "slow.example.com" {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(vec![Record::from_rdata(
            qname.parse().unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
        )]
        .into())
    }
}

fn a_query(id: u16, name: &str) -> Message {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    msg
}

async fn write_query(client: &mut TcpStream, msg: &Message) {
    let wire = msg.to_bytes().unwrap();
    client.write_u16(wire.len() as u16).await.unwrap();
    client.write_all(&wire).await.unwrap();
}

async fn read_response(client: &mut TcpStream) -> Message {
    let len = client.read_u16().await.unwrap() as usize;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await.unwrap();
    Message::from_bytes(&buf).unwrap()
}

#[tokio::test]
async fn a_fast_query_pipelined_behind_a_slow_one_is_answered_first() {
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
    bundle.signature = signing_key.sign(&bytes).to_bytes().to_vec();

    let state = Arc::new(AppState::with_forwarder(public_key, Box::new(DelayedForwarder)));
    state.store.try_publish(bundle, &public_key).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        run_tcp_server(listener, state).await.ok();
    });

    let mut client = TcpStream::connect(addr).await.unwrap();

    // Pipeline both queries back to back, no read in between — id 1 is the
    // slow one, sent first; id 2 is fast, sent right after.
    write_query(&mut client, &a_query(1, "slow.example.com.")).await;
    write_query(&mut client, &a_query(2, "fast.example.com.")).await;

    let first_off_the_wire = tokio::time::timeout(Duration::from_secs(5), read_response(&mut client))
        .await
        .expect("must not block for the full 5s timeout waiting on the slow query");
    assert_eq!(
        first_off_the_wire.id(),
        2,
        "the fast query must be answered before the slow one it was pipelined behind"
    );
    assert_eq!(first_off_the_wire.response_code(), ResponseCode::NoError);

    let second_off_the_wire = read_response(&mut client).await;
    assert_eq!(second_off_the_wire.id(), 1, "the slow query's answer must still arrive, just later");
    assert_eq!(second_off_the_wire.response_code(), ResponseCode::NoError);
}
