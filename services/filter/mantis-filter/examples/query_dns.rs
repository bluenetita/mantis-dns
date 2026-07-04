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

//! Manual smoke-test client: sends one A query at a running mantis-filter
//! instance and prints the response code. Used to validate a live deployment
//! (e.g. the Docker container) end to end, outside the `cargo test` harness.
//!
//! cargo run -p mantis-filter --example query_dns -- 127.0.0.1:1053 some.domain

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::env;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        anyhow::bail!("usage: query_dns <server addr:port> <domain>");
    }
    let server = &args[1];
    let domain = &args[2];

    let client = UdpSocket::bind("0.0.0.0:0").await?;

    let mut msg = Message::new();
    msg.set_id(1);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_ascii(domain)?, RecordType::A));

    client.send_to(&msg.to_bytes()?, server).await?;

    let mut buf = [0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await?;
    let response = Message::from_bytes(&buf[..len])?;

    println!("query={domain} response_code={:?} answers={}", response.response_code(), response.answer_count());
    Ok(())
}
