// Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::net::Ipv6Addr;

/// IANA Private Enterprise Number range reserved for documentation/example
/// use (RFC 5943's registry carve-out, 32473-32476) — used to build a
/// DUID-EN (RFC 8415 §11.4) for this server's own Server Identifier option,
/// since mantis-dhcp isn't itself vendor-registered with IANA.
const DOCUMENTATION_ENTERPRISE_NUMBER: u32 = 32473;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// This server's own DUID (RFC 8415 §11), sent as Server Identifier
    /// (option 2) in every ADVERTISE/REPLY and checked against a client's
    /// Server Identifier on REQUEST/RENEW/RELEASE/DECLINE to confirm the
    /// message is actually meant for this server. Built deterministically
    /// from `MANTIS_DHCP6_SERVER_ID` (DUID-EN: type 2, enterprise number
    /// [`DOCUMENTATION_ENTERPRISE_NUMBER`], the configured address's 16
    /// octets as the id) rather than generated randomly at startup, so it
    /// stays stable across restarts without needing its own persistent
    /// storage — a client that cached this server's DUID between reboots of
    /// the server must keep recognizing it.
    pub server_duid: Vec<u8>,
    pub control_url: String,
    pub internal_token: String,
    pub scope_refresh_interval_s: u64,
    pub lease_sweep_interval_s: u64,
    pub ddns_retry_interval_s: u64,
    /// See v4's `Config::decline_probation_s` — same purpose, same default.
    pub decline_probation_s: i64,
    /// Opt-in Prometheus `/metrics` listener, same convention as the v4
    /// daemon's `MANTIS_DHCP_METRICS_BIND_ADDR` (blank = disabled).
    pub metrics_bind_addr: Option<std::net::SocketAddr>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
        let server_id: Ipv6Addr = std::env::var("MANTIS_DHCP6_SERVER_ID")
            .map_err(|_| {
                anyhow::anyhow!(
                    "MANTIS_DHCP6_SERVER_ID is required (a stable IPv6 address identifying this \
                     server, used only to derive its DUID -- it is never itself handed out to a \
                     client, so it does not need to be on-link)"
                )
            })?
            .parse()?;
        let metrics_bind_addr = match std::env::var("MANTIS_DHCP6_METRICS_BIND_ADDR") {
            Ok(v) if !v.is_empty() => Some(v.parse()?),
            _ => None,
        };
        Ok(Self {
            database_url,
            bind_addr: std::env::var("MANTIS_DHCP6_BIND_ADDR").unwrap_or_else(|_| "[::]:547".to_string()),
            server_duid: build_duid_en(server_id),
            control_url: std::env::var("MANTIS_CTRL_URL").unwrap_or_else(|_| "http://control:8000".to_string()),
            internal_token: std::env::var("MANTIS_INTERNAL_TOKEN").unwrap_or_default(),
            scope_refresh_interval_s: 10,
            lease_sweep_interval_s: 30,
            ddns_retry_interval_s: 10,
            decline_probation_s: std::env::var("MANTIS_DHCP_DECLINE_PROBATION_S")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86400),
            metrics_bind_addr,
        })
    }
}

fn build_duid_en(server_id: Ipv6Addr) -> Vec<u8> {
    let mut duid = Vec::with_capacity(2 + 4 + 16);
    duid.extend_from_slice(&2u16.to_be_bytes()); // DUID-EN type
    duid.extend_from_slice(&DOCUMENTATION_ENTERPRISE_NUMBER.to_be_bytes());
    duid.extend_from_slice(&server_id.octets());
    duid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_duid_en_is_deterministic_for_the_same_address() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(build_duid_en(addr), build_duid_en(addr));
    }

    #[test]
    fn build_duid_en_differs_for_different_addresses() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_ne!(build_duid_en(a), build_duid_en(b));
    }

    #[test]
    fn build_duid_en_has_the_expected_shape() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let duid = build_duid_en(addr);
        assert_eq!(duid.len(), 22);
        assert_eq!(&duid[0..2], &2u16.to_be_bytes());
        assert_eq!(&duid[2..6], &DOCUMENTATION_ENTERPRISE_NUMBER.to_be_bytes());
        assert_eq!(&duid[6..22], &addr.octets());
    }
}
