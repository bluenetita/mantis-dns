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

//! Builds the well-known auto-injected option set (design.md §22.2) for a
//! scope, plus [`apply_custom`] for arbitrary per-scope/per-reservation
//! `dhcp_options` rows (`db::CustomOption`) layered on top.

use std::net::Ipv4Addr;

use dhcproto::v4::{DhcpOption, DhcpOptions, OptionCode, UnknownOption};

use crate::db::{CustomOption, Scope};

pub fn build(scope: &Scope, server_ip: Ipv4Addr, fallback_dns: Option<Ipv4Addr>) -> DhcpOptions {
    let mut opts = DhcpOptions::new();

    opts.insert(DhcpOption::SubnetMask(scope.subnet.netmask()));

    if let Some(router) = scope.router_ip {
        opts.insert(DhcpOption::Router(vec![router]));
    }

    let dns: Vec<Ipv4Addr> = if !scope.dns_servers.is_empty() {
        scope.dns_servers.clone()
    } else {
        fallback_dns.into_iter().collect()
    };
    if !dns.is_empty() {
        opts.insert(DhcpOption::DomainNameServer(dns));
    }

    if let Some(domain) = &scope.domain_name {
        opts.insert(DhcpOption::DomainName(domain.clone()));
    }

    let lease = scope.lease_time_s.max(1) as u32;
    opts.insert(DhcpOption::AddressLeaseTime(lease));
    opts.insert(DhcpOption::Renewal(scope.renew_time_s.map(|v| v as u32).unwrap_or(lease / 2)));
    opts.insert(DhcpOption::Rebinding(scope.rebind_time_s.map(|v| v as u32).unwrap_or(lease * 7 / 8)));

    opts.insert(DhcpOption::ServerIdentifier(server_ip));

    opts
}

/// Options for a DHCPINFORM reply: the same well-known set as [`build`], but
/// with the lease-time timers stripped (option 51 AddressLeaseTime, 58
/// Renewal/T1, 59 Rebinding/T2). RFC 2131 §4.3.5 requires that the reply to a
/// DHCPINFORM "MUST NOT send a lease expiration time to the client" — an
/// INFORM client already holds its address (statically, or from elsewhere)
/// and is only requesting configuration parameters, so a lease timer here is
/// meaningless and can confuse the client into thinking it has a lease to
/// renew. An operator who genuinely wants one of these codes on an INFORM
/// reply can still set it as a custom option (applied after this).
pub fn build_inform(scope: &Scope, server_ip: Ipv4Addr, fallback_dns: Option<Ipv4Addr>) -> DhcpOptions {
    let mut opts = build(scope, server_ip, fallback_dns);
    opts.remove(OptionCode::AddressLeaseTime);
    opts.remove(OptionCode::Renewal);
    opts.remove(OptionCode::Rebinding);
    opts
}

/// Parses a `dhcp_options.value` string: a `0x`-prefixed value decodes as
/// hex bytes, anything else is sent as its literal ASCII/UTF-8 bytes. No
/// per-code typed encoding (e.g. a comma-separated IP list) — see
/// `db::CustomOption`'s docs for why.
pub fn parse_custom_value(value: &str) -> Vec<u8> {
    let trimmed = value.trim();
    if let Some(hex_str) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if let Ok(bytes) = hex::decode(hex_str) {
            return bytes;
        }
    }
    trimmed.as_bytes().to_vec()
}

/// Layers custom `dhcp_options` rows on top of an already-built option set,
/// overwriting a well-known option if a custom row happens to use the same
/// code (last write wins — an admin adding a custom row for e.g. option 15
/// presumably means to override the auto-injected `domain_name`).
pub fn apply_custom(opts: &mut DhcpOptions, custom: &[CustomOption]) {
    for c in custom {
        let code = OptionCode::from(c.option_code.clamp(1, 254) as u8);
        let data = parse_custom_value(&c.value);
        opts.insert(DhcpOption::Unknown(UnknownOption::new(code, data)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::OptionCode;

    fn base_scope() -> Scope {
        Scope {
            id: "s1".to_string(),
            tenant_id: "t1".to_string(),
            name: "test".to_string(),
            subnet: "10.0.0.0/24".parse().unwrap(),
            range_start: "10.0.0.10".parse().unwrap(),
            range_end: "10.0.0.20".parse().unwrap(),
            router_ip: None,
            dns_servers: vec![],
            domain_name: None,
            interface: None,
            lease_time_s: 3600,
            renew_time_s: None,
            rebind_time_s: None,
            ddns_enabled: false,
            pxe_next_server: None,
            pxe_boot_filename: None,
            pxe_uefi_boot_filename: None,
        }
    }

    #[test]
    fn subnet_mask_derived_from_scope_cidr() {
        let opts = build(&base_scope(), "10.0.0.1".parse().unwrap(), None);
        assert_eq!(opts.get(OptionCode::SubnetMask), Some(&DhcpOption::SubnetMask("255.255.255.0".parse().unwrap())));
    }

    #[test]
    fn dns_servers_use_scope_list_when_present() {
        let mut scope = base_scope();
        scope.dns_servers = vec!["1.1.1.1".parse().unwrap()];
        let opts = build(&scope, "10.0.0.1".parse().unwrap(), Some("9.9.9.9".parse().unwrap()));
        assert_eq!(opts.get(OptionCode::DomainNameServer), Some(&DhcpOption::DomainNameServer(vec!["1.1.1.1".parse().unwrap()])));
    }

    #[test]
    fn dns_servers_fall_back_to_filter_node_ip_when_scope_list_empty() {
        let scope = base_scope();
        let fallback: Ipv4Addr = "9.9.9.9".parse().unwrap();
        let opts = build(&scope, "10.0.0.1".parse().unwrap(), Some(fallback));
        assert_eq!(opts.get(OptionCode::DomainNameServer), Some(&DhcpOption::DomainNameServer(vec![fallback])));
    }

    #[test]
    fn no_dns_option_when_scope_list_empty_and_no_fallback_configured() {
        let opts = build(&base_scope(), "10.0.0.1".parse().unwrap(), None);
        assert_eq!(opts.get(OptionCode::DomainNameServer), None);
    }

    #[test]
    fn renew_and_rebind_default_to_50_and_87_5_percent_of_lease() {
        let mut scope = base_scope();
        scope.lease_time_s = 1000;
        let opts = build(&scope, "10.0.0.1".parse().unwrap(), None);
        assert_eq!(opts.get(OptionCode::Renewal), Some(&DhcpOption::Renewal(500)));
        assert_eq!(opts.get(OptionCode::Rebinding), Some(&DhcpOption::Rebinding(875)));
    }

    #[test]
    fn explicit_renew_rebind_override_the_computed_defaults() {
        let mut scope = base_scope();
        scope.lease_time_s = 1000;
        scope.renew_time_s = Some(100);
        scope.rebind_time_s = Some(200);
        let opts = build(&scope, "10.0.0.1".parse().unwrap(), None);
        assert_eq!(opts.get(OptionCode::Renewal), Some(&DhcpOption::Renewal(100)));
        assert_eq!(opts.get(OptionCode::Rebinding), Some(&DhcpOption::Rebinding(200)));
    }

    #[test]
    fn server_identifier_always_set() {
        let server_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let opts = build(&base_scope(), server_ip, None);
        assert_eq!(opts.get(OptionCode::ServerIdentifier), Some(&DhcpOption::ServerIdentifier(server_ip)));
    }

    #[test]
    fn build_inform_strips_lease_time_options_but_keeps_the_rest() {
        let mut scope = base_scope();
        scope.router_ip = Some("10.0.0.1".parse().unwrap());
        let opts = build_inform(&scope, "10.0.0.1".parse().unwrap(), None);
        // RFC 2131 §4.3.5: no lease expiration time on an INFORM reply.
        assert_eq!(opts.get(OptionCode::AddressLeaseTime), None);
        assert_eq!(opts.get(OptionCode::Renewal), None);
        assert_eq!(opts.get(OptionCode::Rebinding), None);
        // Non-timer parameters must still be present.
        assert!(opts.get(OptionCode::SubnetMask).is_some());
        assert!(opts.get(OptionCode::Router).is_some());
        assert!(opts.get(OptionCode::ServerIdentifier).is_some());
    }

    #[test]
    fn parse_custom_value_decodes_0x_prefixed_hex() {
        assert_eq!(parse_custom_value("0xAABBCC"), vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(parse_custom_value("0xaabbcc"), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_custom_value_falls_back_to_raw_bytes_for_non_hex() {
        assert_eq!(parse_custom_value("hello"), b"hello".to_vec());
        // Looks 0x-prefixed but isn't valid hex — must not silently produce
        // an empty/wrong value, falls back to literal bytes of the whole string.
        assert_eq!(parse_custom_value("0xnothex"), b"0xnothex".to_vec());
    }

    #[test]
    fn parse_custom_value_trims_whitespace() {
        assert_eq!(parse_custom_value("  hello  "), b"hello".to_vec());
    }

    #[test]
    fn apply_custom_overwrites_a_well_known_option_with_the_same_code() {
        let mut opts = build(&base_scope(), "10.0.0.1".parse().unwrap(), None);
        assert_eq!(opts.get(OptionCode::DomainName), None);
        apply_custom(&mut opts, &[CustomOption { option_code: 15, value: "example.com".to_string() }]);
        match opts.get(OptionCode::DomainName) {
            Some(DhcpOption::Unknown(u)) => assert_eq!(u.data(), b"example.com"),
            other => panic!("expected DhcpOption::Unknown for a custom-overridden code, got {other:?}"),
        }
    }

    #[test]
    fn apply_custom_adds_an_option_with_no_named_variant() {
        let mut opts = build(&base_scope(), "10.0.0.1".parse().unwrap(), None);
        apply_custom(&mut opts, &[CustomOption { option_code: 224, value: "0xdeadbeef".to_string() }]);
        match opts.get(OptionCode::from(224u8)) {
            Some(DhcpOption::Unknown(u)) => assert_eq!(u.data(), &[0xde, 0xad, 0xbe, 0xef]),
            other => panic!("expected DhcpOption::Unknown for option 224, got {other:?}"),
        }
    }
}
