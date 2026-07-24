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

//! Builds the well-known scope-level DHCPv6 option set — the v6 counterpart
//! of `options.rs::build`, minus per-scope/per-reservation custom option
//! passthrough (`dhcp_options` is v4-only right now, `option_space =
//! 'dhcp4'` — an honest gap, same category as design.md §22.9 flagged the
//! whole daemon as before it existed) and minus Domain Search List (option
//! 24, RFC 3646) — it needs a DNS-name wire encoding (`hickory_proto::rr::Name`)
//! this crate doesn't otherwise depend on, for a field most deployments leave
//! unset anyway.

use dhcproto::v6::{DhcpOption, DhcpOptions};

use crate::db6::Scope6;

pub fn build(scope: &Scope6, server_duid: &[u8]) -> DhcpOptions {
    let mut opts = DhcpOptions::new();
    opts.insert(DhcpOption::ServerId(server_duid.to_vec()));
    if !scope.dns_servers.is_empty() {
        opts.insert(DhcpOption::DomainNameServers(scope.dns_servers.clone()));
    }
    opts
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::OptionCode;
    use std::net::Ipv6Addr;

    fn base_scope() -> Scope6 {
        Scope6 {
            id: "s1".to_string(),
            tenant_id: "t1".to_string(),
            name: "test6".to_string(),
            subnet: "2001:db8::/64".parse().unwrap(),
            pool_start: "2001:db8::100".parse().unwrap(),
            pool_end: "2001:db8::200".parse().unwrap(),
            pd_prefix: None,
            pd_prefix_len: None,
            dns_servers: vec![],
            domain_name: None,
            interface: None,
            preferred_lifetime_s: 3000,
            valid_lifetime_s: 4000,
            renew_time_s: None,
            rebind_time_s: None,
            ddns_enabled: false,
        }
    }

    #[test]
    fn server_id_always_set() {
        let opts = build(&base_scope(), &[0, 2, 0, 0, 0x7e, 0xe9]);
        assert_eq!(opts.get(OptionCode::ServerId), Some(&DhcpOption::ServerId(vec![0, 2, 0, 0, 0x7e, 0xe9])));
    }

    #[test]
    fn no_dns_option_when_scope_list_empty() {
        let opts = build(&base_scope(), &[0, 2]);
        assert_eq!(opts.get(OptionCode::DomainNameServers), None);
    }

    #[test]
    fn dns_servers_set_when_scope_list_present() {
        let mut scope = base_scope();
        let dns: Ipv6Addr = "2001:db8::53".parse().unwrap();
        scope.dns_servers = vec![dns];
        let opts = build(&scope, &[0, 2]);
        assert_eq!(opts.get(OptionCode::DomainNameServers), Some(&DhcpOption::DomainNameServers(vec![dns])));
    }
}
