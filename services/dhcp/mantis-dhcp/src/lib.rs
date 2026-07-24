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

//! Shared library backing both the DHCPv4 binary (`main.rs`, package default
//! bin `mantis-dhcp`) and the DHCPv6 binary (`bin/mantis-dhcp6.rs`) — two
//! separate processes/binaries (different wire protocols, different port,
//! IA_NA/IA_PD vs. a flat address pool) that share the DDNS-retry queue
//! plumbing (`ddns.rs`/`db.rs`'s `dhcp_ddns_retries` table is family-generic)
//! and the same advisory-lock/hot-reload-snapshot idioms.

pub mod config;
pub mod conflict;
pub mod db;
pub mod ddns;
pub mod metrics;
pub mod options;
pub mod server;

pub mod config6;
pub mod db6;
pub mod metrics6;
pub mod options6;
pub mod server6;

/// This host's hostname, best-effort — reported alongside each daemon's
/// heartbeat row (design.md §22.11) so an operator can tell instances apart
/// without cross-referencing `/etc/hosts` on every host. Reads
/// `/proc/sys/kernel/hostname` directly rather than the `HOSTNAME`
/// environment variable, which systemd doesn't export to spawned services
/// (it's a shell-only variable in bash, not a real env var) — the file read
/// just fails harmlessly (`None`) on a non-Linux host or a minimal
/// container without `/proc` mounted.
pub fn hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_never_panics_and_is_non_empty_when_present() {
        if let Some(h) = hostname() {
            assert!(!h.is_empty());
        }
    }
}
