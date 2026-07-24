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
