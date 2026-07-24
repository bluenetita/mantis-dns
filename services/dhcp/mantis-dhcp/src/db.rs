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

//! Reads `dhcp_scopes` / `dhcp_static_leases` / `dhcp_options` /
//! `dhcp_relay_configs` — the same tables the control-plane UI/API edit —
//! directly, and owns `dhcp_leases`, mantis-dhcp's native allocation state.
//! There is no push/sync step: a scope edit is live on this process's next
//! [`Snapshot`] refresh (`scope_refresh_interval_s`, default 10s).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;

#[derive(Debug, Clone)]
pub struct Scope {
    pub id: String,
    #[allow(dead_code)] // informational; not yet used for per-tenant DHCP logging
    pub tenant_id: String,
    pub name: String,
    pub subnet: ipnet::Ipv4Net,
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub router_ip: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub interface: Option<String>,
    pub lease_time_s: i32,
    pub renew_time_s: Option<i32>,
    pub rebind_time_s: Option<i32>,
    pub ddns_enabled: bool,
    pub pxe_next_server: Option<Ipv4Addr>,
    /// BIOS/default boot filename — used whenever the client isn't
    /// recognized as UEFI, or no UEFI-specific filename is configured.
    pub pxe_boot_filename: Option<String>,
    /// Overrides `pxe_boot_filename` when the client's option 93 (Client
    /// System Architecture, RFC 4578) indicates UEFI rather than legacy
    /// BIOS — see `server.rs`'s `select_boot_filename`.
    pub pxe_uefi_boot_filename: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Reservation {
    pub id: String,
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
    pub next_server: Option<Ipv4Addr>,
    pub boot_filename: Option<String>,
    pub uefi_boot_filename: Option<String>,
}

/// A `dhcp_options` row — arbitrary option code + raw value, applied on top
/// of the well-known auto-injected set (`options.rs`). `value` is parsed by
/// `options::parse_custom_value`: `0x`-prefixed hex decodes to raw bytes,
/// anything else is sent as its literal ASCII/UTF-8 bytes. There's no
/// per-option-code typed encoding (e.g. a comma-separated IP list) — that
/// would need knowing each code's declared data type the way Kea's option
/// definitions do, which this doesn't model.
#[derive(Debug, Clone)]
pub struct CustomOption {
    pub option_code: i32,
    pub value: String,
}

/// One `DhcpRelayConfig` row: a trusted `relay_ip`, optionally narrowed
/// further by the relay's own Option 82 (Relay Agent Information) sub-option
/// values — see `find_scope_for_relay`.
#[derive(Debug, Clone)]
pub struct RelayConfigEntry {
    pub relay_ip: Ipv4Addr,
    pub circuit_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
}

/// Immutable, hot-swappable view of DHCP config. Rebuilt wholesale on each
/// refresh tick (see [`refresh_loop`]) and installed via `ArcSwap` — the
/// packet-handling hot path only ever takes a cheap `load()` snapshot, never
/// blocks on a DB round-trip for config (only lease allocation itself does).
pub struct Snapshot {
    pub scopes: Vec<Scope>,
    /// keyed by (scope_id, lowercased mac_address)
    pub reservations: HashMap<(String, String), Reservation>,
    /// scope_id -> its configured relay allow-list. A scope present here
    /// only accepts relayed traffic matching one of these entries — see
    /// `find_scope_for_relay`.
    pub relay_configs_by_scope: HashMap<String, Vec<RelayConfigEntry>>,
    /// scope_id -> its scope-level custom `dhcp_options` rows.
    pub scope_options: HashMap<String, Vec<CustomOption>>,
    /// DhcpStaticLease.id -> its reservation-level custom `dhcp_options`
    /// rows, which override a scope-level option with the same code.
    pub reservation_options: HashMap<String, Vec<CustomOption>>,
}

impl Snapshot {
    /// A scope with `DhcpRelayConfig` rows only accepts relayed traffic
    /// matching one of them — an untrusted relay elsewhere on the same
    /// subnet must not be able to inject requests into it just because its
    /// giaddr happens to fall inside that subnet (design.md §22.12's
    /// relay-authentication gap). When a row also sets `circuit_id`/
    /// `remote_id` (parsed from the DB's `circuit_id_hex`/`remote_id_hex`),
    /// the packet's own Option 82 (Relay Agent Information) sub-options must
    /// match those too, not just `relay_ip` — a relay_ip match alone isn't
    /// enough to satisfy a row that asked for a specific circuit/remote id.
    /// The subnet-containment fallback is only used for scopes with no
    /// relay config rows at all.
    pub fn find_scope_for_relay(&self, giaddr: Ipv4Addr, circuit_id: Option<&[u8]>, remote_id: Option<&[u8]>) -> Option<&Scope> {
        for scope in &self.scopes {
            let Some(configs) = self.relay_configs_by_scope.get(&scope.id) else { continue };
            for cfg in configs {
                if cfg.relay_ip != giaddr {
                    continue;
                }
                let circuit_ok = cfg.circuit_id.as_deref().is_none_or(|want| Some(want) == circuit_id);
                let remote_ok = cfg.remote_id.as_deref().is_none_or(|want| Some(want) == remote_id);
                if circuit_ok && remote_ok {
                    return Some(scope);
                }
            }
        }
        self.scopes.iter().find(|s| {
            s.subnet.contains(&giaddr)
                && self.relay_configs_by_scope.get(&s.id).is_none_or(|c| c.is_empty())
        })
    }

    /// Direct-attached (unrelayed) client dispatch. `recv_interface` is
    /// `Some(name)` when the packet arrived on a socket bound to that
    /// specific interface (`SO_BINDTODEVICE`, Linux-only — see main.rs's
    /// `bind_interface_sockets`), giving an exact, unambiguous match against
    /// the scope configured for that interface. It's `None` on the wildcard
    /// socket — the only option on non-Linux platforms, and also how
    /// traffic for scopes with no `interface` restriction always arrives —
    /// where this falls back to the old single-candidate heuristic (only
    /// disambiguates when there's exactly one such scope).
    pub fn find_scope_for_direct(&self, recv_interface: Option<&str>) -> Option<&Scope> {
        if let Some(iface) = recv_interface {
            return self.scopes.iter().find(|s| s.interface.as_deref() == Some(iface));
        }
        let mut candidates = self.scopes.iter().filter(|s| s.interface.is_none());
        let first = candidates.next()?;
        if candidates.next().is_some() {
            tracing::warn!(
                "multiple direct-attach scopes configured with no interface filter; \
                 picking {:?} — set each scope's `interface` field or route via relay (giaddr) to disambiguate",
                first.id
            );
        }
        Some(first)
    }

    pub fn reservation_for(&self, scope_id: &str, mac: &str) -> Option<&Reservation> {
        self.reservations.get(&(scope_id.to_string(), mac.to_lowercase()))
    }

    /// Custom options that apply to this request: scope-level rows, with
    /// any reservation-level row for the same `option_code` overriding the
    /// scope-level one (an admin setting a per-reservation option
    /// presumably means it to win).
    pub fn custom_options_for(&self, scope_id: &str, reservation: Option<&Reservation>) -> Vec<CustomOption> {
        let mut by_code: std::collections::BTreeMap<i32, CustomOption> = self
            .scope_options
            .get(scope_id)
            .into_iter()
            .flatten()
            .map(|o| (o.option_code, o.clone()))
            .collect();
        if let Some(res_opts) = reservation.and_then(|r| self.reservation_options.get(&r.id)) {
            for o in res_opts {
                by_code.insert(o.option_code, o.clone());
            }
        }
        by_code.into_values().collect()
    }
}

pub async fn load_snapshot(pool: &PgPool) -> anyhow::Result<Snapshot> {
    let scope_rows = sqlx::query(
        r#"SELECT id, tenant_id, name, subnet, range_start, range_end, router_ip,
                  dns_servers, domain_name, interface, lease_time_s, renew_time_s,
                  rebind_time_s, ddns_enabled, pxe_next_server, pxe_boot_filename,
                  pxe_uefi_boot_filename
           FROM dhcp_scopes WHERE enabled = true"#,
    )
    .fetch_all(pool)
    .await?;

    let mut scopes = Vec::with_capacity(scope_rows.len());
    for row in scope_rows {
        let subnet_str: String = row.try_get("subnet")?;
        let subnet = match ipnet::Ipv4Net::from_str(&subnet_str) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("scope {}: invalid subnet {subnet_str:?}: {e}", row.try_get::<String, _>("id")?);
                continue;
            }
        };
        let dns_servers: Vec<String> = row.try_get("dns_servers").unwrap_or_default();
        scopes.push(Scope {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            subnet,
            range_start: parse_ip(&row.try_get::<String, _>("range_start")?)?,
            range_end: parse_ip(&row.try_get::<String, _>("range_end")?)?,
            router_ip: opt_parse_ip(row.try_get("router_ip")?),
            dns_servers: dns_servers.iter().filter_map(|s| s.parse().ok()).collect(),
            domain_name: row.try_get("domain_name")?,
            interface: row.try_get("interface")?,
            lease_time_s: row.try_get("lease_time_s")?,
            renew_time_s: row.try_get("renew_time_s")?,
            rebind_time_s: row.try_get("rebind_time_s")?,
            ddns_enabled: row.try_get("ddns_enabled")?,
            pxe_next_server: opt_parse_ip(row.try_get("pxe_next_server")?),
            pxe_boot_filename: row.try_get("pxe_boot_filename")?,
            pxe_uefi_boot_filename: row.try_get("pxe_uefi_boot_filename")?,
        });
    }

    let res_rows = sqlx::query(
        r#"SELECT id, scope_id, mac_address, ip_address, hostname, next_server, boot_filename, uefi_boot_filename
           FROM dhcp_static_leases WHERE enabled = true"#,
    )
    .fetch_all(pool)
    .await?;
    let mut reservations = HashMap::new();
    for row in res_rows {
        let scope_id: String = row.try_get("scope_id")?;
        let mac: String = row.try_get("mac_address")?;
        let ip_address = parse_ip(&row.try_get::<String, _>("ip_address")?)?;
        reservations.insert(
            (scope_id, mac.to_lowercase()),
            Reservation {
                id: row.try_get("id")?,
                ip_address,
                hostname: row.try_get("hostname")?,
                next_server: opt_parse_ip(row.try_get("next_server")?),
                boot_filename: row.try_get("boot_filename")?,
                uefi_boot_filename: row.try_get("uefi_boot_filename")?,
            },
        );
    }

    let relay_rows = sqlx::query(r#"SELECT scope_id, relay_ip, circuit_id_hex, remote_id_hex FROM dhcp_relay_configs"#)
        .fetch_all(pool)
        .await?;
    let mut relay_configs_by_scope: HashMap<String, Vec<RelayConfigEntry>> = HashMap::new();
    for row in relay_rows {
        let scope_id: String = row.try_get("scope_id")?;
        if let Ok(relay_ip) = parse_ip(&row.try_get::<String, _>("relay_ip")?) {
            let circuit_id = row.try_get::<Option<String>, _>("circuit_id_hex")?.and_then(|s| parse_hex_bytes(&s));
            let remote_id = row.try_get::<Option<String>, _>("remote_id_hex")?.and_then(|s| parse_hex_bytes(&s));
            relay_configs_by_scope.entry(scope_id).or_default().push(RelayConfigEntry { relay_ip, circuit_id, remote_id });
        }
    }

    let opt_rows = sqlx::query(
        r#"SELECT scope_id, static_lease_id, option_code, value
           FROM dhcp_options WHERE option_space = 'dhcp4'"#,
    )
    .fetch_all(pool)
    .await?;
    let mut scope_options: HashMap<String, Vec<CustomOption>> = HashMap::new();
    let mut reservation_options: HashMap<String, Vec<CustomOption>> = HashMap::new();
    for row in opt_rows {
        let option = CustomOption { option_code: row.try_get("option_code")?, value: row.try_get("value")? };
        if let Some(scope_id) = row.try_get::<Option<String>, _>("scope_id")? {
            scope_options.entry(scope_id).or_default().push(option);
        } else if let Some(static_lease_id) = row.try_get::<Option<String>, _>("static_lease_id")? {
            reservation_options.entry(static_lease_id).or_default().push(option);
        }
    }

    Ok(Snapshot { scopes, reservations, relay_configs_by_scope, scope_options, reservation_options })
}

fn parse_ip(s: &str) -> anyhow::Result<Ipv4Addr> {
    Ok(s.parse()?)
}

fn opt_parse_ip(s: Option<String>) -> Option<Ipv4Addr> {
    s.and_then(|v| v.parse().ok())
}

/// `circuit_id_hex`/`remote_id_hex` are stored as hex strings (an optional
/// `0x` prefix, matching the convention `dhcp_options.value` also uses —
/// see `options::parse_custom_value`).
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    hex::decode(s).ok()
}

pub async fn refresh_loop(pool: PgPool, snapshot: Arc<ArcSwap<Snapshot>>, interval_s: u64) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
    loop {
        ticker.tick().await;
        match load_snapshot(&pool).await {
            Ok(s) => snapshot.store(Arc::new(s)),
            Err(e) => tracing::warn!("dhcp config refresh failed (keeping previous snapshot): {e}"),
        }
    }
}

/// Allocate (or renew) an IP for `mac` in `scope`'s dynamic pool.
///
/// Race safety across multiple mantis-dhcp instances sharing this DB (the
/// active/active HA model — see design.md §22.5): a free IP has no row to
/// lock, so instead of `SELECT ... FOR UPDATE` over existing leases, the
/// whole "list active leases, pick the first free address, insert" sequence
/// runs inside a Postgres advisory transaction lock keyed on the scope's
/// UUID. Only one allocator per scope executes that sequence at a time,
/// anywhere; the lock releases automatically on commit/rollback.
pub async fn allocate(
    pool: &PgPool,
    scope: &Scope,
    mac: &str,
    client_id: Option<&str>,
    hostname: Option<&str>,
    lease_seconds: i64,
) -> anyhow::Result<Ipv4Addr> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&scope.id)
        .execute(&mut *tx)
        .await?;

    let expires_at = Utc::now() + chrono::Duration::seconds(lease_seconds);

    // Renewal: this client already holds a lease in this scope.
    if let Some(row) = sqlx::query(
        "SELECT ip_address FROM dhcp_leases WHERE scope_id = $1 AND mac_address = $2 AND state = 0",
    )
    .bind(&scope.id)
    .bind(mac)
    .fetch_optional(&mut *tx)
    .await?
    {
        let ip: String = row.try_get("ip_address")?;
        sqlx::query(
            "UPDATE dhcp_leases SET hostname = $1, client_id = $2, expires_at = $3, allocated_at = now()
             WHERE scope_id = $4 AND ip_address = $5",
        )
        .bind(hostname)
        .bind(client_id)
        .bind(expires_at)
        .bind(&scope.id)
        .bind(&ip)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(ip.parse()?);
    }

    let taken = taken_or_reserved_addresses(&mut *tx, &scope.id).await?;

    let start = u32::from(scope.range_start);
    let end = u32::from(scope.range_end);
    let free = (start..=end)
        .map(Ipv4Addr::from)
        .find(|ip| !taken.contains(ip))
        .ok_or_else(|| anyhow::anyhow!("scope {} pool exhausted ({} addresses in use)", scope.name, taken.len()))?;

    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases (id, scope_id, ip_address, mac_address, client_id, hostname, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 0, now(), $7)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET mac_address = excluded.mac_address, client_id = excluded.client_id,
               hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(&scope.id)
    .bind(free.to_string())
    .bind(mac)
    .bind(client_id)
    .bind(hostname)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(free)
}

/// Non-committing preview of a free IP for a DISCOVER's OFFER. No row is
/// written and no lock is held — an OFFER is non-binding per RFC 2131, so a
/// rare race where two clients get offered the same address is expected and
/// resolved at REQUEST time by `claim_specific` (whichever REQUESTs first
/// wins; the loser gets NAK'd and retries with a fresh DISCOVER).
///
/// `excluded` additionally skips any address already ruled out — used by the DISCOVER conflict-detection retry loop
/// (`server.rs::handle_discover`) to move past a candidate an ICMP probe
/// just found to be in use, without needing a DB round-trip to record that
/// before trying the next one.
pub async fn peek_free_ip_excluding(
    pool: &PgPool,
    scope: &Scope,
    excluded: &std::collections::HashSet<Ipv4Addr>,
) -> anyhow::Result<Option<Ipv4Addr>> {
    let taken = taken_or_reserved_addresses(pool, &scope.id).await?;
    let start = u32::from(scope.range_start);
    let end = u32::from(scope.range_end);
    Ok((start..=end).map(Ipv4Addr::from).find(|ip| !taken.contains(ip) && !excluded.contains(ip)))
}

/// Addresses `allocate`/`peek_free_ip_excluding` must never hand to a
/// different client: currently-active-or-declined dynamic leases, plus every
/// address a reservation (`dhcp_static_leases`) in this scope has claimed —
/// without the latter, a reservation whose IP happens to fall inside the
/// dynamic range could be raced away by an unrelated client's DISCOVER
/// before the reserved owner ever shows up (design.md §22.2's in-pool
/// reservation case; matches Kea's own "reservations are never
/// dynamically handed out" behavior).
async fn taken_or_reserved_addresses<'e, E>(executor: E, scope_id: &str) -> anyhow::Result<std::collections::HashSet<Ipv4Addr>>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows = sqlx::query(
        "SELECT ip_address FROM dhcp_leases WHERE scope_id = $1 AND state IN (0, 1)
         UNION
         SELECT ip_address FROM dhcp_static_leases WHERE scope_id = $1 AND enabled = true",
    )
    .bind(scope_id)
    .fetch_all(executor)
    .await?;
    let mut taken = std::collections::HashSet::new();
    for row in rows {
        taken.insert(row.try_get::<String, _>("ip_address")?.parse()?);
    }
    Ok(taken)
}

/// Records a conflict an ICMP probe found *before* any lease was ever
/// allocated for this address — inserted as already-declined (state 1) so
/// every future scan (`peek_free_ip`/`allocate`'s `taken` set) skips it,
/// the same as a post-allocation DHCPDECLINE (`decline`) would.
pub async fn mark_declined_preemptive(pool: &PgPool, scope_id: &str, ip: Ipv4Addr) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases (id, scope_id, ip_address, mac_address, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, '', 1, now(), now())
         ON CONFLICT (scope_id, ip_address) DO UPDATE SET state = 1",
    )
    .bind(&id)
    .bind(scope_id)
    .bind(ip.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Claim a *specific* IP a client REQUESTed (selecting from an OFFER, a
/// reservation, or INIT-REBOOT re-asserting a previous lease). Returns
/// `Ok(false)` — caller should NAK — if that address is currently an active
/// lease for a *different* mac; per-scope advisory lock same as `allocate`.
pub async fn claim_specific(
    pool: &PgPool,
    scope: &Scope,
    ip: Ipv4Addr,
    mac: &str,
    client_id: Option<&str>,
    hostname: Option<&str>,
    lease_seconds: i64,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&scope.id)
        .execute(&mut *tx)
        .await?;

    if let Some(row) = sqlx::query("SELECT mac_address FROM dhcp_leases WHERE scope_id = $1 AND ip_address = $2 AND state = 0")
        .bind(&scope.id)
        .bind(ip.to_string())
        .fetch_optional(&mut *tx)
        .await?
    {
        let held_by: String = row.try_get("mac_address")?;
        if held_by != mac {
            return Ok(false);
        }
    }

    // A reservation for this address belonging to a *different* mac must
    // never be handed out here — the reservation's own owner is served via
    // `confirm_reservation`, not this path; without this check a client
    // that jumps straight to REQUESTing a reserved-but-still-free address
    // (e.g. replaying a stale OFFER from before the reservation existed)
    // could grab it before the real owner ever shows up.
    if let Some(row) = sqlx::query("SELECT mac_address FROM dhcp_static_leases WHERE scope_id = $1 AND ip_address = $2 AND enabled = true")
        .bind(&scope.id)
        .bind(ip.to_string())
        .fetch_optional(&mut *tx)
        .await?
    {
        let reserved_for: String = row.try_get("mac_address")?;
        if !reserved_for.eq_ignore_ascii_case(mac) {
            return Ok(false);
        }
    }

    let expires_at = Utc::now() + chrono::Duration::seconds(lease_seconds);
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases (id, scope_id, ip_address, mac_address, client_id, hostname, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 0, now(), $7)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET mac_address = excluded.mac_address, client_id = excluded.client_id,
               hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(&scope.id)
    .bind(ip.to_string())
    .bind(mac)
    .bind(client_id)
    .bind(hostname)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

/// Confirm a reservation's fixed IP as an active lease row (reservations
/// don't consume pool-scan capacity — they're written directly).
pub async fn confirm_reservation(
    pool: &PgPool,
    scope_id: &str,
    ip: Ipv4Addr,
    mac: &str,
    client_id: Option<&str>,
    hostname: Option<&str>,
    lease_seconds: i64,
) -> anyhow::Result<()> {
    let expires_at = Utc::now() + chrono::Duration::seconds(lease_seconds);
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases (id, scope_id, ip_address, mac_address, client_id, hostname, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, 0, now(), $7)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET mac_address = excluded.mac_address, client_id = excluded.client_id,
               hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(scope_id)
    .bind(ip.to_string())
    .bind(mac)
    .bind(client_id)
    .bind(hostname)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the released lease's hostname (if it had one) so the caller can
/// fire a DDNS delete for it — a DHCPRELEASE carries no hostname option of
/// its own, so this is the only way the caller learns which record to clean up.
pub async fn release(pool: &PgPool, scope_id: &str, mac: &str) -> anyhow::Result<Option<String>> {
    let row = sqlx::query("DELETE FROM dhcp_leases WHERE scope_id = $1 AND mac_address = $2 RETURNING hostname")
        .bind(scope_id)
        .bind(mac)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|r| r.try_get::<Option<String>, _>("hostname").ok().flatten()))
}

/// Returns `true` if `mac` actually held the lease being declined — a
/// DHCPDECLINE is unauthenticated beyond the MAC in the packet, so without
/// this check any on-link host could decline (and thus permanently exclude,
/// pending `sweep_expired`'s probation reclaim) an address it was never
/// granted, including another client's active lease.
pub async fn decline(pool: &PgPool, scope_id: &str, ip: Ipv4Addr, mac: &str) -> anyhow::Result<bool> {
    let result = sqlx::query("UPDATE dhcp_leases SET state = 1 WHERE scope_id = $1 AND ip_address = $2 AND mac_address = $3 AND state = 0")
        .bind(scope_id)
        .bind(ip.to_string())
        .bind(mac)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// A lease swept up either because it expired (state 0) or because its
/// decline probation window elapsed (state 1, see `sweep_expired`) — the
/// caller uses `hostname` to decide whether a DDNS delete is owed for it.
pub struct ExpiredLease {
    pub scope_id: String,
    pub ip: Ipv4Addr,
    pub mac: String,
    pub hostname: Option<String>,
}

/// Expired *active* leases (state 0) are deleted outright (not soft-marked)
/// so the address becomes immediately available to the next allocation scan
/// — see `allocate`'s `taken` set, which is built from currently-existing
/// rows. Declined leases (state 1) are excluded from allocation forever
/// otherwise — see `decline`/`mark_declined_preemptive` — so this also
/// reclaims any whose `decline_probation_s` has elapsed since they were
/// marked, the same probation-then-retry behavior Kea's
/// `decline-probation-period` provides, in case the conflict that caused
/// the decline was transient.
pub async fn sweep_expired(pool: &PgPool, decline_probation_s: i64) -> anyhow::Result<Vec<ExpiredLease>> {
    let probation_cutoff = Utc::now() - chrono::Duration::seconds(decline_probation_s);
    let rows = sqlx::query(
        "DELETE FROM dhcp_leases
         WHERE (state = 0 AND expires_at < now())
            OR (state = 1 AND allocated_at < $1)
         RETURNING scope_id, ip_address, mac_address, hostname",
    )
    .bind(probation_cutoff)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ExpiredLease {
                scope_id: row.try_get("scope_id")?,
                ip: row.try_get::<String, _>("ip_address")?.parse()?,
                mac: row.try_get("mac_address")?,
                hostname: row.try_get("hostname")?,
            })
        })
        .collect()
}

/// This client's existing active lease IP in this scope, if any — lets
/// `handle_discover` re-offer the same address to a renewing client instead
/// of scanning the pool for a fresh one.
pub async fn active_lease_ip(pool: &PgPool, scope_id: &str, mac: &str) -> Option<Ipv4Addr> {
    let row = sqlx::query("SELECT ip_address FROM dhcp_leases WHERE scope_id = $1 AND mac_address = $2 AND state = 0")
        .bind(scope_id)
        .bind(mac)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()?;
    row.try_get::<String, _>("ip_address").ok()?.parse().ok()
}

pub struct ScopeUtilization {
    pub scope_id: String,
    pub scope_name: String,
    pub assigned: i64,
    pub declined: i64,
}

/// Per-scope lease counts for the metrics endpoint (`metrics.rs`) — same
/// source `/api/v1/dhcp/stats` reads on the control-plane side (design.md
/// §22.11), queried directly here rather than proxying through HTTP.
pub async fn scope_utilization(pool: &PgPool) -> anyhow::Result<Vec<ScopeUtilization>> {
    let rows = sqlx::query(
        "SELECT s.id AS scope_id, s.name AS scope_name,
                count(*) FILTER (WHERE l.state = 0) AS assigned,
                count(*) FILTER (WHERE l.state = 1) AS declined
         FROM dhcp_scopes s
         LEFT JOIN dhcp_leases l ON l.scope_id = s.id
         WHERE s.enabled = true
         GROUP BY s.id, s.name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ScopeUtilization {
                scope_id: row.try_get("scope_id")?,
                scope_name: row.try_get("scope_name")?,
                assigned: row.try_get("assigned")?,
                declined: row.try_get("declined")?,
            })
        })
        .collect()
}

pub async fn ddns_retry_queue_depth(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM dhcp_ddns_retries").fetch_one(pool).await?)
}

#[allow(dead_code)]
pub type LeaseExpiry = DateTime<Utc>;

// ── DDNS retry queue ─────────────────────────────────────────────────────────
// A failed POST to /internal/dhcp-event (control plane down, network blip)
// is durable here instead of silently dropped — see ddns.rs's module docs.

pub struct DdnsRetryRow {
    pub id: String,
    pub event: String,
    pub family: String,
    pub scope_id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub duid: Option<String>,
    pub attempts: i32,
}

/// Gives up after this many retries (~channels through `backoff_secs`'
/// doubling-then-capped schedule to roughly an hour of total retry window)
/// rather than keeping a permanently-unreachable control plane's failures
/// queued forever.
const MAX_DDNS_ATTEMPTS: i32 = 8;

fn backoff_secs(attempts: i32) -> i64 {
    (30i64 * 2i64.pow(attempts.clamp(0, 6) as u32)).min(1800)
}

#[allow(clippy::too_many_arguments)]
pub async fn enqueue_ddns_retry(
    pool: &PgPool,
    event: &str,
    family: &str,
    scope_id: &str,
    ip: &str,
    hostname: Option<&str>,
    mac: Option<&str>,
    duid: Option<&str>,
    last_error: &str,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff_secs(0));
    sqlx::query(
        "INSERT INTO dhcp_ddns_retries
            (id, event, family, scope_id, ip, hostname, mac, duid, attempts, next_attempt_at, last_error, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, $10, now())",
    )
    .bind(&id)
    .bind(event)
    .bind(family)
    .bind(scope_id)
    .bind(ip)
    .bind(hostname)
    .bind(mac)
    .bind(duid)
    .bind(next_attempt_at)
    .bind(last_error)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn due_ddns_retries(pool: &PgPool, limit: i64) -> anyhow::Result<Vec<DdnsRetryRow>> {
    let rows = sqlx::query(
        "SELECT id, event, family, scope_id, ip, hostname, mac, duid, attempts
         FROM dhcp_ddns_retries WHERE next_attempt_at <= now() ORDER BY next_attempt_at LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(DdnsRetryRow {
                id: row.try_get("id")?,
                event: row.try_get("event")?,
                family: row.try_get("family")?,
                scope_id: row.try_get("scope_id")?,
                ip: row.try_get("ip")?,
                hostname: row.try_get("hostname")?,
                mac: row.try_get("mac")?,
                duid: row.try_get("duid")?,
                attempts: row.try_get("attempts")?,
            })
        })
        .collect()
}

pub async fn delete_ddns_retry(pool: &PgPool, id: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM dhcp_ddns_retries WHERE id = $1").bind(id).execute(pool).await?;
    Ok(())
}

/// Bumps the attempt count and schedules the next try, or gives up (deletes
/// the row, logs it) after `MAX_DDNS_ATTEMPTS`. Returns `true` if it gave up.
pub async fn reschedule_or_giveup_ddns_retry(pool: &PgPool, id: &str, attempts: i32, error: &str) -> anyhow::Result<bool> {
    let attempts = attempts + 1;
    if attempts >= MAX_DDNS_ATTEMPTS {
        delete_ddns_retry(pool, id).await?;
        return Ok(true);
    }
    let next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff_secs(attempts));
    sqlx::query("UPDATE dhcp_ddns_retries SET attempts = $1, next_attempt_at = $2, last_error = $3 WHERE id = $4")
        .bind(attempts)
        .bind(next_attempt_at)
        .bind(error)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Points at a throwaway Postgres with the real alembic schema applied
    /// (see services/dhcp/mantis-dhcp/README-tests.md for how to stand one
    /// up) — override with TEST_DATABASE_URL. Every test creates its own
    /// fresh tenant+scope row (random UUID), so tests never collide with
    /// each other's data and can run concurrently.
    async fn test_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:15432/test".to_string());
        PgPool::connect(&url).await.expect("connect to TEST_DATABASE_URL")
    }

    /// Inserts a fresh tenant + dhcp_scopes row and returns a `Scope` with a
    /// pool of exactly `pool_size` addresses starting at 10.<octet>.0.10,
    /// where <octet> is derived from the returned scope id so parallel tests
    /// never share a subnet (not that it matters for allocate/claim_specific,
    /// which only look at dhcp_leases rows for this scope_id, but keeps the
    /// fixture realistic).
    async fn make_scope(pool: &PgPool, pool_size: u32) -> Scope {
        let tenant_id = uuid::Uuid::new_v4().to_string();
        let scope_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, now())")
            .bind(&tenant_id)
            .bind(format!("test-{tenant_id}"))
            .execute(pool)
            .await
            .expect("insert test tenant");

        let range_start: Ipv4Addr = "10.99.0.10".parse().unwrap();
        let range_end = Ipv4Addr::from(u32::from(range_start) + pool_size - 1);

        sqlx::query(
            "INSERT INTO dhcp_scopes
                (id, tenant_id, name, subnet, range_start, range_end, dns_servers,
                 lease_time_s, max_lease_time_s, ddns_enabled, ddns_ttl_s, enabled,
                 created_at, updated_at)
             VALUES ($1, $2, $3, '10.99.0.0/24', $4, $5, ARRAY[]::varchar[],
                     3600, 7200, false, 300, true, now(), now())",
        )
        .bind(&scope_id)
        .bind(&tenant_id)
        .bind(format!("test-scope-{scope_id}"))
        .bind(range_start.to_string())
        .bind(range_end.to_string())
        .execute(pool)
        .await
        .expect("insert test scope");

        Scope {
            id: scope_id,
            tenant_id,
            name: "test-scope".to_string(),
            subnet: "10.99.0.0/24".parse().unwrap(),
            range_start,
            range_end,
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

    #[tokio::test]
    async fn allocate_picks_first_free_ip_in_range() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip = allocate(&pool, &scope, "aa:bb:cc:dd:ee:01", None, None, 3600).await.unwrap();
        assert_eq!(ip, scope.range_start);
    }

    #[tokio::test]
    async fn allocate_renews_existing_lease_for_same_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let mac = "aa:bb:cc:dd:ee:02";
        let first = allocate(&pool, &scope, mac, None, None, 3600).await.unwrap();
        let second = allocate(&pool, &scope, mac, None, Some("laptop"), 3600).await.unwrap();
        assert_eq!(first, second, "same mac must get the same IP back on renewal");

        let row = sqlx::query("SELECT hostname FROM dhcp_leases WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(second.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        let hostname: Option<String> = row.try_get("hostname").unwrap();
        assert_eq!(hostname.as_deref(), Some("laptop"), "renewal must update hostname");
    }

    #[tokio::test]
    async fn allocate_gives_different_macs_different_ips() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let a = allocate(&pool, &scope, "aa:bb:cc:dd:ee:03", None, None, 3600).await.unwrap();
        let b = allocate(&pool, &scope, "aa:bb:cc:dd:ee:04", None, None, 3600).await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn allocate_errors_when_pool_exhausted() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 2).await;
        allocate(&pool, &scope, "aa:bb:cc:dd:ee:05", None, None, 3600).await.unwrap();
        allocate(&pool, &scope, "aa:bb:cc:dd:ee:06", None, None, 3600).await.unwrap();
        let err = allocate(&pool, &scope, "aa:bb:cc:dd:ee:07", None, None, 3600).await;
        assert!(err.is_err(), "third client in a 2-address pool must fail, not silently succeed");
    }

    /// The property that actually matters for HA (design.md §22.3): many
    /// concurrent allocators (simulating multiple mantis-dhcp instances
    /// against one Postgres) racing for a small pool must never hand the
    /// same address to two different macs.
    #[tokio::test]
    async fn allocate_is_race_safe_under_concurrency() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 8).await;

        let mut handles = Vec::new();
        for i in 0..8u8 {
            let pool = pool.clone();
            let scope = scope.clone();
            handles.push(tokio::spawn(async move {
                let mac = format!("aa:bb:cc:dd:ee:{i:02x}");
                allocate(&pool, &scope, &mac, None, None, 3600).await
            }));
        }

        let mut ips = std::collections::HashSet::new();
        for h in handles {
            let ip = h.await.unwrap().expect("pool has exactly enough addresses for 8 clients");
            assert!(ips.insert(ip), "two different macs were handed the same IP: {ip}");
        }
        assert_eq!(ips.len(), 8);
    }

    #[tokio::test]
    async fn peek_free_ip_does_not_write_a_row() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 3).await;
        let peeked = peek_free_ip_excluding(&pool, &scope, &Default::default()).await.unwrap();
        assert_eq!(peeked, Some(scope.range_start));

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dhcp_leases WHERE scope_id = $1")
            .bind(&scope.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "peek must not commit a lease row");
    }

    #[tokio::test]
    async fn peek_free_ip_returns_none_when_exhausted() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 1).await;
        allocate(&pool, &scope, "aa:bb:cc:dd:ee:08", None, None, 3600).await.unwrap();
        assert_eq!(peek_free_ip_excluding(&pool, &scope, &Default::default()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn peek_free_ip_excluding_skips_the_excluded_candidate() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 3).await;
        let mut excluded = std::collections::HashSet::new();
        excluded.insert(scope.range_start);
        let peeked = peek_free_ip_excluding(&pool, &scope, &excluded).await.unwrap();
        assert_eq!(peeked, Some(Ipv4Addr::from(u32::from(scope.range_start) + 1)));
    }

    #[tokio::test]
    async fn mark_declined_preemptive_excludes_ip_from_future_allocation() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 2).await;
        mark_declined_preemptive(&pool, &scope.id, scope.range_start).await.unwrap();

        let ip = allocate(&pool, &scope, "aa:bb:cc:dd:ee:22", None, None, 3600).await.unwrap();
        assert_ne!(ip, scope.range_start, "a preemptively-declined address must not be handed out");
    }

    #[tokio::test]
    async fn claim_specific_succeeds_on_free_address() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.12".parse().unwrap();
        let ok = claim_specific(&pool, &scope, ip, "aa:bb:cc:dd:ee:09", None, None, 3600).await.unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn claim_specific_rejects_address_held_by_different_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.13".parse().unwrap();
        assert!(claim_specific(&pool, &scope, ip, "aa:bb:cc:dd:ee:0a", None, None, 3600).await.unwrap());
        let stolen = claim_specific(&pool, &scope, ip, "aa:bb:cc:dd:ee:0b", None, None, 3600).await.unwrap();
        assert!(!stolen, "a different mac must be NAK'd (false), not silently take over the address");
    }

    #[tokio::test]
    async fn claim_specific_allows_same_mac_to_reclaim_its_own_address() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.14".parse().unwrap();
        let mac = "aa:bb:cc:dd:ee:0c";
        assert!(claim_specific(&pool, &scope, ip, mac, None, None, 3600).await.unwrap());
        assert!(claim_specific(&pool, &scope, ip, mac, None, Some("phone"), 3600).await.unwrap());
    }

    /// Inserts a `dhcp_static_leases` reservation row directly, the same way
    /// `load_snapshot_reads_scope_reservation_and_relay` does — used by the
    /// reservation-exclusion tests below, which exercise the raw DB layer
    /// rather than the `Snapshot` mantis-dhcp actually reads reservations
    /// through.
    async fn insert_reservation(pool: &PgPool, scope: &Scope, mac: &str, ip: Ipv4Addr) {
        sqlx::query(
            "INSERT INTO dhcp_static_leases
                (id, scope_id, tenant_id, mac_address, ip_address, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, true, now(), now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&scope.id)
        .bind(&scope.tenant_id)
        .bind(mac)
        .bind(ip.to_string())
        .execute(pool)
        .await
        .expect("insert test reservation");
    }

    #[tokio::test]
    async fn allocate_skips_an_address_reserved_for_a_different_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 3).await;
        // Reserve the pool's first address for a mac that never shows up.
        insert_reservation(&pool, &scope, "aa:bb:cc:dd:ee:40", scope.range_start).await;

        let ip = allocate(&pool, &scope, "aa:bb:cc:dd:ee:41", None, None, 3600).await.unwrap();
        assert_ne!(ip, scope.range_start, "a reserved address must never be dynamically allocated to a different mac");
    }

    #[tokio::test]
    async fn peek_free_ip_skips_an_address_reserved_for_a_different_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 3).await;
        insert_reservation(&pool, &scope, "aa:bb:cc:dd:ee:42", scope.range_start).await;

        let peeked = peek_free_ip_excluding(&pool, &scope, &Default::default()).await.unwrap();
        assert_ne!(peeked, Some(scope.range_start));
    }

    #[tokio::test]
    async fn claim_specific_rejects_an_address_reserved_for_a_different_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.16".parse().unwrap();
        insert_reservation(&pool, &scope, "aa:bb:cc:dd:ee:43", ip).await;

        let stolen = claim_specific(&pool, &scope, ip, "aa:bb:cc:dd:ee:44", None, None, 3600).await.unwrap();
        assert!(!stolen, "an address reserved for another mac must not be claimable via REQUEST");
    }

    #[tokio::test]
    async fn claim_specific_allows_the_reservations_own_mac() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.17".parse().unwrap();
        insert_reservation(&pool, &scope, "aa:bb:cc:dd:ee:45", ip).await;

        let ok = claim_specific(&pool, &scope, ip, "aa:bb:cc:dd:ee:45", None, None, 3600).await.unwrap();
        assert!(ok, "the reservation's own mac must still be able to claim its address via this path");
    }

    #[tokio::test]
    async fn confirm_reservation_upserts_active_lease() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let ip: Ipv4Addr = "10.99.0.15".parse().unwrap();
        confirm_reservation(&pool, &scope.id, ip, "aa:bb:cc:dd:ee:0d", None, Some("printer"), 3600)
            .await
            .unwrap();

        let row = sqlx::query("SELECT hostname, state FROM dhcp_leases WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(ip.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        let hostname: Option<String> = row.try_get("hostname").unwrap();
        let state: i32 = row.try_get("state").unwrap();
        assert_eq!(hostname.as_deref(), Some("printer"));
        assert_eq!(state, 0);
    }

    #[tokio::test]
    async fn release_deletes_the_lease_row() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let mac = "aa:bb:cc:dd:ee:0e";
        allocate(&pool, &scope, mac, None, None, 3600).await.unwrap();
        release(&pool, &scope.id, mac).await.unwrap();
        assert_eq!(active_lease_ip(&pool, &scope.id, mac).await, None);
    }

    #[tokio::test]
    async fn decline_marks_state_and_excludes_from_future_allocation() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 2).await;
        let mac = "aa:bb:cc:dd:ee:0f";
        let ip = allocate(&pool, &scope, mac, None, None, 3600).await.unwrap();
        assert!(decline(&pool, &scope.id, ip, mac).await.unwrap());

        let state: i32 = sqlx::query_scalar("SELECT state FROM dhcp_leases WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(ip.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, 1);

        // Pool has 2 addresses; one is now declined (still "taken" for
        // allocation purposes), so only one more client can get an address.
        allocate(&pool, &scope, "aa:bb:cc:dd:ee:10", None, None, 3600).await.unwrap();
        let err = allocate(&pool, &scope, "aa:bb:cc:dd:ee:11", None, None, 3600).await;
        assert!(err.is_err(), "declined address must still count as taken");
    }

    #[tokio::test]
    async fn decline_rejects_a_mac_that_never_held_the_lease() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 2).await;
        let owner = "aa:bb:cc:dd:ee:30";
        let ip = allocate(&pool, &scope, owner, None, None, 3600).await.unwrap();

        let declined = decline(&pool, &scope.id, ip, "aa:bb:cc:dd:ee:31").await.unwrap();
        assert!(!declined, "a mac that never held this lease must not be able to decline it");

        let state: i32 = sqlx::query_scalar("SELECT state FROM dhcp_leases WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(ip.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, 0, "the real owner's lease must remain active");
    }

    #[tokio::test]
    async fn sweep_expired_deletes_only_expired_active_leases() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;

        // Already-expired lease (negative lease_seconds).
        let expired_mac = "aa:bb:cc:dd:ee:12";
        allocate(&pool, &scope, expired_mac, None, None, -10).await.unwrap();
        // Still-valid lease.
        let live_mac = "aa:bb:cc:dd:ee:13";
        let live_ip = allocate(&pool, &scope, live_mac, None, None, 3600).await.unwrap();

        // `sweep_expired` isn't scoped to one scope_id -- a concurrent test's
        // own sweep call against this same shared Postgres can race in and
        // delete this row first, so the DB post-state (not this call's own
        // return value) is the only reliable thing to assert on here.
        sweep_expired(&pool, 86400).await.unwrap();
        assert_eq!(active_lease_ip(&pool, &scope.id, expired_mac).await, None);
        assert_eq!(active_lease_ip(&pool, &scope.id, live_mac).await, Some(live_ip));
    }

    #[tokio::test]
    async fn sweep_expired_reports_hostname_for_ddns_delete() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let mac = "aa:bb:cc:dd:ee:32";
        allocate(&pool, &scope, mac, None, Some("printer"), -10).await.unwrap();

        let swept = sweep_expired(&pool, 86400).await.unwrap();
        let lease = swept.iter().find(|l| l.mac == mac).expect("expired lease must be reported");
        assert_eq!(lease.hostname.as_deref(), Some("printer"));
    }

    #[tokio::test]
    async fn sweep_expired_reclaims_a_declined_lease_past_its_probation() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 2).await;
        let mac = "aa:bb:cc:dd:ee:33";
        let ip = allocate(&pool, &scope, mac, None, None, 3600).await.unwrap();
        assert!(decline(&pool, &scope.id, ip, mac).await.unwrap());

        // Not yet past probation -- must survive a sweep with a long window.
        let swept = sweep_expired(&pool, 86400).await.unwrap();
        assert!(swept.iter().all(|l| l.ip != ip), "a freshly-declined lease must not be reclaimed early");

        // Back-date allocated_at so it looks like probation has elapsed.
        sqlx::query("UPDATE dhcp_leases SET allocated_at = now() - interval '2 hours' WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(ip.to_string())
            .execute(&pool)
            .await
            .unwrap();

        let swept = sweep_expired(&pool, 3600).await.unwrap();
        assert!(swept.iter().any(|l| l.ip == ip), "a declined lease past its probation window must be reclaimed");

        // Reclaimed, so a fresh allocation can now reuse the address.
        let reused = allocate(&pool, &scope, "aa:bb:cc:dd:ee:34", None, None, 3600).await.unwrap();
        assert_eq!(reused, ip);
    }

    #[tokio::test]
    async fn enqueue_ddns_retry_is_not_immediately_due() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        enqueue_ddns_retry(&pool, "add", "4", &scope.id, "10.99.0.30", Some("phone"), Some("aa:bb:cc:dd:ee:20"), None, "connection refused")
            .await
            .unwrap();
        // backoff_secs(0) = 30s, so a freshly-enqueued row must not show up
        // as due yet — otherwise every failure would be retried in a tight
        // loop instead of backing off. A generous limit (rather than a
        // small one like 10) so this assertion isn't at the mercy of
        // however many older rows other test runs have left due in the
        // meantime — this row is what's under test, not the backlog size.
        let due = due_ddns_retries(&pool, 10_000).await.unwrap();
        assert!(due.iter().all(|r| r.scope_id != scope.id), "freshly-enqueued retry must not be immediately due");

        // Clean up rather than leaving a row that becomes due 30s from now
        // and clutters every subsequent test run against this DB.
        sqlx::query("DELETE FROM dhcp_ddns_retries WHERE scope_id = $1").bind(&scope.id).execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn due_ddns_retries_finds_a_row_scheduled_in_the_past() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let id = uuid::Uuid::new_v4().to_string();
        // Insert directly with next_attempt_at already in the past, rather
        // than waiting out enqueue_ddns_retry's real backoff in a test.
        sqlx::query(
            "INSERT INTO dhcp_ddns_retries
                (id, event, family, scope_id, ip, hostname, mac, duid, attempts, next_attempt_at, last_error, created_at)
             VALUES ($1, 'add', '4', $2, '10.99.0.31', 'tv', 'aa:bb:cc:dd:ee:21', NULL, 0, now() - interval '1 minute', 'boom', now())",
        )
        .bind(&id)
        .bind(&scope.id)
        .execute(&pool)
        .await
        .unwrap();

        // Generous limit — see enqueue_ddns_retry_is_not_immediately_due's
        // comment on why a small one flakes as other tests' rows accumulate.
        let due = due_ddns_retries(&pool, 10_000).await.unwrap();
        assert!(due.iter().any(|r| r.id == id));

        sqlx::query("DELETE FROM dhcp_ddns_retries WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn reschedule_or_giveup_reschedules_before_max_attempts() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO dhcp_ddns_retries
                (id, event, family, scope_id, ip, attempts, next_attempt_at, created_at)
             VALUES ($1, 'add', '4', $2, '10.99.0.32', 0, now() - interval '1 minute', now())",
        )
        .bind(&id)
        .bind(&scope.id)
        .execute(&pool)
        .await
        .unwrap();

        let gave_up = reschedule_or_giveup_ddns_retry(&pool, &id, 0, "still failing").await.unwrap();
        assert!(!gave_up);
        let (attempts, next_due): (i32, bool) = {
            let row = sqlx::query("SELECT attempts, next_attempt_at > now() AS not_due FROM dhcp_ddns_retries WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
            (row.try_get("attempts").unwrap(), row.try_get("not_due").unwrap())
        };
        assert_eq!(attempts, 1);
        assert!(next_due, "rescheduled row must be pushed into the future, not left immediately due again");

        sqlx::query("DELETE FROM dhcp_ddns_retries WHERE id = $1").bind(&id).execute(&pool).await.unwrap();
    }

    #[tokio::test]
    async fn reschedule_or_giveup_deletes_row_after_max_attempts() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO dhcp_ddns_retries
                (id, event, family, scope_id, ip, attempts, next_attempt_at, created_at)
             VALUES ($1, 'add', '4', $2, '10.99.0.33', $3, now() - interval '1 minute', now())",
        )
        .bind(&id)
        .bind(&scope.id)
        .bind(MAX_DDNS_ATTEMPTS - 1)
        .execute(&pool)
        .await
        .unwrap();

        let gave_up = reschedule_or_giveup_ddns_retry(&pool, &id, MAX_DDNS_ATTEMPTS - 1, "still failing").await.unwrap();
        assert!(gave_up);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dhcp_ddns_retries WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "row must be deleted once max attempts is reached");
    }

    #[tokio::test]
    async fn delete_ddns_retry_removes_the_row() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO dhcp_ddns_retries
                (id, event, family, scope_id, ip, attempts, next_attempt_at, created_at)
             VALUES ($1, 'add', '4', $2, '10.99.0.34', 0, now(), now())",
        )
        .bind(&id)
        .bind(&scope.id)
        .execute(&pool)
        .await
        .unwrap();

        delete_ddns_retry(&pool, &id).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dhcp_ddns_retries WHERE id = $1")
            .bind(&id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn load_snapshot_reads_scope_reservation_and_relay() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;

        sqlx::query(
            "INSERT INTO dhcp_static_leases
                (id, scope_id, tenant_id, mac_address, ip_address, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, true, now(), now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&scope.id)
        .bind(&scope.tenant_id)
        .bind("aa:bb:cc:dd:ee:14")
        .bind("10.99.0.20")
        .execute(&pool)
        .await
        .unwrap();

        // Randomized (not a fixed literal) so a leftover row from a previous
        // run of this test against the same throwaway container can never
        // collide with this run's relay_ip. No `rand` dependency needed —
        // a fresh UUID's bytes are already random.
        let rand_bytes = *uuid::Uuid::new_v4().as_bytes();
        let relay_ip = Ipv4Addr::new(10, rand_bytes[0], rand_bytes[1], rand_bytes[2].max(1));
        sqlx::query("INSERT INTO dhcp_relay_configs (id, scope_id, relay_ip) VALUES ($1, $2, $3)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&scope.id)
            .bind(relay_ip.to_string())
            .execute(&pool)
            .await
            .unwrap();

        let snapshot = load_snapshot(&pool).await.unwrap();
        assert!(snapshot.scopes.iter().any(|s| s.id == scope.id));
        let res = snapshot.reservation_for(&scope.id, "AA:BB:CC:DD:EE:14");
        assert_eq!(res.map(|r| r.ip_address), Some("10.99.0.20".parse().unwrap()), "reservation lookup must be case-insensitive on mac");

        let relay_scope = snapshot.find_scope_for_relay(relay_ip, None, None);
        assert_eq!(relay_scope.map(|s| s.id.as_str()), Some(scope.id.as_str()));
    }

    #[tokio::test]
    async fn load_snapshot_reads_custom_options_and_reservation_overrides_scope() {
        let pool = test_pool().await;
        let scope = make_scope(&pool, 5).await;
        let res_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO dhcp_static_leases
                (id, scope_id, tenant_id, mac_address, ip_address, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, 'aa:bb:cc:dd:ee:15', '10.99.0.21', true, now(), now())",
        )
        .bind(&res_id)
        .bind(&scope.id)
        .bind(&scope.tenant_id)
        .execute(&pool)
        .await
        .unwrap();

        // Scope-level: sets option 66 (TFTP server name).
        sqlx::query(
            "INSERT INTO dhcp_options (id, scope_id, static_lease_id, option_code, option_space, value, always_send)
             VALUES ($1, $2, NULL, 66, 'dhcp4', 'tftp.example.com', false)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&scope.id)
        .execute(&pool)
        .await
        .unwrap();
        // Reservation-level: overrides option 66 for this one reservation.
        sqlx::query(
            "INSERT INTO dhcp_options (id, scope_id, static_lease_id, option_code, option_space, value, always_send)
             VALUES ($1, NULL, $2, 66, 'dhcp4', 'tftp2.example.com', false)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&res_id)
        .execute(&pool)
        .await
        .unwrap();
        // A different option_space must be ignored entirely (not yet supported — v4 only).
        sqlx::query(
            "INSERT INTO dhcp_options (id, scope_id, static_lease_id, option_code, option_space, value, always_send)
             VALUES ($1, $2, NULL, 1, 'dhcp6', 'should-not-appear', false)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&scope.id)
        .execute(&pool)
        .await
        .unwrap();

        let snapshot = load_snapshot(&pool).await.unwrap();
        let reservation = snapshot.reservation_for(&scope.id, "aa:bb:cc:dd:ee:15").unwrap();
        assert_eq!(reservation.id, res_id);

        let scope_only = snapshot.custom_options_for(&scope.id, None);
        assert_eq!(scope_only.len(), 1);
        assert_eq!(scope_only[0].value, "tftp.example.com");

        let merged = snapshot.custom_options_for(&scope.id, Some(reservation));
        assert_eq!(merged.len(), 1, "reservation-level option 66 must replace, not duplicate, the scope-level one");
        assert_eq!(merged[0].value, "tftp2.example.com");
    }

    fn in_memory_scope(id: &str, subnet: &str) -> Scope {
        Scope {
            id: id.to_string(),
            tenant_id: "t1".to_string(),
            name: id.to_string(),
            subnet: subnet.parse().unwrap(),
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

    /// The security-relevant case (design.md §22.12): a scope with an
    /// explicit relay allow-list must reject a giaddr that isn't on it, even
    /// though that giaddr sits inside the scope's own subnet and would
    /// otherwise match via the subnet-containment fallback.
    #[test]
    fn find_scope_for_relay_rejects_unlisted_giaddr_when_scope_has_an_allow_list() {
        let scope = in_memory_scope("s1", "10.0.0.0/24");
        let trusted_relay: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let untrusted_relay: Ipv4Addr = "10.0.0.99".parse().unwrap(); // also inside 10.0.0.0/24

        let mut relay_configs_by_scope = HashMap::new();
        relay_configs_by_scope.insert(
            "s1".to_string(),
            vec![RelayConfigEntry { relay_ip: trusted_relay, circuit_id: None, remote_id: None }],
        );

        let snapshot = Snapshot {
            scopes: vec![scope],
            reservations: HashMap::new(),
            relay_configs_by_scope,
            scope_options: HashMap::new(),
            reservation_options: HashMap::new(),
        };

        assert_eq!(snapshot.find_scope_for_relay(trusted_relay, None, None).map(|s| s.id.as_str()), Some("s1"));
        assert!(
            snapshot.find_scope_for_relay(untrusted_relay, None, None).is_none(),
            "an untrusted relay inside the scope's subnet must not bypass its allow-list"
        );
    }

    /// A scope with *no* relay config rows at all keeps the old
    /// subnet-containment convenience behavior — the allow-list check only
    /// kicks in for scopes that opted into one.
    #[test]
    fn find_scope_for_relay_falls_back_to_subnet_containment_when_no_allow_list_configured() {
        let scope = in_memory_scope("s1", "10.0.0.0/24");
        let snapshot = Snapshot {
            scopes: vec![scope],
            reservations: HashMap::new(),
            relay_configs_by_scope: HashMap::new(),
            scope_options: HashMap::new(),
            reservation_options: HashMap::new(),
        };

        let giaddr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert_eq!(snapshot.find_scope_for_relay(giaddr, None, None).map(|s| s.id.as_str()), Some("s1"));
    }

    /// A `circuit_id`/`remote_id` requirement on a relay config row must be
    /// satisfied by the packet's own Option 82 sub-options, not just the
    /// giaddr — this is the actual "client-classing" design.md §22.7 refers
    /// to: a relay_ip match alone isn't enough if the row asked for more.
    #[test]
    fn find_scope_for_relay_enforces_circuit_id_when_configured() {
        let scope = in_memory_scope("s1", "10.0.0.0/24");
        let relay_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mut relay_configs_by_scope = HashMap::new();
        relay_configs_by_scope.insert(
            "s1".to_string(),
            vec![RelayConfigEntry { relay_ip, circuit_id: Some(vec![0x01, 0x02]), remote_id: None }],
        );
        let snapshot = Snapshot {
            scopes: vec![scope],
            reservations: HashMap::new(),
            relay_configs_by_scope,
            scope_options: HashMap::new(),
            reservation_options: HashMap::new(),
        };

        assert_eq!(
            snapshot.find_scope_for_relay(relay_ip, Some(&[0x01, 0x02]), None).map(|s| s.id.as_str()),
            Some("s1"),
            "matching circuit-id must be accepted"
        );
        assert!(
            snapshot.find_scope_for_relay(relay_ip, Some(&[0xff, 0xff]), None).is_none(),
            "a relay_ip match with the wrong circuit-id must still be rejected"
        );
        assert!(
            snapshot.find_scope_for_relay(relay_ip, None, None).is_none(),
            "a relay_ip match with no circuit-id at all (row requires one) must be rejected"
        );
    }
}
