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

//! DHCPv6 counterpart of `db.rs`: reads `dhcp_scopes6`/`dhcp_static_leases6`
//! directly (same live-config, no push/sync step) and owns `dhcp_leases6`.
//!
//! The advisory-lock HA model is identical to v4's (see `db.rs::allocate`'s
//! docs) — same Postgres, same `pg_advisory_xact_lock`, just a different
//! namespace argument (2 for IA_NA, 3 for IA_PD; v4 uses 0) so a v4 and v6
//! instance sharing one scope UUID space by coincidence can never contend on
//! the same lock key.
//!
//! IA_NA pool selection differs fundamentally from v4's: a v4 pool is a
//! handful to a few thousand addresses, small enough to linearly scan for
//! the first free one. A v6 pool can span a /64 (~1.8*10^19 addresses) —
//! linear scanning is not an option. Instead, [`allocate_na`] picks a
//! uniformly random candidate in the pool's range and retries a bounded
//! number of times on collision (`RANDOM_PICK_ATTEMPTS`) — the same
//! technique real DHCPv6 servers use for large ranges. This means pool
//! *exhaustion* can only ever be inferred probabilistically (repeated
//! collisions), never proven exactly the way v4's `taken.len()` can; a
//! sparse-but-technically-full pool would need many more than
//! `RANDOM_PICK_ATTEMPTS` collisions to even show up as a false exhaustion
//! signal, which is the standard trade-off this technique makes.
//!
//! IA_PD is scoped to exactly the single `pd_prefix`/`pd_prefix_len` a
//! `DhcpScope6` row carries — there's no prefix *pool*, just one prefix the
//! whole scope can delegate to at most one DUID at a time (see
//! [`allocate_pd`]). A scope with `pd_prefix` unset simply never satisfies
//! an IA_PD request.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Utc;
use sqlx::PgPool;
use sqlx::Row;

#[derive(Debug, Clone)]
pub struct Scope6 {
    pub id: String,
    #[allow(dead_code)] // informational; not yet used for per-tenant DHCP logging
    pub tenant_id: String,
    pub name: String,
    pub subnet: ipnet::Ipv6Net,
    pub pool_start: Ipv6Addr,
    pub pool_end: Ipv6Addr,
    pub pd_prefix: Option<Ipv6Addr>,
    pub pd_prefix_len: Option<u8>,
    pub dns_servers: Vec<Ipv6Addr>,
    pub domain_name: Option<String>,
    pub interface: Option<String>,
    pub preferred_lifetime_s: i32,
    pub valid_lifetime_s: i32,
    pub renew_time_s: Option<i32>,
    pub rebind_time_s: Option<i32>,
    pub ddns_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Reservation6 {
    pub id: String,
    pub ip_address: Ipv6Addr,
    pub hostname: Option<String>,
}

/// Immutable, hot-swappable view of DHCPv6 config — same idiom as
/// `db::Snapshot` (see its docs).
pub struct Snapshot6 {
    pub scopes: Vec<Scope6>,
    /// keyed by (scope_id, normalized DUID hex — see `normalize_duid`)
    pub reservations: HashMap<(String, String), Reservation6>,
}

impl Snapshot6 {
    /// Scope for a relayed request: the innermost relay's `link_addr`
    /// (`server6.rs::unwrap_relay`) indicates the client's actual subnet —
    /// direct v6 counterpart of v4's giaddr-subnet-containment fallback.
    /// There's no relay allow-list/authentication here yet (v4's
    /// `find_scope_for_relay` circuit/remote-id check, design.md §22.7) —
    /// an honest gap, tracked the same way §22.9 flagged the whole daemon
    /// before this existed.
    pub fn find_scope_for_link(&self, link_addr: Ipv6Addr) -> Option<&Scope6> {
        self.scopes.iter().find(|s| s.subnet.contains(&link_addr))
    }

    /// Direct-attached (multicast, unrelayed) dispatch — same limitation as
    /// v4's `find_scope_for_direct`: unambiguous only via `recv_interface`
    /// (not implemented for v6 in this version; always `None` — see
    /// `main6.rs`) or when exactly one enabled scope has no `interface`
    /// filter.
    pub fn find_scope_for_direct(&self, recv_interface: Option<&str>) -> Option<&Scope6> {
        if let Some(iface) = recv_interface {
            return self.scopes.iter().find(|s| s.interface.as_deref() == Some(iface));
        }
        let mut candidates = self.scopes.iter().filter(|s| s.interface.is_none());
        let first = candidates.next()?;
        if candidates.next().is_some() {
            tracing::warn!(
                "multiple direct-attach v6 scopes configured with no interface filter; \
                 picking {:?} — set each scope's `interface` field or route via a relay to disambiguate",
                first.id
            );
        }
        Some(first)
    }

    pub fn reservation_for(&self, scope_id: &str, duid: &str) -> Option<&Reservation6> {
        self.reservations.get(&(scope_id.to_string(), normalize_duid(duid)))
    }
}

/// DUIDs are compared as their bare hex digits, case- and
/// separator-insensitive (`00:01:00:01:...` and `0001000100AB...` must match
/// the same reservation) — mirrors how v4 already treats `mac_address`
/// case-insensitively.
pub fn normalize_duid(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit()).flat_map(|c| c.to_lowercase()).collect()
}

pub async fn load_snapshot6(pool: &PgPool) -> anyhow::Result<Snapshot6> {
    let scope_rows = sqlx::query(
        r#"SELECT id, tenant_id, name, subnet, pool_start, pool_end, pd_prefix, pd_prefix_len,
                  dns_servers, domain_name, interface, preferred_lifetime_s, valid_lifetime_s,
                  renew_time_s, rebind_time_s, ddns_enabled
           FROM dhcp_scopes6 WHERE enabled = true"#,
    )
    .fetch_all(pool)
    .await?;

    let mut scopes = Vec::with_capacity(scope_rows.len());
    for row in scope_rows {
        let subnet_str: String = row.try_get("subnet")?;
        let subnet = match ipnet::Ipv6Net::from_str(&subnet_str) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("scope6 {}: invalid subnet {subnet_str:?}: {e}", row.try_get::<String, _>("id")?);
                continue;
            }
        };
        let dns_servers: Vec<String> = row.try_get("dns_servers").unwrap_or_default();
        let pd_prefix: Option<String> = row.try_get("pd_prefix")?;
        scopes.push(Scope6 {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            subnet,
            pool_start: parse_ip6(&row.try_get::<String, _>("pool_start")?)?,
            pool_end: parse_ip6(&row.try_get::<String, _>("pool_end")?)?,
            pd_prefix: pd_prefix.and_then(|s| s.parse().ok()),
            pd_prefix_len: row.try_get::<Option<i32>, _>("pd_prefix_len")?.map(|v| v as u8),
            dns_servers: dns_servers.iter().filter_map(|s| s.parse().ok()).collect(),
            domain_name: row.try_get("domain_name")?,
            interface: row.try_get("interface")?,
            preferred_lifetime_s: row.try_get("preferred_lifetime_s")?,
            valid_lifetime_s: row.try_get("valid_lifetime_s")?,
            renew_time_s: row.try_get("renew_time_s")?,
            rebind_time_s: row.try_get("rebind_time_s")?,
            ddns_enabled: row.try_get("ddns_enabled")?,
        });
    }

    let res_rows = sqlx::query(
        r#"SELECT id, scope_id, duid, ip_address, hostname FROM dhcp_static_leases6 WHERE enabled = true"#,
    )
    .fetch_all(pool)
    .await?;
    let mut reservations = HashMap::new();
    for row in res_rows {
        let scope_id: String = row.try_get("scope_id")?;
        let duid: String = row.try_get("duid")?;
        let ip_address = parse_ip6(&row.try_get::<String, _>("ip_address")?)?;
        reservations.insert(
            (scope_id, normalize_duid(&duid)),
            Reservation6 { id: row.try_get("id")?, ip_address, hostname: row.try_get("hostname")? },
        );
    }

    Ok(Snapshot6 { scopes, reservations })
}

fn parse_ip6(s: &str) -> anyhow::Result<Ipv6Addr> {
    Ok(s.parse()?)
}

pub async fn refresh_loop6(pool: PgPool, snapshot: Arc<ArcSwap<Snapshot6>>, interval_s: u64) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_s));
    loop {
        ticker.tick().await;
        match load_snapshot6(&pool).await {
            Ok(s) => snapshot.store(Arc::new(s)),
            Err(e) => tracing::warn!("dhcp6 config refresh failed (keeping previous snapshot): {e}"),
        }
    }
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

fn u128_to_ipv6(v: u128) -> Ipv6Addr {
    Ipv6Addr::from(v.to_be_bytes())
}

/// Bounded retries for `allocate_na`'s random-probe pool scan — see module
/// docs for why a v6 pool can't be linearly scanned the way v4's can.
const RANDOM_PICK_ATTEMPTS: u32 = 16;

/// Allocate (or renew) an IA_NA address for `duid` in `scope`'s dynamic
/// pool. Race-safety model identical to v4's `allocate` (advisory lock,
/// same transaction as the insert) — see its docs; namespace `2` here vs.
/// v4's `0` so the two daemons' locks never collide on a coincidentally
/// equal scope UUID.
pub async fn allocate_na(
    pool: &PgPool,
    scope: &Scope6,
    duid: &str,
    hostname: Option<&str>,
    preferred_s: i64,
    valid_s: i64,
) -> anyhow::Result<Ipv6Addr> {
    let duid_hex = normalize_duid(duid);
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(&scope.id)
        .execute(&mut *tx)
        .await?;

    let expires_at = Utc::now() + chrono::Duration::seconds(valid_s.max(preferred_s));

    if let Some(row) = sqlx::query(
        "SELECT ip_address FROM dhcp_leases6 WHERE scope_id = $1 AND duid = $2 AND lease_type = 0 AND state = 0",
    )
    .bind(&scope.id)
    .bind(&duid_hex)
    .fetch_optional(&mut *tx)
    .await?
    {
        let ip: String = row.try_get("ip_address")?;
        sqlx::query("UPDATE dhcp_leases6 SET hostname = $1, expires_at = $2, allocated_at = now() WHERE scope_id = $3 AND ip_address = $4")
            .bind(hostname)
            .bind(expires_at)
            .bind(&scope.id)
            .bind(&ip)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(ip.parse()?);
    }

    let lo = ipv6_to_u128(scope.pool_start);
    let hi = ipv6_to_u128(scope.pool_end);
    let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };

    for _ in 0..RANDOM_PICK_ATTEMPTS {
        let candidate = u128_to_ipv6(rand::random_range(lo..=hi));
        // Also excludes an address reserved for a *different* DUID (mirrors
        // v4's `taken_or_reserved_addresses`) — a reservation is served via
        // `confirm_reservation_na`, never handed out here.
        let exists = sqlx::query(
            "SELECT 1 FROM dhcp_leases6 WHERE scope_id = $1 AND ip_address = $2 AND lease_type = 0 AND state IN (0, 1)
             UNION
             SELECT 1 FROM dhcp_static_leases6 WHERE scope_id = $1 AND ip_address = $2 AND enabled = true",
        )
        .bind(&scope.id)
        .bind(candidate.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_some() {
            continue;
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO dhcp_leases6 (id, scope_id, ip_address, duid, hostname, lease_type, state, allocated_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, 0, 0, now(), $6)
             ON CONFLICT (scope_id, ip_address) DO UPDATE
               SET duid = excluded.duid, hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
        )
        .bind(&id)
        .bind(&scope.id)
        .bind(candidate.to_string())
        .bind(&duid_hex)
        .bind(hostname)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(candidate);
    }

    anyhow::bail!(
        "scope {} ({}): {RANDOM_PICK_ATTEMPTS} random pool picks all collided -- pool likely exhausted \
         (or pathologically dense for its size)",
        scope.name, scope.id
    )
}

/// Claim a *specific* IA_NA address the client itself asserted (a REQUEST
/// echoing an ADVERTISE's IAAddr, or a RENEW/REBIND/CONFIRM re-asserting a
/// previously-held one). `Ok(false)` — caller should reply with
/// `Status::NoBinding`/`NotOnLink` — if it's currently held by a *different*
/// DUID.
pub async fn claim_specific_na(
    pool: &PgPool,
    scope: &Scope6,
    ip: Ipv6Addr,
    duid: &str,
    hostname: Option<&str>,
    preferred_s: i64,
    valid_s: i64,
) -> anyhow::Result<bool> {
    let duid_hex = normalize_duid(duid);
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 2))")
        .bind(&scope.id)
        .execute(&mut *tx)
        .await?;

    if let Some(row) = sqlx::query(
        "SELECT duid FROM dhcp_leases6 WHERE scope_id = $1 AND ip_address = $2 AND lease_type = 0 AND state = 0",
    )
    .bind(&scope.id)
    .bind(ip.to_string())
    .fetch_optional(&mut *tx)
    .await?
    {
        let held_by: String = row.try_get("duid")?;
        if held_by != duid_hex {
            return Ok(false);
        }
    }

    // Same reservation-ownership guard as v4's `claim_specific` — see its
    // comment for why.
    if let Some(row) = sqlx::query("SELECT duid FROM dhcp_static_leases6 WHERE scope_id = $1 AND ip_address = $2 AND enabled = true")
        .bind(&scope.id)
        .bind(ip.to_string())
        .fetch_optional(&mut *tx)
        .await?
    {
        let reserved_for: String = row.try_get("duid")?;
        if normalize_duid(&reserved_for) != duid_hex {
            return Ok(false);
        }
    }

    let expires_at = Utc::now() + chrono::Duration::seconds(valid_s.max(preferred_s));
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases6 (id, scope_id, ip_address, duid, hostname, lease_type, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, 0, 0, now(), $6)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET duid = excluded.duid, hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(&scope.id)
    .bind(ip.to_string())
    .bind(&duid_hex)
    .bind(hostname)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

pub async fn confirm_reservation_na(
    pool: &PgPool,
    scope_id: &str,
    ip: Ipv6Addr,
    duid: &str,
    hostname: Option<&str>,
    preferred_s: i64,
    valid_s: i64,
) -> anyhow::Result<()> {
    let expires_at = Utc::now() + chrono::Duration::seconds(valid_s.max(preferred_s));
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases6 (id, scope_id, ip_address, duid, hostname, lease_type, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, 0, 0, now(), $6)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET duid = excluded.duid, hostname = excluded.hostname, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(scope_id)
    .bind(ip.to_string())
    .bind(normalize_duid(duid))
    .bind(hostname)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Returns the released lease's `(ip, hostname)` if it had one — a
/// DHCPv6 RELEASE carries no hostname of its own, so this is the only way
/// the caller learns which address/record to send a DDNS delete for.
pub async fn release_na(pool: &PgPool, scope_id: &str, duid: &str) -> anyhow::Result<Option<(Ipv6Addr, Option<String>)>> {
    let row = sqlx::query(
        "DELETE FROM dhcp_leases6 WHERE scope_id = $1 AND duid = $2 AND lease_type = 0 RETURNING ip_address, hostname",
    )
    .bind(scope_id)
    .bind(normalize_duid(duid))
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let ip: String = row.try_get("ip_address")?;
    let hostname: Option<String> = row.try_get("hostname")?;
    Ok(Some((ip.parse()?, hostname)))
}

/// Returns `true` if `duid` actually held the lease being declined — same
/// ownership guard as v4's `decline`, since a DHCPv6 DECLINE is equally
/// unauthenticated beyond the DUID in the packet.
pub async fn decline_na(pool: &PgPool, scope_id: &str, ip: Ipv6Addr, duid: &str) -> anyhow::Result<bool> {
    let result = sqlx::query(
        "UPDATE dhcp_leases6 SET state = 1 WHERE scope_id = $1 AND ip_address = $2 AND lease_type = 0 AND duid = $3 AND state = 0",
    )
    .bind(scope_id)
    .bind(ip.to_string())
    .bind(normalize_duid(duid))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// This DUID's existing active IA_NA lease in this scope, if any — lets
/// `handle_solicit` re-advertise the same address on a repeated SOLICIT
/// instead of picking a fresh random candidate.
pub async fn active_lease_na(pool: &PgPool, scope_id: &str, duid: &str) -> Option<Ipv6Addr> {
    let row = sqlx::query(
        "SELECT ip_address FROM dhcp_leases6 WHERE scope_id = $1 AND duid = $2 AND lease_type = 0 AND state = 0",
    )
    .bind(scope_id)
    .bind(normalize_duid(duid))
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;
    row.try_get::<String, _>("ip_address").ok()?.parse().ok()
}

/// Delegate `scope`'s single `pd_prefix`/`pd_prefix_len` to `duid` — there is
/// no prefix *pool*, just this one prefix (see module docs), so unlike
/// `allocate_na` there's nothing to scan: either the prefix is unheld (or
/// already held by this same DUID, i.e. a renewal), or it's held by someone
/// else and this request gets `NoPrefixAvail`. `Ok(None)` covers both "no PD
/// configured for this scope" and "already delegated elsewhere" — the
/// caller (`server6.rs`) replies `NoPrefixAvail`/omits the IA_PD either way.
pub async fn allocate_pd(
    pool: &PgPool,
    scope: &Scope6,
    duid: &str,
    preferred_s: i64,
    valid_s: i64,
) -> anyhow::Result<Option<(Ipv6Addr, u8)>> {
    let (Some(prefix), Some(len)) = (scope.pd_prefix, scope.pd_prefix_len) else {
        return Ok(None);
    };
    let duid_hex = normalize_duid(duid);
    let key = format!("{prefix}/{len}");

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 3))")
        .bind(&scope.id)
        .execute(&mut *tx)
        .await?;

    if let Some(row) = sqlx::query(
        "SELECT duid FROM dhcp_leases6 WHERE scope_id = $1 AND ip_address = $2 AND lease_type = 2 AND state = 0",
    )
    .bind(&scope.id)
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let held_by: String = row.try_get("duid")?;
        if held_by != duid_hex {
            return Ok(None);
        }
    }

    let expires_at = Utc::now() + chrono::Duration::seconds(valid_s.max(preferred_s));
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_leases6 (id, scope_id, ip_address, duid, hostname, lease_type, state, allocated_at, expires_at)
         VALUES ($1, $2, $3, $4, NULL, 2, 0, now(), $5)
         ON CONFLICT (scope_id, ip_address) DO UPDATE
           SET duid = excluded.duid, state = 0, allocated_at = now(), expires_at = excluded.expires_at",
    )
    .bind(&id)
    .bind(&scope.id)
    .bind(&key)
    .bind(&duid_hex)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some((prefix, len)))
}

pub async fn release_pd(pool: &PgPool, scope_id: &str, duid: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM dhcp_leases6 WHERE scope_id = $1 AND duid = $2 AND lease_type = 2")
        .bind(scope_id)
        .bind(normalize_duid(duid))
        .execute(pool)
        .await?;
    Ok(())
}

/// v6 counterpart of `db::ExpiredLease`. `duid` is always the normalized
/// hex form (see `normalize_duid`); IA_PD rows never carry a `hostname`
/// (`allocate_pd` never sets one), so they're naturally skipped by callers
/// that only act when `hostname.is_some()`.
pub struct ExpiredLease6 {
    pub scope_id: String,
    pub ip: Ipv6Addr,
    pub duid: String,
    pub hostname: Option<String>,
}

/// Expired leases (IA_NA and IA_PD alike, state 0) are deleted outright,
/// same immediately-reusable rationale as v4's `sweep_expired`. IA_NA leases
/// past their `decline_probation_s` (state 1) are reclaimed the same way too
/// — see `sweep_expired`'s docs.
pub async fn sweep_expired6(pool: &PgPool, decline_probation_s: i64) -> anyhow::Result<Vec<ExpiredLease6>> {
    let probation_cutoff = Utc::now() - chrono::Duration::seconds(decline_probation_s);
    let rows = sqlx::query(
        "DELETE FROM dhcp_leases6
         WHERE (state = 0 AND expires_at < now())
            OR (state = 1 AND allocated_at < $1)
         RETURNING scope_id, ip_address, duid, hostname",
    )
    .bind(probation_cutoff)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ExpiredLease6 {
                scope_id: row.try_get("scope_id")?,
                ip: row.try_get::<String, _>("ip_address")?.parse()?,
                duid: row.try_get("duid")?,
                hostname: row.try_get("hostname")?,
            })
        })
        .collect()
}

pub struct ScopeUtilization6 {
    pub scope_id: String,
    pub scope_name: String,
    pub assigned_na: i64,
    pub assigned_pd: i64,
    pub declined: i64,
}

pub async fn scope_utilization6(pool: &PgPool) -> anyhow::Result<Vec<ScopeUtilization6>> {
    let rows = sqlx::query(
        "SELECT s.id AS scope_id, s.name AS scope_name,
                count(*) FILTER (WHERE l.state = 0 AND l.lease_type = 0) AS assigned_na,
                count(*) FILTER (WHERE l.state = 0 AND l.lease_type = 2) AS assigned_pd,
                count(*) FILTER (WHERE l.state = 1) AS declined
         FROM dhcp_scopes6 s
         LEFT JOIN dhcp_leases6 l ON l.scope_id = s.id
         WHERE s.enabled = true
         GROUP BY s.id, s.name",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ScopeUtilization6 {
                scope_id: row.try_get("scope_id")?,
                scope_name: row.try_get("scope_name")?,
                assigned_na: row.try_get("assigned_na")?,
                assigned_pd: row.try_get("assigned_pd")?,
                declined: row.try_get("declined")?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_duid_strips_colons_and_lowercases() {
        assert_eq!(normalize_duid("00:01:00:01:2B:3C:4D:5E"), "000100012b3c4d5e");
    }

    #[test]
    fn normalize_duid_matches_regardless_of_separator_style() {
        let a = normalize_duid("0001-0001-2b3c-4d5e");
        let b = normalize_duid("00:01:00:01:2b:3c:4d:5e");
        let c = normalize_duid("000100012b3c4d5e");
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn ipv6_u128_roundtrip() {
        let ip: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        assert_eq!(u128_to_ipv6(ipv6_to_u128(ip)), ip);
    }

    fn test_scope() -> Scope6 {
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
    fn find_scope_for_link_matches_subnet_containment() {
        let snap = Snapshot6 { scopes: vec![test_scope()], reservations: HashMap::new() };
        let link: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(snap.find_scope_for_link(link).unwrap().id, "s1");
        let outside: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(snap.find_scope_for_link(outside).is_none());
    }

    #[test]
    fn find_scope_for_direct_matches_exact_interface() {
        let mut eth0 = test_scope();
        eth0.id = "s-eth0".to_string();
        eth0.interface = Some("eth0".to_string());
        let mut eth1 = test_scope();
        eth1.id = "s-eth1".to_string();
        eth1.interface = Some("eth1".to_string());
        let snap = Snapshot6 { scopes: vec![eth0, eth1], reservations: HashMap::new() };
        assert_eq!(snap.find_scope_for_direct(Some("eth1")).unwrap().id, "s-eth1");
    }

    #[test]
    fn find_scope_for_direct_picks_sole_interfaceless_scope_on_wildcard() {
        let snap = Snapshot6 { scopes: vec![test_scope()], reservations: HashMap::new() };
        assert_eq!(snap.find_scope_for_direct(None).unwrap().id, "s1");
    }

    #[test]
    fn reservation_for_normalizes_duid_lookup() {
        let mut reservations = HashMap::new();
        reservations.insert(
            ("s1".to_string(), normalize_duid("00:01:00:01:aa:bb")),
            Reservation6 { id: "r1".to_string(), ip_address: "2001:db8::42".parse().unwrap(), hostname: None },
        );
        let snap = Snapshot6 { scopes: vec![test_scope()], reservations };
        assert_eq!(snap.reservation_for("s1", "0001 0001 AA BB").unwrap().id, "r1");
        assert!(snap.reservation_for("s1", "00:01:00:01:aa:cc").is_none());
    }

    // ── DB-backed tests (README-tests.md) ───────────────────────────────────
    // Same rationale as db.rs's own DB-backed tests: the advisory-lock/
    // ON CONFLICT allocation logic is deliberately exercised against a real
    // Postgres, not mocked.

    async fn test_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:15432/test".to_string());
        PgPool::connect(&url).await.expect("connect to TEST_DATABASE_URL")
    }

    /// Inserts a fresh tenant + `dhcp_scopes6` row (random subnet per call
    /// so parallel tests never collide) and returns a matching [`Scope6`].
    /// `pd` controls whether the scope carries a `pd_prefix`/`pd_prefix_len`.
    async fn make_scope6(pool: &PgPool, pd: bool) -> Scope6 {
        let tenant_id = uuid::Uuid::new_v4().to_string();
        let scope_id = uuid::Uuid::new_v4().to_string();
        let octet = (uuid::Uuid::new_v4().as_u128() % 0xfff) as u32;
        let subnet_str = format!("2001:db8:{octet:x}::/64");
        let pool_start: Ipv6Addr = format!("2001:db8:{octet:x}::100").parse().unwrap();
        let pool_end: Ipv6Addr = format!("2001:db8:{octet:x}::200").parse().unwrap();
        let (pd_prefix, pd_prefix_len): (Option<Ipv6Addr>, Option<i32>) =
            if pd { (Some(format!("2001:db8:{octet:x}:f000::").parse().unwrap()), Some(64)) } else { (None, None) };

        sqlx::query("INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, now())")
            .bind(&tenant_id)
            .bind(format!("test6-{tenant_id}"))
            .execute(pool)
            .await
            .expect("insert test tenant");

        sqlx::query(
            "INSERT INTO dhcp_scopes6
                (id, tenant_id, name, subnet, pool_start, pool_end, pd_prefix, pd_prefix_len,
                 dns_servers, preferred_lifetime_s, valid_lifetime_s, ddns_enabled, ddns_ttl_s,
                 enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ARRAY[]::varchar[], 3000, 4000, false, 300,
                     true, now(), now())",
        )
        .bind(&scope_id)
        .bind(&tenant_id)
        .bind(format!("test6-scope-{scope_id}"))
        .bind(&subnet_str)
        .bind(pool_start.to_string())
        .bind(pool_end.to_string())
        .bind(pd_prefix.map(|p| p.to_string()))
        .bind(pd_prefix_len)
        .execute(pool)
        .await
        .expect("insert test scope6");

        Scope6 {
            id: scope_id,
            tenant_id,
            name: "test6-scope".to_string(),
            subnet: subnet_str.parse().unwrap(),
            pool_start,
            pool_end,
            pd_prefix,
            pd_prefix_len: pd_prefix_len.map(|v| v as u8),
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

    fn fresh_duid() -> String {
        hex::encode(uuid::Uuid::new_v4().as_bytes())
    }

    #[tokio::test]
    async fn allocate_na_picks_a_free_address_in_the_pool_range() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip = allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await.unwrap();
        assert!(ipv6_to_u128(ip) >= ipv6_to_u128(scope.pool_start));
        assert!(ipv6_to_u128(ip) <= ipv6_to_u128(scope.pool_end));
    }

    #[tokio::test]
    async fn allocate_na_renews_existing_lease_for_same_duid() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let duid = fresh_duid();
        let first = allocate_na(&pool, &scope, &duid, None, 3000, 4000).await.unwrap();
        let second = allocate_na(&pool, &scope, &duid, None, 3000, 4000).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn allocate_na_gives_different_duids_different_addresses() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let a = allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await.unwrap();
        let b = allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await.unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn claim_specific_na_succeeds_on_a_free_address_then_rejects_a_different_duid() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip = scope.pool_start;
        let duid_a = fresh_duid();
        assert!(claim_specific_na(&pool, &scope, ip, &duid_a, None, 3000, 4000).await.unwrap());

        let duid_b = fresh_duid();
        assert!(!claim_specific_na(&pool, &scope, ip, &duid_b, None, 3000, 4000).await.unwrap());
        // The original holder can still reclaim/renew its own address.
        assert!(claim_specific_na(&pool, &scope, ip, &duid_a, None, 3000, 4000).await.unwrap());
    }

    /// Inserts a `dhcp_static_leases6` reservation row directly — v6
    /// counterpart of db.rs's `insert_reservation` test helper.
    async fn insert_reservation6(pool: &PgPool, scope: &Scope6, duid: &str, ip: Ipv6Addr) {
        sqlx::query(
            "INSERT INTO dhcp_static_leases6
                (id, scope_id, tenant_id, duid, ip_address, enabled, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, true, now(), now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&scope.id)
        .bind(&scope.tenant_id)
        .bind(duid)
        .bind(ip.to_string())
        .execute(pool)
        .await
        .expect("insert test reservation6");
    }

    #[tokio::test]
    async fn allocate_na_skips_an_address_reserved_for_a_different_duid() {
        let pool = test_pool().await;
        // A 1-address pool makes the reservation the only candidate, so a
        // pool-exhausted error proves the reservation was actually skipped
        // rather than won by chance.
        let mut scope = make_scope6(&pool, false).await;
        scope.pool_end = scope.pool_start;
        insert_reservation6(&pool, &scope, &fresh_duid(), scope.pool_start).await;

        let err = allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await;
        assert!(err.is_err(), "the sole address being reserved for another duid must starve a dynamic allocation");
    }

    #[tokio::test]
    async fn claim_specific_na_rejects_an_address_reserved_for_a_different_duid() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip = scope.pool_start;
        insert_reservation6(&pool, &scope, &fresh_duid(), ip).await;

        let stolen = claim_specific_na(&pool, &scope, ip, &fresh_duid(), None, 3000, 4000).await.unwrap();
        assert!(!stolen, "an address reserved for another duid must not be claimable via REQUEST");
    }

    #[tokio::test]
    async fn confirm_reservation_na_upserts_an_active_lease() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip: Ipv6Addr = "2001:db8::dead".parse().unwrap();
        let duid = fresh_duid();
        confirm_reservation_na(&pool, &scope.id, ip, &duid, Some("host6"), 3000, 4000).await.unwrap();
        assert_eq!(active_lease_na(&pool, &scope.id, &duid).await, Some(ip));
    }

    #[tokio::test]
    async fn release_na_deletes_the_lease_row() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let duid = fresh_duid();
        allocate_na(&pool, &scope, &duid, None, 3000, 4000).await.unwrap();
        assert!(active_lease_na(&pool, &scope.id, &duid).await.is_some());
        release_na(&pool, &scope.id, &duid).await.unwrap();
        assert!(active_lease_na(&pool, &scope.id, &duid).await.is_none());
    }

    #[tokio::test]
    async fn decline_na_marks_state_and_excludes_from_future_allocation() {
        let pool = test_pool().await;
        // A 1-address pool makes the post-decline exhaustion easy to assert.
        let mut scope = make_scope6(&pool, false).await;
        scope.pool_end = scope.pool_start;
        let ip = scope.pool_start;
        let duid = fresh_duid();
        assert!(claim_specific_na(&pool, &scope, ip, &duid, None, 3000, 4000).await.unwrap());
        assert!(decline_na(&pool, &scope.id, ip, &duid).await.unwrap());
        assert!(active_lease_na(&pool, &scope.id, &duid).await.is_none());
        // Pool is exhausted now (the sole address is declined, not free).
        assert!(allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await.is_err());
    }

    #[tokio::test]
    async fn decline_na_rejects_a_duid_that_never_held_the_lease() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip = scope.pool_start;
        let owner = fresh_duid();
        assert!(claim_specific_na(&pool, &scope, ip, &owner, None, 3000, 4000).await.unwrap());

        let declined = decline_na(&pool, &scope.id, ip, &fresh_duid()).await.unwrap();
        assert!(!declined, "a duid that never held this lease must not be able to decline it");
        assert_eq!(active_lease_na(&pool, &scope.id, &owner).await, Some(ip));
    }

    #[tokio::test]
    async fn allocate_pd_delegates_the_scope_prefix_and_renews_for_the_same_duid() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, true).await;
        let duid = fresh_duid();
        let first = allocate_pd(&pool, &scope, &duid, 3000, 4000).await.unwrap().unwrap();
        assert_eq!(first, (scope.pd_prefix.unwrap(), scope.pd_prefix_len.unwrap()));
        let second = allocate_pd(&pool, &scope, &duid, 3000, 4000).await.unwrap().unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn allocate_pd_rejects_a_second_duid_while_the_prefix_is_held() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, true).await;
        assert!(allocate_pd(&pool, &scope, &fresh_duid(), 3000, 4000).await.unwrap().is_some());
        assert!(allocate_pd(&pool, &scope, &fresh_duid(), 3000, 4000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn allocate_pd_returns_none_when_scope_has_no_pd_configured() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        assert!(allocate_pd(&pool, &scope, &fresh_duid(), 3000, 4000).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn release_pd_frees_the_prefix_for_a_different_duid() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, true).await;
        let duid_a = fresh_duid();
        allocate_pd(&pool, &scope, &duid_a, 3000, 4000).await.unwrap().unwrap();
        release_pd(&pool, &scope.id, &duid_a).await.unwrap();

        let duid_b = fresh_duid();
        assert!(allocate_pd(&pool, &scope, &duid_b, 3000, 4000).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn sweep_expired6_deletes_only_expired_active_leases() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let duid = fresh_duid();
        // valid_s negative -> already-expired expires_at.
        allocate_na(&pool, &scope, &duid, None, -10, -10).await.unwrap();
        // Same race caveat as db.rs's `sweep_expired_deletes_only_expired_active_leases`
        // -- assert DB post-state, not this call's own return value.
        sweep_expired6(&pool, 86400).await.unwrap();
        assert!(active_lease_na(&pool, &scope.id, &duid).await.is_none());
    }

    #[tokio::test]
    async fn sweep_expired6_reclaims_a_declined_lease_past_its_probation() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, false).await;
        let ip = scope.pool_start;
        let duid = fresh_duid();
        assert!(claim_specific_na(&pool, &scope, ip, &duid, None, 3000, 4000).await.unwrap());
        assert!(decline_na(&pool, &scope.id, ip, &duid).await.unwrap());

        let swept = sweep_expired6(&pool, 86400).await.unwrap();
        assert!(swept.iter().all(|l| l.ip != ip), "a freshly-declined lease must not be reclaimed early");

        sqlx::query("UPDATE dhcp_leases6 SET allocated_at = now() - interval '2 hours' WHERE scope_id = $1 AND ip_address = $2")
            .bind(&scope.id)
            .bind(ip.to_string())
            .execute(&pool)
            .await
            .unwrap();

        let swept = sweep_expired6(&pool, 3600).await.unwrap();
        assert!(swept.iter().any(|l| l.ip == ip), "a declined lease past its probation window must be reclaimed");
    }

    #[tokio::test]
    async fn scope_utilization6_counts_na_pd_and_declined_separately() {
        let pool = test_pool().await;
        let scope = make_scope6(&pool, true).await;
        allocate_na(&pool, &scope, &fresh_duid(), None, 3000, 4000).await.unwrap();
        allocate_pd(&pool, &scope, &fresh_duid(), 3000, 4000).await.unwrap();
        let declined_ip = scope.pool_end;
        let declined_duid = fresh_duid();
        assert!(claim_specific_na(&pool, &scope, declined_ip, &declined_duid, None, 3000, 4000).await.unwrap());
        assert!(decline_na(&pool, &scope.id, declined_ip, &declined_duid).await.unwrap());

        let rows = scope_utilization6(&pool).await.unwrap();
        let row = rows.iter().find(|r| r.scope_id == scope.id).expect("scope present in utilization rows");
        assert_eq!(row.assigned_na, 1);
        assert_eq!(row.assigned_pd, 1);
        assert_eq!(row.declined, 1);
    }
}
