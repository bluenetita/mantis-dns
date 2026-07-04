//! Per-pool-member health monitoring (design.md §21.4, Sprint 18).
//!
//! Watches the upstream bundle store for version changes and (re-)spawns
//! per-member probe loops. Each loop sends a DNS SOA/A/TXT probe at the
//! pool's configured interval, drives a state machine
//! (Unknown → Healthy / Unhealthy), and updates a shared `HealthStore`
//! consumed by `UpstreamBundleForwarder` at query time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use tokio::task::JoinSet;
use tracing::{info, warn};

use crate::upstream_bundle::{
    build_hickory_resolver, PoolConfig, PoolMember, ResolverConfig_, UpstreamBundleStore,
};

// ── Health snapshot ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MemberHealthSnapshot {
    pub healthy: bool,
    pub latency_ema_us: u64,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl Default for MemberHealthSnapshot {
    /// Unknown state = optimistically healthy until we have probe data.
    fn default() -> Self {
        Self {
            healthy: true,
            latency_ema_us: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}

// ── HealthStore ────────────────────────────────────────────────────────────────

/// Lock-free, ARC-swap-backed store of per-(pool, resolver) health state.
/// Readers pay only a pointer load; writers do a full clone (rare — one write
/// per probe period per member).
pub struct HealthStore {
    inner: ArcSwap<HashMap<(String, String), MemberHealthSnapshot>>,
}

impl HealthStore {
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::from_pointee(HashMap::new()),
        })
    }

    /// True if the member is healthy, or if we have no data yet (optimistic).
    pub fn is_healthy(&self, pool_id: &str, resolver_id: &str) -> bool {
        self.inner
            .load()
            .get(&(pool_id.to_string(), resolver_id.to_string()))
            .map(|s| s.healthy)
            .unwrap_or(true)
    }

    pub fn snapshot(&self, pool_id: &str, resolver_id: &str) -> MemberHealthSnapshot {
        self.inner
            .load()
            .get(&(pool_id.to_string(), resolver_id.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn update(&self, pool_id: &str, resolver_id: &str, snap: MemberHealthSnapshot) {
        let key = (pool_id.to_string(), resolver_id.to_string());
        let old = self.inner.load();
        let mut next = (**old).clone();
        next.insert(key, snap);
        self.inner.store(Arc::new(next));
    }

    /// Returns resolver IDs of healthy members ordered by the pool's member
    /// list ordering. Falls back to all members if none are healthy (fail-open).
    pub fn healthy_members(&self, pool_id: &str, members: &[PoolMember]) -> Vec<String> {
        let snap = self.inner.load();
        let healthy: Vec<String> = members
            .iter()
            .filter(|m| {
                snap.get(&(pool_id.to_string(), m.resolver_id.clone()))
                    .map(|s| s.healthy)
                    .unwrap_or(true)
            })
            .map(|m| m.resolver_id.clone())
            .collect();
        if healthy.is_empty() {
            members.iter().map(|m| m.resolver_id.clone()).collect()
        } else {
            healthy
        }
    }
}

// ── Probe ──────────────────────────────────────────────────────────────────────

async fn probe_once(
    resolver: &Resolver<TokioConnectionProvider>,
    health_check_query: &str,
    health_check_type: &str,
) -> Result<Duration> {
    let start = Instant::now();
    let name: Name = health_check_query
        .parse()
        .unwrap_or_else(|_| Name::root());

    let record_type = match health_check_type {
        "a" => RecordType::A,
        "txt" => RecordType::TXT,
        _ => RecordType::SOA,
    };

    match resolver.lookup(name, record_type).await {
        Ok(_) => {}
        Err(e) => {
            // ResolveErrorKind is not publicly re-exported in hickory-resolver 0.25.
            // Check the Debug representation for the variant name instead.
            // "NoRecordsFound" = NXDOMAIN / NODATA — resolver IS reachable, probe healthy.
            // Anything else (Timeout, IO, TLS, Proto) = transport failure = unhealthy.
            if !format!("{e:?}").contains("NoRecordsFound") {
                return Err(anyhow::anyhow!("probe error: {e}"));
            }
        }
    }

    Ok(start.elapsed())
}

// ── Per-member probe loop ──────────────────────────────────────────────────────

async fn probe_member_loop(
    pool_id: String,
    pool: PoolConfig,
    member: PoolMember,
    resolver_cfg: ResolverConfig_,
    health_store: Arc<HealthStore>,
) {
    let probe_interval = Duration::from_secs(pool.health_check_interval_s.max(5));
    let probe_timeout = Duration::from_millis(pool.health_check_timeout_ms.max(500));

    let Some(resolver) = build_hickory_resolver(&resolver_cfg, pool.health_check_timeout_ms, false)
    else {
        warn!(
            pool_id = %pool_id,
            resolver_id = %member.resolver_id,
            "cannot build resolver for health probe — member stays in unknown (healthy) state"
        );
        return;
    };

    const EMA_ALPHA: f64 = 0.2;
    let mut snap = health_store.snapshot(&pool_id, &member.resolver_id);

    loop {
        let result = tokio::time::timeout(
            probe_timeout,
            probe_once(&resolver, &pool.health_check_query, &pool.health_check_type),
        )
        .await;

        let probe_ok = match result {
            Ok(Ok(latency)) => {
                let us = latency.as_micros() as f64;
                snap.latency_ema_us = if snap.latency_ema_us == 0 {
                    us as u64
                } else {
                    (EMA_ALPHA * us + (1.0 - EMA_ALPHA) * snap.latency_ema_us as f64) as u64
                };
                true
            }
            Ok(Err(e)) => {
                // Probe returned but got an error (timeout at DNS layer, IO, etc.)
                // Log only first failure to avoid spam.
                if snap.consecutive_failures == 0 {
                    warn!(
                        pool_id = %pool_id,
                        resolver_id = %member.resolver_id,
                        error = %e,
                        "upstream probe failed"
                    );
                }
                false
            }
            Err(_elapsed) => false, // tokio timeout
        };

        let was_healthy = snap.healthy;

        if probe_ok {
            snap.consecutive_failures = 0;
            snap.consecutive_successes += 1;
            if !snap.healthy && snap.consecutive_successes >= pool.healthy_threshold {
                snap.healthy = true;
            }
        } else {
            snap.consecutive_successes = 0;
            snap.consecutive_failures += 1;
            if snap.healthy && snap.consecutive_failures >= pool.unhealthy_threshold {
                snap.healthy = false;
            }
        }

        if snap.healthy != was_healthy {
            if snap.healthy {
                info!(
                    pool_id = %pool_id,
                    resolver_id = %member.resolver_id,
                    latency_ms = snap.latency_ema_us / 1000,
                    "upstream resolver recovered"
                );
            } else {
                warn!(
                    pool_id = %pool_id,
                    resolver_id = %member.resolver_id,
                    consecutive_failures = snap.consecutive_failures,
                    "upstream resolver marked unhealthy"
                );
            }
        }

        health_store.update(&pool_id, &member.resolver_id, snap.clone());

        // Back off when unhealthy to avoid hammering a dead resolver.
        // Capped at 5× the configured interval or 5 minutes, whichever is smaller.
        let sleep_for = if snap.healthy {
            probe_interval
        } else {
            (probe_interval * 5).min(Duration::from_secs(300))
        };
        tokio::time::sleep(sleep_for).await;
    }
}

// ── Public monitor task ────────────────────────────────────────────────────────

/// Watches for bundle version changes, cancels old probe tasks, and spawns new
/// ones per pool member. Runs forever — call `tokio::spawn(run_health_monitor(...))`.
pub async fn run_health_monitor(
    bundle_store: Arc<UpstreamBundleStore>,
    health_store: Arc<HealthStore>,
) {
    let mut last_version: u64 = 0;
    let mut probe_set: JoinSet<()> = JoinSet::new();

    loop {
        if let Some(bundle) = bundle_store.current() {
            if bundle.version != last_version {
                last_version = bundle.version;

                probe_set.abort_all();
                while probe_set.try_join_next().is_some() {}

                let mut spawned: usize = 0;
                for (pool_id, pool) in &bundle.pools {
                    for member in &pool.members {
                        let Some(resolver_cfg) =
                            bundle.resolvers.get(&member.resolver_id).cloned()
                        else {
                            continue;
                        };
                        probe_set.spawn(probe_member_loop(
                            pool_id.clone(),
                            pool.clone(),
                            member.clone(),
                            resolver_cfg,
                            health_store.clone(),
                        ));
                        spawned += 1;
                    }
                }

                info!(
                    bundle_version = last_version,
                    probe_tasks = spawned,
                    "health monitor re-armed for new upstream bundle"
                );
            }
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
