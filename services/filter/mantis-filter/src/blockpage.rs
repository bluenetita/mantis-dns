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

//! Co-hosted HTTP block-page listener.
//!
//! When a policy uses `BLOCK_MODE_REDIRECT`, blocked A/AAAA queries resolve to
//! this node's block-page IP (see `apply_block_response` in `lib.rs`). A web
//! navigation to a blocked domain then lands here. We reuse the same
//! client-IP → bundle resolution as the DNS path, re-run `decide()` on the
//! requested Host to recover the matched category, fetch the tenant's branding
//! template from the control plane (cached), and render an explanation page.
//!
//! This is deliberately off the DNS hot path: it runs as its own Tokio task on
//! a separate listener and never touches the resolver's UDP/TCP servers.
//!
//! Phase 1 is HTTP-only. HTTPS block pages cannot present a valid certificate
//! for the *blocked* domain without a device-installed root CA, so TLS is
//! deferred (see docs/design-block-page.md §4.2).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::any;
use axum::Router;
use mantis_bundle::Bundle;
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::{decide, with_service_token, AppState, TenantRouter};

/// Branding/config for a group's block page, served by the control plane at
/// `GET /api/v1/groups/{group_id}/block-template`. Every field is optional so
/// a partially-configured template still renders against built-in defaults.
#[derive(Clone, Debug, Deserialize)]
pub struct BlockTemplate {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub logo_url: Option<String>,
    #[serde(default)]
    pub brand_color: Option<String>,
    #[serde(default = "default_true")]
    pub show_domain: bool,
    #[serde(default = "default_true")]
    pub show_category: bool,
    #[serde(default)]
    pub contact_url: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for BlockTemplate {
    fn default() -> Self {
        Self {
            title: None,
            message: None,
            logo_url: None,
            brand_color: None,
            show_domain: true,
            show_category: true,
            contact_url: None,
        }
    }
}

/// Where the listener resolves a client IP to a policy bundle. Mirrors the two
/// DNS serving modes so the block page shows the same tenant's policy the DNS
/// path enforced.
#[derive(Clone)]
pub enum BlockPageBundles {
    Single(Arc<AppState>),
    Multi(Arc<TenantRouter>),
}

impl BlockPageBundles {
    fn resolve(&self, ip: IpAddr) -> Option<Arc<Bundle>> {
        match self {
            BlockPageBundles::Single(state) => state.store.current(),
            BlockPageBundles::Multi(router) => router.bundle_for(ip),
        }
    }
}

/// In-memory template cache keyed by group id. Branding is not on the DNS hot
/// path, so the listener pulls it lazily from the control plane and caches both
/// hits and misses for `ttl` to avoid hammering control on a busy block IP.
struct TemplateCache {
    control_url: String,
    client: reqwest::Client,
    ttl: Duration,
    entries: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    fetched_at: Instant,
    template: Option<Arc<BlockTemplate>>,
}

impl TemplateCache {
    fn new(control_url: String) -> Self {
        Self {
            control_url,
            client: reqwest::Client::new(),
            ttl: Duration::from_secs(60),
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn get(&self, group_id: &str) -> Option<Arc<BlockTemplate>> {
        if group_id.is_empty() {
            return None;
        }
        // Fast path: fresh cache entry (hit or negative).
        {
            let entries = self.entries.lock().unwrap();
            if let Some(entry) = entries.get(group_id) {
                if entry.fetched_at.elapsed() < self.ttl {
                    return entry.template.clone();
                }
            }
        }
        // Slow path: (re)fetch. On error keep serving built-in defaults and
        // cache the miss so a flood of blocked hits doesn't stampede control.
        let template = match self.fetch(group_id).await {
            Ok(t) => t.map(Arc::new),
            Err(e) => {
                warn!("block template fetch failed for group {group_id}: {e}");
                None
            }
        };
        self.entries.lock().unwrap().insert(
            group_id.to_string(),
            CacheEntry {
                fetched_at: Instant::now(),
                template: template.clone(),
            },
        );
        template
    }

    async fn fetch(&self, group_id: &str) -> anyhow::Result<Option<BlockTemplate>> {
        let url = format!(
            "{}/api/v1/groups/{group_id}/block-template",
            self.control_url
        );
        let resp = with_service_token(self.client.get(url)).send().await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        Ok(Some(resp.json().await?))
    }
}

#[derive(Clone)]
struct BlockPageAppState {
    bundles: BlockPageBundles,
    cache: Arc<TemplateCache>,
}

/// Binds the block-page HTTP listener and serves every request with the block
/// page. Runs until the listener errors; spawned as its own task from `main`.
pub async fn run_block_page_server(
    listener: TcpListener,
    bundles: BlockPageBundles,
    control_url: String,
) -> anyhow::Result<()> {
    let local_addr = listener.local_addr()?;
    info!("mantis-filter block-page HTTP listener bound on {local_addr}");

    let state = BlockPageAppState {
        bundles,
        cache: Arc::new(TemplateCache::new(control_url)),
    };
    // Every path/method returns the block page — the client asked for a blocked
    // site, whatever the URL was.
    let app = Router::new().fallback(any(handle)).with_state(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn handle(
    State(state): State<BlockPageAppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // The blocked hostname is the Host header (strip any :port).
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    let bundle = state.bundles.resolve(peer.ip());
    let (group_id, category) = match bundle.as_deref() {
        Some(b) => {
            let outcome = decide(b, &host);
            (b.group_id.clone(), outcome.matched_category)
        }
        None => (String::new(), None),
    };

    let template = state.cache.get(&group_id).await;
    let html = render_page(template.as_deref(), &host, category.as_deref());
    // 200 (not 403): captive-portal detectors and plain browsers render the
    // body cleanly on 200; a 4xx can trigger a browser error page instead.
    (StatusCode::OK, Html(html))
}

/// Renders the block page. Uses the template's branding where present and falls
/// back to neutral built-in defaults otherwise. All interpolated values are
/// HTML-escaped.
fn render_page(template: Option<&BlockTemplate>, domain: &str, category: Option<&str>) -> String {
    let default = BlockTemplate::default();
    let t = template.unwrap_or(&default);

    let title = t.title.as_deref().unwrap_or("Access blocked");
    let message = t
        .message
        .as_deref()
        .unwrap_or("This site has been blocked by your network's content policy.");
    let color = sanitize_color(t.brand_color.as_deref()).unwrap_or_else(|| "#c0392b".to_string());

    let mut body = String::new();
    if let Some(logo) = t.logo_url.as_deref().filter(|s| !s.is_empty()).and_then(sanitize_url) {
        body.push_str(&format!(
            "<img class=\"logo\" src=\"{}\" alt=\"\">",
            escape_html(logo)
        ));
    }
    body.push_str(&format!("<h1>{}</h1>", escape_html(title)));
    body.push_str(&format!("<p class=\"msg\">{}</p>", escape_html(message)));

    if t.show_domain && !domain.is_empty() {
        body.push_str(&format!(
            "<p class=\"domain\">Requested site: <strong>{}</strong></p>",
            escape_html(domain)
        ));
    }
    if t.show_category {
        if let Some(cat) = category.filter(|c| !c.is_empty()) {
            body.push_str(&format!(
                "<p class=\"reason\">Category: <strong>{}</strong></p>",
                escape_html(cat)
            ));
        }
    }
    if let Some(url) = t.contact_url.as_deref().filter(|s| !s.is_empty()).and_then(sanitize_url) {
        body.push_str(&format!(
            "<p class=\"contact\"><a href=\"{0}\">Request access or contact your administrator</a></p>",
            escape_html(url)
        ));
    }

    format!(
        "<!doctype html>\n<html lang=\"en\"><head>\
<meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title}</title>\
<style>\
:root{{color-scheme:light dark}}\
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f4f5;color:#18181b}}\
.card{{max-width:32rem;margin:1rem;padding:2.5rem;background:#fff;border-radius:12px;\
box-shadow:0 10px 30px rgba(0,0,0,.08);border-top:6px solid {color};text-align:center}}\
.logo{{max-height:56px;margin-bottom:1rem}}\
h1{{margin:.25rem 0 1rem;font-size:1.5rem;color:{color}}}\
.msg{{font-size:1.05rem;line-height:1.5}}\
.domain,.reason{{margin:.5rem 0;color:#52525b;font-size:.95rem}}\
.contact{{margin-top:1.5rem}}\
.contact a{{color:{color}}}\
@media(prefers-color-scheme:dark){{body{{background:#18181b;color:#f4f4f5}}\
.card{{background:#27272a;box-shadow:none}}.domain,.reason{{color:#a1a1aa}}}}\
</style></head><body><main class=\"card\">{body}</main></body></html>",
        title = escape_html(title),
        color = color,
        body = body,
    )
}

/// Minimal HTML-escaping for interpolated, attacker-influenced values (the
/// requested Host in particular).
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Only allows http(s) URLs for branding links/images. `escape_html` stops
/// these values from breaking out of the surrounding HTML attribute, but it
/// doesn't stop a `javascript:`/`data:` URI from still running when the
/// visitor clicks it — this closes that off. These values come from the
/// control plane's per-tenant branding config, so this matters only if that
/// connection or the stored value itself is compromised.
fn sanitize_url(url: &str) -> Option<&str> {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://")).then_some(trimmed)
}

/// Accepts only a simple `#rgb`/`#rrggbb` hex color so a stored brand color
/// can't inject arbitrary CSS into the page.
fn sanitize_color(color: Option<&str>) -> Option<String> {
    let c = color?.trim();
    let hex = c.strip_prefix('#')?;
    let ok = matches!(hex.len(), 3 | 6) && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    ok.then(|| format!("#{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_host_header_injection() {
        let html = render_page(None, "<script>evil()</script>.example", None);
        assert!(!html.contains("<script>evil"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn renders_category_and_domain_by_default() {
        let html = render_page(None, "ads.example", Some("advertising"));
        assert!(html.contains("ads.example"));
        assert!(html.contains("advertising"));
    }

    #[test]
    fn honors_show_flags() {
        let t = BlockTemplate {
            show_domain: false,
            show_category: false,
            ..Default::default()
        };
        let html = render_page(Some(&t), "ads.example", Some("advertising"));
        assert!(!html.contains("ads.example"));
        assert!(!html.contains("advertising"));
    }

    #[test]
    fn rejects_non_hex_brand_color() {
        assert_eq!(sanitize_color(Some("#abc")), Some("#abc".to_string()));
        assert_eq!(sanitize_color(Some("#aabbcc")), Some("#aabbcc".to_string()));
        assert_eq!(sanitize_color(Some("red;}body{display:none")), None);
        assert_eq!(sanitize_color(Some("#xyz")), None);
    }

    #[test]
    fn rejects_non_http_schemes_for_branding_urls() {
        assert_eq!(sanitize_url("https://example.com/logo.png"), Some("https://example.com/logo.png"));
        assert_eq!(sanitize_url("HTTP://Example.COM"), Some("HTTP://Example.COM"));
        assert_eq!(sanitize_url("javascript:alert(1)"), None);
        assert_eq!(sanitize_url("data:text/html,<script>alert(1)</script>"), None);
        assert_eq!(sanitize_url("//evil.example/logo.png"), None);
    }

    #[test]
    fn drops_javascript_scheme_logo_and_contact_url_instead_of_rendering_them() {
        let t = BlockTemplate {
            logo_url: Some("javascript:alert(document.cookie)".to_string()),
            contact_url: Some("javascript:alert(1)".to_string()),
            ..Default::default()
        };
        let html = render_page(Some(&t), "ads.example", None);
        assert!(!html.contains("javascript:"));
        assert!(!html.contains("class=\"logo\""));
        assert!(!html.contains("class=\"contact\""));
    }
}
