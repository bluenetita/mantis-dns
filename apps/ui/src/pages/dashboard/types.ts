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

export type DashboardSummary = {
  total_queries: number;
  blocked_queries: number;
  allowed_queries: number;
  block_ratio: number;
  cache_hit_ratio: number;
  unique_clients: number;
  tenant_count: number;
  group_count: number;
  feed_count: number;
  top_blocked_domains: Array<{ qname: string; decision: string; count: number }>;
};

export type TimeseriesPoint = {
  bucket: string;
  total: number;
  blocked: number;
  allowed: number;
};

export type GroupBreakdown = {
  group_id: string;
  group_name: string;
  tenant_name: string;
  total: number;
  blocked: number;
  block_ratio: number;
};

export type TopClient = {
  client_ip: string;
  hostname: string | null;
  owner: string | null;
  group_name: string | null;
  total: number;
  blocked: number;
  block_ratio: number;
};

export type CategoryBreakdown = {
  category: string;
  count: number;
  pct: number;
};

export type RecentEvent = {
  id: string;
  occurred_at: string;
  client_ip: string | null;
  client_name: string | null;
  qname: string;
  decision: string;
  matched_category: string | null;
  matched_feed_id: string | null;
  group_name: string | null;
  latency_us: number | null;
};

export type FeedItem = { id: string; provider: string; category_id: string; enabled: boolean; last_domain_count: number | null };

export type WebhookItem = {
  id: string;
  name: string;
  format: string;
  enabled: boolean;
  consecutive_failures: number;
  last_delivered_at: string | null;
  last_error: string | null;
};
