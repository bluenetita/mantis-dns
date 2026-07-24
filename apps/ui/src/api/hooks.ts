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

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient, rawDelete, rawGet, rawPatch, rawPost, rawPut, unwrap } from "./client";
import type { components } from "./schema";

type TenantCreate = components["schemas"]["TenantCreate"];
type GroupCreate = components["schemas"]["GroupCreate"];
type GroupUpdate = components["schemas"]["GroupUpdate"];
type GroupSubnetUpdate = components["schemas"]["GroupSubnetUpdate"];
type PolicyUpsert = components["schemas"]["PolicyUpsert"];
type BlockPageTemplateUpsert = components["schemas"]["BlockPageTemplateUpsert"];
type FeedCreate = components["schemas"]["FeedCreate"];
type FeedUpdate = components["schemas"]["FeedUpdate"];
type SiemWebhookCreate = components["schemas"]["SiemWebhookCreate"];
type SiemWebhookUpdate = components["schemas"]["SiemWebhookUpdate"];
type SiemSyslogCreate = components["schemas"]["SiemSyslogCreate"];
type SiemSyslogUpdate = components["schemas"]["SiemSyslogUpdate"];
type ClientUpsert = components["schemas"]["ClientUpsert"];
type UserCreate = components["schemas"]["UserCreate"];
type UserUpdate = components["schemas"]["UserUpdate"];
type ChangePasswordRequest = components["schemas"]["ChangePasswordRequest"];
type ZoneCreate = components["schemas"]["ZoneCreate"];
type ZoneUpdate = components["schemas"]["ZoneUpdate"];
type RecordIn = components["schemas"]["RecordIn"];
type RecordUpdate = components["schemas"]["RecordUpdate"];

// --- Users ---

export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/users")),
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: UserCreate) => unwrap(await apiClient.POST("/api/v1/users", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, body }: { userId: string; body: UserUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/users/{user_id}", { params: { path: { user_id: userId } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (userId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/users/{user_id}", { params: { path: { user_id: userId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

// --- Auth ---

export function useChangePassword() {
  return useMutation({
    mutationFn: async (body: ChangePasswordRequest) =>
      unwrap(await apiClient.POST("/api/v1/auth/change-password", { body })),
  });
}

// --- Tenants ---

export function useTenants() {
  return useQuery({
    queryKey: ["tenants"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/tenants")),
  });
}

export function useCreateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: TenantCreate) =>
      unwrap(await apiClient.POST("/api/v1/tenants", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}

export function useDeleteTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (tenantId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/tenants/{tenant_id}", { params: { path: { tenant_id: tenantId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
}

// --- Groups ---

export function useGroups(tenantId: string | undefined) {
  return useQuery({
    queryKey: ["groups", tenantId],
    queryFn: async () =>
      unwrap(
        await apiClient.GET("/api/v1/tenants/{tenant_id}/groups", {
          params: { path: { tenant_id: tenantId! } },
        })
      ),
    enabled: !!tenantId,
  });
}

export function useCreateGroup(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: GroupCreate) =>
      unwrap(
        await apiClient.POST("/api/v1/tenants/{tenant_id}/groups", {
          params: { path: { tenant_id: tenantId! } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups", tenantId] }),
  });
}

export function useSetGroupSubnet(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ groupId, body }: { groupId: string; body: GroupSubnetUpdate }) =>
      unwrap(
        await apiClient.PUT("/api/v1/groups/{group_id}/subnet", {
          params: { path: { group_id: groupId } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups", tenantId] }),
  });
}

export function useRenameGroup(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ groupId, body }: { groupId: string; body: GroupUpdate }) =>
      unwrap(
        await apiClient.PUT("/api/v1/groups/{group_id}", {
          params: { path: { group_id: groupId } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups", tenantId] }),
  });
}

export function useDeleteGroup(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (groupId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/groups/{group_id}", { params: { path: { group_id: groupId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups", tenantId] }),
  });
}

// --- Policy ---

export function usePolicy(groupId: string | undefined) {
  return useQuery({
    queryKey: ["policy", groupId],
    queryFn: async () => {
      const res = await apiClient.GET("/api/v1/groups/{group_id}/policy", {
        params: { path: { group_id: groupId! } },
      });
      if (res.response.status === 404) return null;
      return unwrap(res);
    },
    enabled: !!groupId,
  });
}

export function useUpsertPolicy(groupId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: PolicyUpsert) =>
      unwrap(
        await apiClient.PUT("/api/v1/groups/{group_id}/policy", {
          params: { path: { group_id: groupId! } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policy", groupId] }),
  });
}

export function useCompileBundle() {
  return useMutation({
    mutationFn: async (groupId: string) =>
      unwrap(await apiClient.POST("/api/v1/groups/{group_id}/bundle", { params: { path: { group_id: groupId } } })),
  });
}

export function useBlockPageTemplate(groupId: string | undefined) {
  return useQuery({
    queryKey: ["block-page-template", groupId],
    queryFn: async () => {
      const res = await apiClient.GET("/api/v1/groups/{group_id}/block-page-template", {
        params: { path: { group_id: groupId! } },
      });
      if (res.response.status === 404) return null;
      return unwrap(res);
    },
    enabled: !!groupId,
  });
}

export function useUpsertBlockPageTemplate(groupId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: BlockPageTemplateUpsert) =>
      unwrap(
        await apiClient.PUT("/api/v1/groups/{group_id}/block-page-template", {
          params: { path: { group_id: groupId! } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["block-page-template", groupId] }),
  });
}

export function useTopDomains(groupId: string | undefined) {
  return useQuery({
    queryKey: ["top-domains", groupId],
    queryFn: async () =>
      unwrap(
        await apiClient.GET("/api/v1/groups/{group_id}/top-domains", {
          params: { path: { group_id: groupId! } },
        })
      ),
    enabled: !!groupId,
  });
}

// --- Categories ---

export interface Category {
  id: string;
  label: string;
  description: string;
  group: "security" | "content" | "distraction" | "privacy" | "network";
  color: string;
  icon: string;
  default_action: "ACTION_BLOCK" | "ACTION_LOG_ONLY";
  has_bundled_feed: boolean;
}

export function useCategories() {
  return useQuery({
    queryKey: ["categories"],
    queryFn: () => rawGet<Category[]>("/api/v1/categories"),
    staleTime: Infinity,
  });
}

// --- Feeds ---

export function useFeeds() {
  return useQuery({
    queryKey: ["feeds"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/feeds")),
  });
}

export function useCreateFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: FeedCreate) => unwrap(await apiClient.POST("/api/v1/feeds", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }),
  });
}

export function useUpdateFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ feedId, body }: { feedId: string; body: FeedUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/feeds/{feed_id}", { params: { path: { feed_id: feedId } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }),
  });
}

export function useDeleteFeed() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (feedId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/feeds/{feed_id}", { params: { path: { feed_id: feedId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }),
  });
}

export function useIngestFeedNow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (feedId: string) =>
      unwrap(await apiClient.POST("/api/v1/feeds/{feed_id}/ingest", { params: { path: { feed_id: feedId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feeds"] }),
  });
}

// --- Analytics ---

export function useAnalyticsSummary(hours = 24) {
  return useQuery({
    queryKey: ["analytics-summary", hours],
    queryFn: async () =>
      unwrap(await apiClient.GET("/api/v1/analytics/summary", { params: { query: { hours } } })),
    refetchInterval: 15_000,
  });
}

export function useAnalyticsTimeseries(hours = 24) {
  return useQuery({
    queryKey: ["analytics-timeseries", hours],
    queryFn: async () =>
      unwrap(await apiClient.GET("/api/v1/analytics/timeseries", { params: { query: { hours } } })),
    refetchInterval: 15_000,
  });
}

export function useAnalyticsByGroup(hours = 24) {
  return useQuery({
    queryKey: ["analytics-by-group", hours],
    queryFn: async () =>
      unwrap(await apiClient.GET("/api/v1/analytics/by-group", { params: { query: { hours } as never } })),
    refetchInterval: 15_000,
  });
}

// --- Audit log ---

export interface AuditLogEntry {
  id: string;
  occurred_at: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string;
  detail: string;
  tenant_id: string | null;
}

export const AUDIT_PAGE_SIZE = 50;

export function useAuditLog(resourceType?: string, offset = 0) {
  return useQuery({
    queryKey: ["audit-log", resourceType, offset],
    queryFn: () =>
      rawGet<AuditLogEntry[]>("/api/v1/audit-log", {
        limit: AUDIT_PAGE_SIZE,
        offset,
        ...(resourceType ? { resource_type: resourceType } : {}),
      }),
    refetchInterval: 15_000,
  });
}

// --- Query log ---

export interface QueryLogEntry {
  id: string;
  occurred_at: string;
  group_id: string;
  group_name: string | null;
  tenant_id: string | null;
  client_ip: string | null;
  client_name: string | null;
  qname: string;
  qtype: string | null;
  decision: string;
  matched_rule: string | null;
  matched_category: string | null;
  matched_feed_id: string | null;
  response_code: string | null;
  cache_hit: boolean | null;
  latency_us: number | null;
}

export const QUERY_LOG_PAGE_SIZE = 50;

export function useQueryLog(params: {
  offset?: number;
  decision?: "allow" | "block" | "";
  group_id?: string;
  qname?: string;
  client_ip?: string;
  qtype?: string;
  matched_category?: string;
  hours?: number;
}) {
  const { offset = 0, decision, group_id, qname, client_ip, qtype, matched_category, hours } = params;
  return useQuery({
    queryKey: ["query-log", offset, decision, group_id, qname, client_ip, qtype, matched_category, hours],
    queryFn: () =>
      rawGet<QueryLogEntry[]>("/api/v1/query-log", {
        limit: QUERY_LOG_PAGE_SIZE,
        offset,
        ...(decision ? { decision } : {}),
        ...(group_id ? { group_id } : {}),
        ...(qname ? { qname } : {}),
        ...(client_ip ? { client_ip } : {}),
        ...(qtype ? { qtype } : {}),
        ...(matched_category ? { matched_category } : {}),
        ...(hours ? { hours } : {}),
      }),
    refetchInterval: 30_000,
  });
}

// --- SIEM webhooks ---

export function useSiemWebhooks() {
  return useQuery({
    queryKey: ["siem-webhooks"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/siem/webhooks")),
    refetchInterval: 15_000,
  });
}

export function useCreateSiemWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: SiemWebhookCreate) => unwrap(await apiClient.POST("/api/v1/siem/webhooks", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-webhooks"] }),
  });
}

export function useUpdateSiemWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ webhookId, body }: { webhookId: string; body: SiemWebhookUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/siem/webhooks/{webhook_id}", { params: { path: { webhook_id: webhookId } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-webhooks"] }),
  });
}

export function useDeleteSiemWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (webhookId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/siem/webhooks/{webhook_id}", { params: { path: { webhook_id: webhookId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-webhooks"] }),
  });
}

export function useTestSiemWebhook() {
  return useMutation({
    mutationFn: async (webhookId: string) =>
      unwrap(await apiClient.POST("/api/v1/siem/webhooks/{webhook_id}/test", { params: { path: { webhook_id: webhookId } } })),
  });
}

// --- SIEM syslog ---

export function useSiemSyslogSinks() {
  return useQuery({
    queryKey: ["siem-syslog"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/siem/syslog")),
    refetchInterval: 15_000,
  });
}

export function useCreateSiemSyslogSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: SiemSyslogCreate) => unwrap(await apiClient.POST("/api/v1/siem/syslog", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-syslog"] }),
  });
}

export function useUpdateSiemSyslogSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ syslogId, body }: { syslogId: string; body: SiemSyslogUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/siem/syslog/{syslog_id}", { params: { path: { syslog_id: syslogId } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-syslog"] }),
  });
}

export function useDeleteSiemSyslogSink() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (syslogId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/siem/syslog/{syslog_id}", { params: { path: { syslog_id: syslogId } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["siem-syslog"] }),
  });
}

export function useTestSiemSyslogSink() {
  return useMutation({
    mutationFn: async (syslogId: string) =>
      unwrap(await apiClient.POST("/api/v1/siem/syslog/{syslog_id}/test", { params: { path: { syslog_id: syslogId } } })),
  });
}

// --- Client registry ---

export function useClients(tenantId: string | undefined, unregisteredOnly = false) {
  return useQuery({
    queryKey: ["clients", tenantId, unregisteredOnly],
    queryFn: async () =>
      unwrap(
        await apiClient.GET("/api/v1/tenants/{tenant_id}/clients", {
          params: { path: { tenant_id: tenantId! }, query: { unregistered_only: unregisteredOnly } },
        })
      ),
    enabled: !!tenantId,
    refetchInterval: 15_000,
  });
}

export function useRegisterClient(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ ip, body }: { ip: string; body: ClientUpsert }) =>
      unwrap(
        await apiClient.PUT("/api/v1/tenants/{tenant_id}/clients/{ip}", {
          params: { path: { tenant_id: tenantId!, ip } },
          body,
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["clients", tenantId] }),
  });
}

export function useDeleteClient(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (ip: string) =>
      unwrap(
        await apiClient.DELETE("/api/v1/tenants/{tenant_id}/clients/{ip}", {
          params: { path: { tenant_id: tenantId!, ip } },
        })
      ),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["clients", tenantId] }),
  });
}

// --- DNS Zones ---

export function useZones() {
  return useQuery({
    queryKey: ["dns-zones"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/dns-zones")),
  });
}

export function useZone(zoneId: string) {
  return useQuery({
    queryKey: ["dns-zones", zoneId],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/dns-zones/{zone_id}", { params: { path: { zone_id: zoneId } } })),
    enabled: !!zoneId,
  });
}

export function useCreateZone() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: ZoneCreate) => unwrap(await apiClient.POST("/api/v1/dns-zones", { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-zones"] }),
  });
}

export function useUpdateZone() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ zoneId, body }: { zoneId: string; body: ZoneUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/dns-zones/{zone_id}", { params: { path: { zone_id: zoneId } }, body })),
    onSuccess: (_d, { zoneId }) => {
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["dns-zones", zoneId] });
    },
  });
}

export function useDeleteZone() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (zoneId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/dns-zones/{zone_id}", { params: { path: { zone_id: zoneId } } })),
    onSuccess: (_d, zoneId) => {
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.removeQueries({ queryKey: ["dns-records", zoneId] });
    },
  });
}

// --- DNS Records ---

export function useRecords(zoneId: string) {
  return useQuery({
    queryKey: ["dns-records", zoneId],
    queryFn: async () =>
      unwrap(await apiClient.GET("/api/v1/dns-zones/{zone_id}/records", { params: { path: { zone_id: zoneId } } })),
    enabled: !!zoneId,
  });
}

export function useCreateRecord(zoneId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: RecordIn) =>
      unwrap(await apiClient.POST("/api/v1/dns-zones/{zone_id}/records", { params: { path: { zone_id: zoneId } }, body })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-records", zoneId] });
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["dns-zones", zoneId] });
    },
  });
}

export function useUpdateRecord(zoneId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ recordId, body }: { recordId: string; body: RecordUpdate }) =>
      unwrap(await apiClient.PATCH("/api/v1/dns-zones/{zone_id}/records/{record_id}", {
        params: { path: { zone_id: zoneId, record_id: recordId } },
        body,
      })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-records", zoneId] }),
  });
}

export function useDeleteRecord(zoneId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (recordId: string) =>
      unwrap(await apiClient.DELETE("/api/v1/dns-zones/{zone_id}/records/{record_id}", {
        params: { path: { zone_id: zoneId, record_id: recordId } },
      })),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-records", zoneId] });
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["dns-zones", zoneId] });
    },
  });
}

// --- Policy domain test ---

export type PolicyTestResult = {
  domain: string;
  decision: "allow" | "block";
  matched: "override_allow" | "override_deny" | "category" | "default";
  matched_category: string | null;
  matched_feed_id: string | null;
};

export function useTestPolicy(groupId: string | undefined) {
  return useMutation({
    mutationFn: (domain: string) =>
      rawPost<PolicyTestResult>(`/api/v1/groups/${groupId}/policy/test`, { domain }),
  });
}

// --- Upstream configuration ---

export interface UpstreamResolver {
  id: string;
  name: string;
  protocol: "dot" | "doh" | "do53";
  address: string;
  port: number;
  tls_hostname: string | null;
  tls_pin_sha256: string[];
  doh_path: string;
  doh_method: string;
  dnssec_validation: string;
  qname_minimization: boolean;
  edns_client_subnet: boolean;
  timeout_ms: number;
  max_retries: number;
  connect_timeout_ms: number;
  tags: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UpstreamPoolMember {
  id: string;
  pool_id: string;
  resolver_id: string;
  weight: number;
  priority: number;
}

export interface UpstreamPool {
  id: string;
  name: string;
  strategy: string;
  health_check_interval_s: number;
  health_check_timeout_ms: number;
  health_check_query: string;
  health_check_type: string;
  unhealthy_threshold: number;
  healthy_threshold: number;
  min_healthy_members: number;
  fallback_pool_id: string | null;
  members: UpstreamPoolMember[];
  created_at: string;
  updated_at: string;
}

export interface UpstreamRoute {
  id: string;
  name: string;
  tenant_id: string | null;
  group_id: string | null;
  match_type: string;
  match_value: string | null;
  pool_id: string;
  nxdomain_ttl_override: number | null;
  require_dnssec: boolean | null;
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface UpstreamTenantPolicy {
  tenant_id: string;
  require_encrypted: boolean;
  dnssec_validation: string;
  qname_minimization: boolean;
  blocked_response_type: string;
  min_ttl_s: number;
  max_ttl_s: number;
  negative_ttl_s: number;
}

export interface ProbeResult {
  ok: boolean;
  latency_ms: number | null;
  response_code: string | null;
  dnssec_ad: boolean;
  tls_subject: string | null;
  error: string | null;
}

export function useUpstreamResolvers() {
  return useQuery({
    queryKey: ["upstream-resolvers"],
    queryFn: () => rawGet<UpstreamResolver[]>("/api/v1/upstream/resolvers"),
  });
}

export function useCreateUpstreamResolver() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<UpstreamResolver>) =>
      rawPost<UpstreamResolver>("/api/v1/upstream/resolvers", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-resolvers"] }),
  });
}

export function useUpdateUpstreamResolver() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<UpstreamResolver> }) =>
      rawPatch<UpstreamResolver>(`/api/v1/upstream/resolvers/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-resolvers"] }),
  });
}

export function useDeleteUpstreamResolver() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/upstream/resolvers/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-resolvers"] }),
  });
}

export function useProbeUpstreamResolver() {
  return useMutation({
    mutationFn: (id: string) =>
      rawPost<ProbeResult>(`/api/v1/upstream/resolvers/${id}/probe`, {}),
  });
}

export function useUpstreamPools() {
  return useQuery({
    queryKey: ["upstream-pools"],
    queryFn: () => rawGet<UpstreamPool[]>("/api/v1/upstream/pools"),
  });
}

export function useCreateUpstreamPool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<UpstreamPool> & { members?: { resolver_id: string; weight: number; priority: number }[] }) =>
      rawPost<UpstreamPool>("/api/v1/upstream/pools", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-pools"] }),
  });
}

export function useUpdateUpstreamPool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<UpstreamPool> }) =>
      rawPatch<UpstreamPool>(`/api/v1/upstream/pools/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-pools"] }),
  });
}

export function useDeleteUpstreamPool() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/upstream/pools/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-pools"] }),
  });
}

export function useUpsertPoolMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ poolId, resolverId, weight, priority }: { poolId: string; resolverId: string; weight: number; priority: number }) =>
      rawPut<UpstreamPoolMember>(`/api/v1/upstream/pools/${poolId}/members/${resolverId}`, { resolver_id: resolverId, weight, priority }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-pools"] }),
  });
}

export function useRemovePoolMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ poolId, resolverId }: { poolId: string; resolverId: string }) =>
      rawDelete(`/api/v1/upstream/pools/${poolId}/members/${resolverId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-pools"] }),
  });
}

export function useUpstreamRoutes(tenantId: string | undefined) {
  return useQuery({
    queryKey: ["upstream-routes", tenantId],
    queryFn: () => rawGet<UpstreamRoute[]>(`/api/v1/tenants/${tenantId}/upstream/routes`),
    enabled: !!tenantId,
  });
}

export function useCreateUpstreamRoute(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<UpstreamRoute>) =>
      rawPost<UpstreamRoute>(`/api/v1/tenants/${tenantId}/upstream/routes`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-routes", tenantId] }),
  });
}

export function useUpdateUpstreamRoute(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<UpstreamRoute> }) =>
      rawPatch<UpstreamRoute>(`/api/v1/tenants/${tenantId}/upstream/routes/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-routes", tenantId] }),
  });
}

export function useDeleteUpstreamRoute(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/tenants/${tenantId}/upstream/routes/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-routes", tenantId] }),
  });
}

export function useUpstreamTenantPolicy(tenantId: string | undefined) {
  return useQuery({
    queryKey: ["upstream-policy", tenantId],
    queryFn: () => rawGet<UpstreamTenantPolicy>(`/api/v1/tenants/${tenantId}/upstream/policy`),
    enabled: !!tenantId,
  });
}

export function useUpsertUpstreamTenantPolicy(tenantId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Omit<UpstreamTenantPolicy, "tenant_id">) =>
      rawPut<UpstreamTenantPolicy>(`/api/v1/tenants/${tenantId}/upstream/policy`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["upstream-policy", tenantId] }),
  });
}

// ── DHCP ──────────────────────────────────────────────────────────────────────

export interface DhcpScope {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  subnet: string;
  range_start: string;
  range_end: string;
  router_ip: string | null;
  dns_servers: string[];
  ntp_server: string | null;
  domain_name: string | null;
  interface: string | null;
  vlan_id: number | null;
  lease_time_s: number;
  max_lease_time_s: number;
  renew_time_s: number | null;
  rebind_time_s: number | null;
  ddns_enabled: boolean;
  ddns_zone_id: string | null;
  ddns_ttl_s: number;
  pxe_next_server: string | null;
  pxe_boot_filename: string | null;
  pxe_uefi_boot_filename: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DhcpReservation {
  id: string;
  scope_id: string;
  tenant_id: string;
  mac_address: string;
  ip_address: string;
  hostname: string | null;
  description: string | null;
  client_id: string | null;
  next_server: string | null;
  boot_filename: string | null;
  uefi_boot_filename: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DhcpLease {
  ip_address: string;
  mac_address: string;
  hostname: string | null;
  scope_id: string;
  expires_at: string;
  state: number;
}

export interface DhcpSubnetStat {
  scope_id: string;
  scope_name: string;
  subnet: string;
  total_addresses: number;
  assigned_addresses: number;
  declined_addresses: number;
}

export function useDhcpScopes(tenantId?: string) {
  return useQuery({
    queryKey: ["dhcp-scopes", tenantId],
    queryFn: () => rawGet<DhcpScope[]>("/api/v1/dhcp/scopes", tenantId ? { tenant_id: tenantId } : undefined),
  });
}

export function useCreateDhcpScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<DhcpScope>) => rawPost<DhcpScope>("/api/v1/dhcp/scopes", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-scopes"] }),
  });
}

export function useUpdateDhcpScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<DhcpScope> }) =>
      rawPatch<DhcpScope>(`/api/v1/dhcp/scopes/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-scopes"] }),
  });
}

export function useDeleteDhcpScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/dhcp/scopes/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-scopes"] }),
  });
}

export function useDhcpReservations(scopeId: string | undefined) {
  return useQuery({
    queryKey: ["dhcp-reservations", scopeId],
    queryFn: () => rawGet<DhcpReservation[]>(`/api/v1/dhcp/scopes/${scopeId}/reservations`),
    enabled: !!scopeId,
  });
}

export function useCreateDhcpReservation(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<DhcpReservation>) =>
      rawPost<DhcpReservation>(`/api/v1/dhcp/scopes/${scopeId}/reservations`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-reservations", scopeId] }),
  });
}

export function useUpdateDhcpReservation(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<DhcpReservation> }) =>
      rawPatch<DhcpReservation>(`/api/v1/dhcp/scopes/${scopeId}/reservations/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-reservations", scopeId] }),
  });
}

export function useDeleteDhcpReservation(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/dhcp/scopes/${scopeId}/reservations/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp-reservations", scopeId] }),
  });
}

export function useDhcpLeases(scopeId: string | undefined) {
  return useQuery({
    queryKey: ["dhcp-leases", scopeId],
    queryFn: () => rawGet<DhcpLease[]>("/api/v1/dhcp/leases", scopeId ? { scope_id: scopeId } : undefined),
    enabled: !!scopeId,
    refetchInterval: 30_000,
  });
}

export function useDhcpStats() {
  return useQuery({
    queryKey: ["dhcp-stats"],
    queryFn: () => rawGet<DhcpSubnetStat[]>("/api/v1/dhcp/stats"),
    refetchInterval: 60_000,
  });
}

// ── DHCPv6 ────────────────────────────────────────────────────────────────────

export interface DhcpScope6 {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  subnet: string;
  pool_start: string;
  pool_end: string;
  pd_prefix: string | null;
  pd_prefix_len: number | null;
  dns_servers: string[];
  domain_name: string | null;
  interface: string | null;
  preferred_lifetime_s: number;
  valid_lifetime_s: number;
  renew_time_s: number | null;
  rebind_time_s: number | null;
  ddns_enabled: boolean;
  ddns_zone_id: string | null;
  ddns_ttl_s: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DhcpReservation6 {
  id: string;
  scope_id: string;
  tenant_id: string;
  duid: string;
  ip_address: string;
  hostname: string | null;
  description: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface DhcpLease6 {
  ip_address: string;
  duid: string;
  hostname: string | null;
  scope_id: string;
  expires_at: string;
  state: number;
  lease_type: number;
}

export function useDhcpScopes6(tenantId?: string) {
  return useQuery({
    queryKey: ["dhcp6-scopes", tenantId],
    queryFn: () => rawGet<DhcpScope6[]>("/api/v1/dhcp6/scopes", tenantId ? { tenant_id: tenantId } : undefined),
  });
}

export function useCreateDhcpScope6() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<DhcpScope6>) => rawPost<DhcpScope6>("/api/v1/dhcp6/scopes", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-scopes"] }),
  });
}

export function useUpdateDhcpScope6() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<DhcpScope6> }) =>
      rawPatch<DhcpScope6>(`/api/v1/dhcp6/scopes/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-scopes"] }),
  });
}

export function useDeleteDhcpScope6() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/dhcp6/scopes/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-scopes"] }),
  });
}

export function useDhcpReservations6(scopeId: string | undefined) {
  return useQuery({
    queryKey: ["dhcp6-reservations", scopeId],
    queryFn: () => rawGet<DhcpReservation6[]>(`/api/v1/dhcp6/scopes/${scopeId}/reservations`),
    enabled: !!scopeId,
  });
}

export function useCreateDhcpReservation6(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<DhcpReservation6>) =>
      rawPost<DhcpReservation6>(`/api/v1/dhcp6/scopes/${scopeId}/reservations`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-reservations", scopeId] }),
  });
}

export function useUpdateDhcpReservation6(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: Partial<DhcpReservation6> }) =>
      rawPatch<DhcpReservation6>(`/api/v1/dhcp6/scopes/${scopeId}/reservations/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-reservations", scopeId] }),
  });
}

export function useDeleteDhcpReservation6(scopeId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => rawDelete(`/api/v1/dhcp6/scopes/${scopeId}/reservations/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dhcp6-reservations", scopeId] }),
  });
}

export function useDhcpLeases6(scopeId: string | undefined) {
  return useQuery({
    queryKey: ["dhcp6-leases", scopeId],
    queryFn: () => rawGet<DhcpLease6[]>("/api/v1/dhcp6/leases", scopeId ? { scope_id: scopeId } : undefined),
    enabled: !!scopeId,
    refetchInterval: 30_000,
  });
}

