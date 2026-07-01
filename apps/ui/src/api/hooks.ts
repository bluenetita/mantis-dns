import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient, unwrap } from "./client";
import type { components } from "./schema";

type TenantCreate = components["schemas"]["TenantCreate"];
type GroupCreate = components["schemas"]["GroupCreate"];
type GroupSubnetUpdate = components["schemas"]["GroupSubnetUpdate"];
type PolicyUpsert = components["schemas"]["PolicyUpsert"];
type FeedCreate = components["schemas"]["FeedCreate"];
type FeedUpdate = components["schemas"]["FeedUpdate"];
type SiemWebhookCreate = components["schemas"]["SiemWebhookCreate"];
type SiemWebhookUpdate = components["schemas"]["SiemWebhookUpdate"];
type ClientUpsert = components["schemas"]["ClientUpsert"];

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

export function useAnalyticsSummary() {
  return useQuery({
    queryKey: ["analytics-summary"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/analytics/summary")),
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

export function useAnalyticsByGroup() {
  return useQuery({
    queryKey: ["analytics-by-group"],
    queryFn: async () => unwrap(await apiClient.GET("/api/v1/analytics/by-group")),
    refetchInterval: 15_000,
  });
}

// --- Audit log ---

export function useAuditLog(resourceType?: string) {
  return useQuery({
    queryKey: ["audit-log", resourceType],
    queryFn: async () =>
      unwrap(
        await apiClient.GET("/api/v1/audit-log", {
          params: { query: resourceType ? { resource_type: resourceType } : {} },
        })
      ),
    refetchInterval: 15_000,
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
