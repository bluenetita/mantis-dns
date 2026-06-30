import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiClient, unwrap } from "./client";
import type { components } from "./schema";

type TenantCreate = components["schemas"]["TenantCreate"];
type GroupCreate = components["schemas"]["GroupCreate"];
type GroupSubnetUpdate = components["schemas"]["GroupSubnetUpdate"];
type PolicyUpsert = components["schemas"]["PolicyUpsert"];
type FeedCreate = components["schemas"]["FeedCreate"];
type FeedUpdate = components["schemas"]["FeedUpdate"];

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
