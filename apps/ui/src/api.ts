const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export interface Tenant {
  id: string;
  name: string;
  created_at: string;
}

export interface Group {
  id: string;
  tenant_id: string;
  name: string;
  vpn_subnet: string | null;
  created_at: string;
}

export interface CategoryToggle {
  category_id: string;
  action: "ACTION_BLOCK" | "ACTION_LOG_ONLY" | "ACTION_ALLOW";
}

export interface Override {
  domain: string;
  kind: "allow" | "deny";
}

export interface Policy {
  id: string;
  group_id: string;
  on_load_failure: "FAIL_OPEN" | "FAIL_CLOSED";
  category_toggles: CategoryToggle[];
  overrides: Override[];
}

export interface TopDomain {
  qname: string;
  decision: string;
  count: number;
}

export interface Feed {
  id: string;
  category_id: string;
  url: string;
  format: string;
  interval_seconds: number;
  license: string;
  provider: string;
  from_catalog: boolean;
  enabled: boolean;
  last_domain_count: number | null;
  last_version: string | null;
}

export interface IngestResult {
  status: string;
  domain_count: number;
  reason: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    if (res.status === 404) {
      throw new NotFoundError(path);
    }
    throw new Error(`${init?.method ?? "GET"} ${path} failed: ${res.status} ${await res.text()}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export class NotFoundError extends Error {}

export const api = {
  listTenants: () => request<Tenant[]>("/api/v1/tenants"),
  createTenant: (name: string) =>
    request<Tenant>("/api/v1/tenants", { method: "POST", body: JSON.stringify({ name }) }),

  listGroups: (tenantId: string) => request<Group[]>(`/api/v1/tenants/${tenantId}/groups`),
  createGroup: (tenantId: string, name: string, vpnSubnet: string) =>
    request<Group>(`/api/v1/tenants/${tenantId}/groups`, {
      method: "POST",
      body: JSON.stringify({ name, vpn_subnet: vpnSubnet || null }),
    }),
  setGroupSubnet: (groupId: string, vpnSubnet: string) =>
    request<Group>(`/api/v1/groups/${groupId}/subnet`, {
      method: "PUT",
      body: JSON.stringify({ vpn_subnet: vpnSubnet }),
    }),

  getPolicy: (groupId: string) => request<Policy>(`/api/v1/groups/${groupId}/policy`),
  upsertPolicy: (
    groupId: string,
    body: { on_load_failure: string; category_toggles: CategoryToggle[]; overrides: Override[] }
  ) =>
    request<Policy>(`/api/v1/groups/${groupId}/policy`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  compileBundle: (groupId: string) =>
    fetch(`${API_BASE}/api/v1/groups/${groupId}/bundle`, { method: "POST" }).then((r) => {
      if (!r.ok) throw new Error(`compile failed: ${r.status}`);
      return r.blob();
    }),

  topDomains: (groupId: string) => request<TopDomain[]>(`/api/v1/groups/${groupId}/top-domains`),

  listFeeds: () => request<Feed[]>("/api/v1/feeds"),
  createFeed: (feed: {
    id: string;
    category_id: string;
    url: string;
    format: string;
    interval_seconds: number;
    license: string;
    provider: string;
  }) => request<Feed>("/api/v1/feeds", { method: "POST", body: JSON.stringify(feed) }),
  updateFeed: (feedId: string, patch: Partial<Pick<Feed, "enabled" | "interval_seconds" | "url" | "license">>) =>
    request<Feed>(`/api/v1/feeds/${feedId}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteFeed: (feedId: string) => request<void>(`/api/v1/feeds/${feedId}`, { method: "DELETE" }),
  ingestFeedNow: (feedId: string) =>
    request<IngestResult>(`/api/v1/feeds/${feedId}/ingest`, { method: "POST" }),
};
