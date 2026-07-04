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

import {
  AreaChart,
  DonutChart,
} from "@mantine/charts";
import {
  ActionIcon,
  Badge,
  Card,
  Center,
  Drawer,
  Grid,
  Group,
  Loader,
  Progress,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconActivity,
  IconBolt,
  IconChevronDown,
  IconChevronUp,
  IconDevices,
  IconLayoutDashboard,
  IconShieldOff,
  IconUsers,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import type React from "react";
import { useState } from "react";
import { rawGet } from "../api/client";
import { useFeeds, useSiemWebhooks, useTenants } from "../api/hooks";

// --- Local types for new endpoints ---

type DashboardSummary = {
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

type TimeseriesPoint = {
  bucket: string;
  total: number;
  blocked: number;
  allowed: number;
};

type GroupBreakdown = {
  group_id: string;
  group_name: string;
  tenant_name: string;
  total: number;
  blocked: number;
  block_ratio: number;
};

type TopClient = {
  client_ip: string;
  hostname: string | null;
  owner: string | null;
  group_name: string | null;
  total: number;
  blocked: number;
  block_ratio: number;
};

type CategoryBreakdown = {
  category: string;
  count: number;
  pct: number;
};

type RecentEvent = {
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

// --- Shared widget wrapper ---

function WidgetCard({
  title,
  rightSection,
  children,
  loading,
  minH,
}: {
  title: string;
  rightSection?: React.ReactNode;
  children: React.ReactNode;
  loading?: boolean;
  minH?: number;
}) {
  return (
    <Card withBorder h="100%" style={minH ? { minHeight: minH } : undefined}>
      <Group justify="space-between" mb="sm">
        <Text fw={500} size="sm">
          {title}
        </Text>
        {rightSection}
      </Group>
      {loading ? (
        <Center py="xl">
          <Loader size="sm" />
        </Center>
      ) : (
        children
      )}
    </Card>
  );
}

// --- KPI strip ---

function KpiCard({
  label,
  value,
  sub,
  icon: Icon,
}: {
  label: string;
  value: string;
  sub?: string;
  icon: typeof IconActivity;
}) {
  return (
    <Card withBorder padding="sm">
      <Group gap="xs" mb={4}>
        <Icon size={14} aria-hidden="true" color="var(--mantine-color-dimmed)" />
        <Text size="xs" c="dimmed">
          {label}
        </Text>
      </Group>
      <Text size="xl" fw={500} lh={1.1}>
        {value}
      </Text>
      {sub && (
        <Text size="xs" c="dimmed" mt={2}>
          {sub}
        </Text>
      )}
    </Card>
  );
}

// --- Charts ---

function QueryVolumeWidget({ data, loading }: { data: TimeseriesPoint[] | undefined; loading: boolean }) {
  const chartData = (data ?? []).map((p) => ({
    time: new Date(p.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    Allowed: p.allowed,
    Blocked: p.blocked,
  }));

  return (
    <WidgetCard title="Query volume" loading={loading} minH={280}>
      {chartData.every((p) => p.Allowed === 0 && p.Blocked === 0) ? (
        <Text c="dimmed" size="sm">
          No query telemetry in this window.
        </Text>
      ) : (
        <AreaChart
          h={220}
          data={chartData}
          dataKey="time"
          series={[
            { name: "Allowed", color: "blue.5" },
            { name: "Blocked", color: "red.5" },
          ]}
          type="stacked"
          curveType="step"
          withLegend
          tickLine="y"
          withDots={false}
        />
      )}
    </WidgetCard>
  );
}

function DecisionWidget({ summary, loading }: { summary: DashboardSummary | undefined; loading: boolean }) {
  const total = summary?.total_queries ?? 0;
  const blocked = summary?.blocked_queries ?? 0;
  const allowed = summary?.allowed_queries ?? 0;

  const data =
    total > 0
      ? [
          { name: "Allowed", value: allowed, color: "blue.5" },
          { name: "Blocked", value: blocked, color: "red.5" },
        ]
      : [{ name: "No data", value: 1, color: "gray.3" }];

  return (
    <WidgetCard title="Decision breakdown" loading={loading} minH={280}>
      <Center>
        <DonutChart
          data={data}
          withTooltip={total > 0}
          tooltipDataSource="segment"
          size={160}
          thickness={28}
          chartLabel={total > 0 ? `${((allowed / total) * 100).toFixed(1)}% allowed` : ""}
        />
      </Center>
      {total > 0 && (
        <Stack gap={4} mt="sm">
          <Group justify="space-between">
            <Group gap="xs">
              <div style={{ width: 10, height: 10, borderRadius: 2, background: "var(--mantine-color-blue-5)" }} />
              <Text size="xs">Allowed</Text>
            </Group>
            <Text size="xs" c="dimmed">
              {allowed.toLocaleString()}
            </Text>
          </Group>
          <Group justify="space-between">
            <Group gap="xs">
              <div style={{ width: 10, height: 10, borderRadius: 2, background: "var(--mantine-color-red-5)" }} />
              <Text size="xs">Blocked</Text>
            </Group>
            <Text size="xs" c="dimmed">
              {blocked.toLocaleString()}
            </Text>
          </Group>
        </Stack>
      )}
    </WidgetCard>
  );
}

// --- Top blocked domains ---

function TopDomainsWidget({
  data,
  loading,
}: {
  data: DashboardSummary["top_blocked_domains"] | undefined;
  loading: boolean;
}) {
  return (
    <WidgetCard title="Top blocked domains" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No blocked queries in this window.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>#</Table.Th>
              <Table.Th>Domain</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Hits</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((d, i) => (
              <Table.Tr key={d.qname}>
                <Table.Td>
                  <Text c="dimmed" size="xs">
                    {i + 1}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {d.qname}
                  </Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{d.count.toLocaleString()}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}

// --- Blocks by category ---

function CategoriesWidget({ data, loading }: { data: CategoryBreakdown[] | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Blocks by category" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No categorised blocks in this window.
        </Text>
      ) : (
        <Stack gap="xs">
          {data.map((c) => (
            <div key={c.category}>
              <Group justify="space-between" mb={2}>
                <Text size="xs" tt="capitalize">
                  {c.category}
                </Text>
                <Text size="xs" c="dimmed">
                  {c.pct}%
                </Text>
              </Group>
              <Progress value={c.pct} color="red" size="sm" />
            </div>
          ))}
        </Stack>
      )}
    </WidgetCard>
  );
}

// --- Top clients ---

function TopClientsWidget({ data, loading }: { data: TopClient[] | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Top clients by query volume" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No client telemetry in this window.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Client</Table.Th>
              <Table.Th>Owner</Table.Th>
              <Table.Th>Group</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Queries</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Block%</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((c) => (
              <Table.Tr key={c.client_ip}>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {c.client_ip}
                  </Text>
                  {c.hostname && (
                    <Text size="xs" c="dimmed">
                      {c.hostname}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {c.owner ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {c.group_name ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{c.total.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Badge
                    size="sm"
                    color={c.block_ratio > 0.3 ? "red" : c.block_ratio > 0.1 ? "yellow" : "green"}
                    variant="light"
                  >
                    {(c.block_ratio * 100).toFixed(0)}%
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}

// --- Per-group breakdown ---

function GroupBreakdownWidget({ data, loading }: { data: GroupBreakdown[] | undefined; loading: boolean }) {
  const sorted = [...(data ?? [])].sort((a, b) => b.total - a.total);

  return (
    <WidgetCard title="Per-group breakdown" loading={loading}>
      {sorted.length === 0 ? (
        <Text c="dimmed" size="sm">
          No group telemetry yet.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tenant</Table.Th>
              <Table.Th>Group</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Total</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Blocked</Table.Th>
              <Table.Th>Block ratio</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {sorted.map((g) => (
              <Table.Tr key={g.group_id}>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {g.tenant_name}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{g.group_name}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{g.total.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{g.blocked.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" wrap="nowrap">
                    <Progress value={g.block_ratio * 100} color="red" size="sm" w={80} />
                    <Text size="xs">{(g.block_ratio * 100).toFixed(0)}%</Text>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}

// --- Feed health ---

type FeedItem = { id: string; provider: string; category_id: string; enabled: boolean; last_domain_count: number | null };

function feedStatus(f: FeedItem): { color: string; label: string } {
  if (!f.enabled) return { color: "gray", label: "disabled" };
  if (f.last_domain_count == null) return { color: "yellow", label: "pending" };
  return { color: "green", label: "ok" };
}

function FeedHealthWidget({ data }: { data: FeedItem[] | undefined }) {
  return (
    <WidgetCard title="Feed health">
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No feeds configured.
        </Text>
      ) : (
        <Stack gap={6}>
          {data.slice(0, 8).map((f) => {
            const s = feedStatus(f);
            return (
              <Group key={f.id} justify="space-between" wrap="nowrap">
                <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                  <Badge size="xs" color={s.color} variant="dot" />
                  <Text size="xs" truncate>
                    {f.provider || f.id}
                  </Text>
                </Group>
                <Group gap="xs" wrap="nowrap">
                  <Badge size="xs" variant="light" color="gray">
                    {f.category_id}
                  </Badge>
                  {f.last_domain_count != null && (
                    <Text size="xs" c="dimmed">
                      {f.last_domain_count.toLocaleString()} domains
                    </Text>
                  )}
                </Group>
              </Group>
            );
          })}
          {data.length > 8 && (
            <Text size="xs" c="dimmed">
              +{data.length - 8} more
            </Text>
          )}
        </Stack>
      )}
    </WidgetCard>
  );
}

// --- SIEM delivery ---

type WebhookItem = {
  id: string;
  name: string;
  format: string;
  enabled: boolean;
  consecutive_failures: number;
  last_delivered_at: string | null;
  last_error: string | null;
};

function webhookStatus(w: WebhookItem): { color: string; label: string } {
  if (!w.enabled) return { color: "gray", label: "disabled" };
  if (w.consecutive_failures >= 3) return { color: "red", label: `${w.consecutive_failures} failures` };
  if (w.consecutive_failures > 0) return { color: "yellow", label: "retrying" };
  return { color: "green", label: "ok" };
}

function SiemDeliveryWidget({ data }: { data: WebhookItem[] | undefined }) {
  return (
    <WidgetCard title="SIEM delivery">
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No webhooks configured.
        </Text>
      ) : (
        <Stack gap={6}>
          {data.map((w) => {
            const s = webhookStatus(w);
            return (
              <Group key={w.id} justify="space-between" wrap="nowrap">
                <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                  <Badge size="xs" color={s.color} variant="dot" />
                  <Text size="xs" truncate>
                    {w.name}
                  </Text>
                </Group>
                <Group gap="xs" wrap="nowrap">
                  <Badge size="xs" variant="light" color="gray">
                    {w.format.toUpperCase()}
                  </Badge>
                  <Text size="xs" c={s.color === "green" ? "dimmed" : s.color}>
                    {s.label}
                  </Text>
                </Group>
              </Group>
            );
          })}
        </Stack>
      )}
    </WidgetCard>
  );
}

// --- Recent block events ---

function RecentEventsWidget({ data, loading }: { data: RecentEvent[] | undefined; loading: boolean }) {
  return (
    <WidgetCard
      title="Recent block events"
      rightSection={
        <Badge size="xs" variant="light" color="red">
          live · last 25
        </Badge>
      }
      loading={loading}
    >
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No block events recorded yet.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Time</Table.Th>
              <Table.Th>Client</Table.Th>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Category</Table.Th>
              <Table.Th>Feed</Table.Th>
              <Table.Th>Group</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td>
                  <Text ff="monospace" size="xs" c="dimmed">
                    {new Date(e.occurred_at).toLocaleTimeString()}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {e.client_ip ?? "—"}
                  </Text>
                  {e.client_name && (
                    <Text size="xs" c="dimmed">
                      {e.client_name}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {e.qname}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {e.matched_category ? (
                    <Badge size="xs" color="red" variant="light">
                      {e.matched_category}
                    </Badge>
                  ) : (
                    <Text c="dimmed" size="xs">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {e.matched_feed_id ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {e.group_name ?? "—"}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}

// --- Widget registry ---

const WIDGET_DEFS = [
  { id: "query-volume",    label: "Query volume",          span: { base: 12, md: 8 } },
  { id: "decision",        label: "Decision breakdown",    span: { base: 12, md: 4 } },
  { id: "top-domains",     label: "Top blocked domains",   span: { base: 12, md: 6 } },
  { id: "categories",      label: "Blocks by category",    span: { base: 12, md: 6 } },
  { id: "top-clients",     label: "Top clients",           span: { base: 12 } },
  { id: "group-breakdown", label: "Group breakdown",       span: { base: 12 } },
  { id: "feed-health",     label: "Feed health",           span: { base: 12, md: 6 } },
  { id: "siem-delivery",   label: "SIEM delivery",         span: { base: 12, md: 6 } },
  { id: "recent-events",   label: "Recent block events",   span: { base: 12 } },
] as const;

type WidgetId = typeof WIDGET_DEFS[number]["id"];

interface WidgetConfig { id: WidgetId; visible: boolean }

const DEFAULT_CONFIG: WidgetConfig[] = WIDGET_DEFS.map((w) => ({ id: w.id, visible: true }));

function loadWidgetConfig(): WidgetConfig[] {
  try {
    const raw = localStorage.getItem("dashboard-widget-config");
    if (!raw) return DEFAULT_CONFIG;
    const saved: WidgetConfig[] = JSON.parse(raw);
    // Merge: keep saved order/visibility, add any new widgets at end
    const ids = new Set(saved.map((w) => w.id));
    const merged = [...saved, ...DEFAULT_CONFIG.filter((w) => !ids.has(w.id))];
    // Drop stale ids
    const valid = new Set(WIDGET_DEFS.map((w) => w.id));
    return merged.filter((w) => valid.has(w.id));
  } catch {
    return DEFAULT_CONFIG;
  }
}

function saveWidgetConfig(config: WidgetConfig[]) {
  localStorage.setItem("dashboard-widget-config", JSON.stringify(config));
}

// --- Main page ---

const TIME_SEGMENTS = [
  { value: "1", label: "1h" },
  { value: "6", label: "6h" },
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
];

export function DashboardPage() {
  const [hours, setHours] = useState(24);
  const [tenantFilter, setTenantFilter] = useState<string>("");
  const REFRESH = 30_000;
  const [widgetConfig, setWidgetConfig] = useState<WidgetConfig[]>(loadWidgetConfig);
  const [customizeOpened, { open: openCustomize, close: closeCustomize }] = useDisclosure(false);

  const { data: tenants } = useTenants();
  const { data: feeds } = useFeeds();
  const { data: webhooks } = useSiemWebhooks();

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["dashboard-summary", hours],
    queryFn: () => rawGet<DashboardSummary>("/api/v1/analytics/summary", { hours }),
    refetchInterval: REFRESH,
  });

  const { data: timeseries, isLoading: tsLoading } = useQuery({
    queryKey: ["dashboard-timeseries", hours],
    queryFn: () => rawGet<TimeseriesPoint[]>("/api/v1/analytics/timeseries", { hours }),
    refetchInterval: REFRESH,
  });

  const { data: byGroup, isLoading: groupLoading } = useQuery({
    queryKey: ["dashboard-by-group", hours],
    queryFn: () => rawGet<GroupBreakdown[]>("/api/v1/analytics/by-group", { hours }),
    refetchInterval: REFRESH,
  });

  const { data: topClients, isLoading: clientsLoading } = useQuery({
    queryKey: ["dashboard-top-clients", hours],
    queryFn: () => rawGet<TopClient[]>("/api/v1/analytics/top-clients", { hours, limit: 10 }),
    refetchInterval: REFRESH,
  });

  const { data: categories, isLoading: catsLoading } = useQuery({
    queryKey: ["dashboard-categories", hours],
    queryFn: () => rawGet<CategoryBreakdown[]>("/api/v1/analytics/top-categories", { hours }),
    refetchInterval: REFRESH,
  });

  const { data: recentBlocks, isLoading: recentLoading } = useQuery({
    queryKey: ["dashboard-recent-blocks"],
    queryFn: () => rawGet<RecentEvent[]>("/api/v1/analytics/recent-events", { decision: "block", limit: 25 }),
    refetchInterval: 10_000,
  });

  const tenantOptions = [
    { value: "", label: "All tenants" },
    ...(tenants ?? []).map((t) => ({ value: t.id, label: t.name })),
  ];

  function updateConfig(next: WidgetConfig[]) {
    setWidgetConfig(next);
    saveWidgetConfig(next);
  }

  function toggleWidget(id: WidgetId) {
    updateConfig(widgetConfig.map((w) => w.id === id ? { ...w, visible: !w.visible } : w));
  }

  function moveWidget(id: WidgetId, dir: -1 | 1) {
    const idx = widgetConfig.findIndex((w) => w.id === id);
    if (idx < 0) return;
    const next = [...widgetConfig];
    const swap = idx + dir;
    if (swap < 0 || swap >= next.length) return;
    [next[idx], next[swap]] = [next[swap], next[idx]];
    updateConfig(next);
  }

  function resetConfig() {
    updateConfig(DEFAULT_CONFIG);
  }

  function renderWidget(id: WidgetId) {
    switch (id) {
      case "query-volume":    return <QueryVolumeWidget data={timeseries} loading={tsLoading} />;
      case "decision":        return <DecisionWidget summary={summary} loading={summaryLoading} />;
      case "top-domains":     return <TopDomainsWidget data={summary?.top_blocked_domains} loading={summaryLoading} />;
      case "categories":      return <CategoriesWidget data={categories} loading={catsLoading} />;
      case "top-clients":     return <TopClientsWidget data={topClients} loading={clientsLoading} />;
      case "group-breakdown": return <GroupBreakdownWidget data={byGroup} loading={groupLoading} />;
      case "feed-health":     return <FeedHealthWidget data={feeds as FeedItem[] | undefined} />;
      case "siem-delivery":   return <SiemDeliveryWidget data={webhooks as WebhookItem[] | undefined} />;
      case "recent-events":   return <RecentEventsWidget data={recentBlocks} loading={recentLoading} />;
    }
  }

  const visibleWidgets = widgetConfig.filter((w) => w.visible);
  const hiddenCount = widgetConfig.length - visibleWidgets.length;

  return (
    <Stack gap="md">
      {/* Header */}
      <Group justify="space-between" wrap="wrap" gap="sm">
        <Title order={2}>Dashboard</Title>
        <Group gap="sm" wrap="wrap">
          <Select size="xs" data={tenantOptions} value={tenantFilter} onChange={(v) => setTenantFilter(v ?? "")} w={160} aria-label="Filter by tenant" />
          <SegmentedControl
            size="xs"
            value={String(hours)}
            onChange={(v) => setHours(Number(v))}
            data={TIME_SEGMENTS}
          />
          <Badge size="sm" variant="light" color="teal">auto-refresh 30s</Badge>
          <Tooltip label="Customize widgets">
            <ActionIcon variant="default" size="sm" onClick={openCustomize} aria-label="Customize dashboard">
              <IconLayoutDashboard size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* KPI strip */}
      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="sm">
        <KpiCard label="Total queries" value={summaryLoading ? "…" : (summary?.total_queries ?? 0).toLocaleString()} icon={IconActivity} />
        <KpiCard label="Block ratio" value={summaryLoading ? "…" : `${((summary?.block_ratio ?? 0) * 100).toFixed(1)}%`} icon={IconShieldOff} />
        <KpiCard label="Cache hit" value={summaryLoading ? "…" : `${((summary?.cache_hit_ratio ?? 0) * 100).toFixed(1)}%`} icon={IconBolt} />
        <KpiCard label="Active clients" value={summaryLoading ? "…" : (summary?.unique_clients ?? 0).toLocaleString()} icon={IconDevices} />
        <KpiCard label="Tenants" value={summaryLoading ? "…" : (summary?.tenant_count ?? 0).toLocaleString()} sub={`${summary?.group_count ?? 0} groups`} icon={IconUsers} />
      </SimpleGrid>

      {/* Configurable widget grid */}
      <Grid>
        {widgetConfig.filter((w) => w.visible).map((w) => {
          const def = WIDGET_DEFS.find((d) => d.id === w.id)!;
          return (
            <Grid.Col key={w.id} span={def.span}>
              {renderWidget(w.id)}
            </Grid.Col>
          );
        })}
      </Grid>

      {/* Customize drawer */}
      <Drawer
        opened={customizeOpened}
        onClose={closeCustomize}
        title="Customize dashboard"
        position="right"
        size="sm"
      >
        <Stack gap="xs">
          <Text size="xs" c="dimmed">
            Toggle widgets on or off and reorder them. Changes are saved automatically.
          </Text>

          {widgetConfig.map((w, idx) => (
            <Group key={w.id} justify="space-between" wrap="nowrap"
              style={{
                padding: "8px 10px",
                borderRadius: 6,
                background: "var(--mantine-color-default)",
                border: "1px solid var(--mantine-color-default-border)",
                opacity: w.visible ? 1 : 0.5,
              }}
            >
              <Switch
                label={WIDGET_DEFS.find((d) => d.id === w.id)!.label}
                checked={w.visible}
                onChange={() => toggleWidget(w.id)}
                size="sm"
              />
              <Group gap={2} wrap="nowrap">
                <ActionIcon
                  size="xs" variant="subtle"
                  disabled={idx === 0}
                  onClick={() => moveWidget(w.id, -1)}
                  aria-label="Move up"
                >
                  <IconChevronUp size={13} />
                </ActionIcon>
                <ActionIcon
                  size="xs" variant="subtle"
                  disabled={idx === widgetConfig.length - 1}
                  onClick={() => moveWidget(w.id, 1)}
                  aria-label="Move down"
                >
                  <IconChevronDown size={13} />
                </ActionIcon>
              </Group>
            </Group>
          ))}

          {hiddenCount > 0 && (
            <Text size="xs" c="dimmed" ta="center" mt="xs">
              {hiddenCount} widget{hiddenCount > 1 ? "s" : ""} hidden
            </Text>
          )}

          <ActionIcon
            variant="subtle" color="gray" size="sm"
            onClick={resetConfig}
            style={{ alignSelf: "flex-end" }}
            aria-label="Reset to defaults"
          >
            Reset to defaults
          </ActionIcon>
        </Stack>
      </Drawer>
    </Stack>
  );
}
