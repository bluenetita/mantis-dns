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
  ActionIcon,
  Badge,
  Grid,
  Group,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconActivity,
  IconBolt,
  IconDevices,
  IconLayoutDashboard,
  IconShieldOff,
  IconUsers,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { rawGet } from "../api/client";
import { useFeeds, useSiemWebhooks, useTenants } from "../api/hooks";
import { CustomizeDrawer } from "./dashboard/CustomizeDrawer";
import type {
  CategoryBreakdown,
  DashboardSummary,
  FeedItem,
  GroupBreakdown,
  RecentEvent,
  TimeseriesPoint,
  TopClient,
  WebhookItem,
} from "./dashboard/types";
import {
  DEFAULT_CONFIG,
  loadWidgetConfig,
  saveWidgetConfig,
  TIME_SEGMENTS,
  WIDGET_DEFS,
  type WidgetConfig,
  type WidgetId,
} from "./dashboard/widgetConfig";
import {
  CategoriesWidget,
  DecisionWidget,
  FeedHealthWidget,
  GroupBreakdownWidget,
  KpiCard,
  QueryVolumeWidget,
  RecentEventsWidget,
  SiemDeliveryWidget,
  TopClientsWidget,
  TopDomainsWidget,
} from "./dashboard/widgets";

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

      <CustomizeDrawer
        opened={customizeOpened}
        onClose={closeCustomize}
        widgetConfig={widgetConfig}
        onToggleWidget={toggleWidget}
        onMoveWidget={moveWidget}
        onResetConfig={resetConfig}
      />
    </Stack>
  );
}
