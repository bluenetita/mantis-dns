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
  Alert,
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
  IconAlertTriangle,
  IconBolt,
  IconDevices,
  IconLayoutDashboard,
  IconShieldOff,
  IconUsers,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { rawGet } from "../api/client";
import { formatError } from "../api/errors";
import { useFeeds } from "../api/hooks";
import { CustomizeDrawer } from "./dashboard/CustomizeDrawer";
import type {
  CategoryBreakdown,
  DashboardSummary,
  FeedItem,
  GroupBreakdown,
  LatencyStats,
  QueryMix,
  RecentEvent,
  TimeseriesPoint,
  TopClient,
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
  LatencyWidget,
  QueryMixWidget,
  QueryVolumeWidget,
  RecentEventsWidget,
  TopClientsWidget,
  TopDomainsWidget,
} from "./dashboard/widgets";

export function DashboardPage() {
  const [hours, setHours] = useState(24);
  const [groupScope, setGroupScope] = useState<string | null>(null);
  const REFRESH = 30_000;
  const [widgetConfig, setWidgetConfig] = useState<WidgetConfig[]>(loadWidgetConfig);
  const [customizeOpened, { open: openCustomize, close: closeCustomize }] = useDisclosure(false);

  const { data: feeds } = useFeeds();

  const { data: summary, isLoading: summaryLoading, error: summaryError } = useQuery({
    queryKey: ["dashboard-summary", hours, groupScope],
    queryFn: () => rawGet<DashboardSummary>("/api/v1/analytics/summary", { hours, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  const { data: timeseries, isLoading: tsLoading, error: tsError } = useQuery({
    queryKey: ["dashboard-timeseries", hours, groupScope],
    queryFn: () => rawGet<TimeseriesPoint[]>("/api/v1/analytics/timeseries", { hours, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  // by-group is always org-wide (it IS the per-group breakdown) — not scoped
  // by groupScope, and doubles as the source of options for the scope picker.
  const { data: byGroup, isLoading: groupLoading, error: groupError } = useQuery({
    queryKey: ["dashboard-by-group", hours],
    queryFn: () => rawGet<GroupBreakdown[]>("/api/v1/analytics/by-group", { hours }),
    refetchInterval: REFRESH,
  });

  const { data: topClients, isLoading: clientsLoading, error: clientsError } = useQuery({
    queryKey: ["dashboard-top-clients", hours, groupScope],
    queryFn: () =>
      rawGet<TopClient[]>("/api/v1/analytics/top-clients", { hours, limit: 10, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  const { data: categories, isLoading: catsLoading, error: catsError } = useQuery({
    queryKey: ["dashboard-categories", hours, groupScope],
    queryFn: () =>
      rawGet<CategoryBreakdown[]>("/api/v1/analytics/top-categories", { hours, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  const { data: recentBlocks, isLoading: recentLoading, error: recentError } = useQuery({
    queryKey: ["dashboard-recent-blocks", hours, groupScope],
    queryFn: () =>
      rawGet<RecentEvent[]>("/api/v1/analytics/recent-events", {
        decision: "block",
        limit: 25,
        hours,
        group_id: groupScope ?? undefined,
      }),
    refetchInterval: 10_000,
  });

  // Surfaced as a banner, and used to blank the KPI strip instead of showing
  // "0" for numbers we actually failed to fetch — a false "0 blocked" reads
  // as "all clear" on a DNS filtering dashboard, which is the wrong failure mode.
  const { data: latency, isLoading: latencyLoading, error: latencyError } = useQuery({
    queryKey: ["dashboard-latency", hours, groupScope],
    queryFn: () => rawGet<LatencyStats>("/api/v1/analytics/latency", { hours, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  const { data: queryMix, isLoading: mixLoading, error: mixError } = useQuery({
    queryKey: ["dashboard-query-mix", hours, groupScope],
    queryFn: () => rawGet<QueryMix>("/api/v1/analytics/query-mix", { hours, group_id: groupScope ?? undefined }),
    refetchInterval: REFRESH,
  });

  const groupOptions = (byGroup ?? []).map((g) => ({
    value: g.group_id,
    label: `${g.tenant_name} / ${g.group_name}`,
  }));

  // Prior equal-length period, for the "vs prior window" deltas on the KPI
  // strip — otherwise every number on the dashboard is a number without a
  // baseline, which is why it reads as flat even when something changed.
  const { data: prevSummary } = useQuery({
    queryKey: ["dashboard-summary-prev", hours, groupScope],
    queryFn: () =>
      rawGet<DashboardSummary>("/api/v1/analytics/summary", {
        hours,
        offset_hours: hours,
        group_id: groupScope ?? undefined,
      }),
    refetchInterval: REFRESH,
  });

  const rangeLabel = TIME_SEGMENTS.find((s) => Number(s.value) === hours)?.label ?? `${hours}h`;

  function relativeDelta(cur: number | undefined, prev: number | undefined): string | undefined {
    if (cur === undefined || prev === undefined) return undefined;
    if (prev === 0) return cur > 0 ? `new vs prior ${rangeLabel}` : undefined;
    const pct = ((cur - prev) / prev) * 100;
    const arrow = pct > 0 ? "▲" : pct < 0 ? "▼" : "";
    return `${arrow}${Math.abs(pct).toFixed(0)}% vs prior ${rangeLabel}`;
  }

  function pointDelta(cur: number | undefined, prev: number | undefined): string | undefined {
    if (cur === undefined || prev === undefined) return undefined;
    const pts = (cur - prev) * 100;
    const arrow = pts > 0 ? "▲" : pts < 0 ? "▼" : "";
    return `${arrow}${Math.abs(pts).toFixed(1)}pts vs prior ${rangeLabel}`;
  }

  const dashboardError =
    summaryError ?? tsError ?? groupError ?? clientsError ?? catsError ?? recentError ?? latencyError ?? mixError;

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
      case "decision":        return <DecisionWidget summary={summary} loading={summaryLoading} hours={hours} />;
      case "top-domains":     return <TopDomainsWidget data={summary?.top_blocked_domains} loading={summaryLoading} hours={hours} />;
      case "categories":      return <CategoriesWidget data={categories} loading={catsLoading} hours={hours} />;
      case "top-clients":     return <TopClientsWidget data={topClients} loading={clientsLoading} hours={hours} />;
      case "group-breakdown":
        return (
          <GroupBreakdownWidget
            data={byGroup}
            loading={groupLoading}
            scopedGroupId={groupScope}
            onScope={setGroupScope}
          />
        );
      case "feed-health":     return <FeedHealthWidget data={feeds as FeedItem[] | undefined} />;
      case "recent-events":   return <RecentEventsWidget data={recentBlocks} loading={recentLoading} hours={hours} />;
      case "latency":         return <LatencyWidget data={latency} loading={latencyLoading} />;
      case "query-mix":       return <QueryMixWidget data={queryMix} loading={mixLoading} />;
    }
  }

  return (
    <Stack gap="md">
      {/* Header */}
      <Group justify="space-between" wrap="wrap" gap="sm">
        <Title order={2}>Dashboard</Title>
        <Group gap="sm" wrap="wrap">
          <Select
            size="xs"
            placeholder="All groups"
            data={groupOptions}
            value={groupScope}
            onChange={(value) => setGroupScope(value)}
            searchable
            clearable
            w={220}
          />
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

      {dashboardError && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} title="Some dashboard data failed to load">
          {formatError(dashboardError)}
        </Alert>
      )}

      {/* KPI strip */}
      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="sm">
        <KpiCard
          label="Total queries"
          value={summaryLoading ? "…" : summaryError ? "—" : (summary?.total_queries ?? 0).toLocaleString()}
          sub={summaryError ? undefined : relativeDelta(summary?.total_queries, prevSummary?.total_queries)}
          icon={IconActivity}
        />
        <KpiCard
          label="Block ratio"
          value={summaryLoading ? "…" : summaryError ? "—" : `${((summary?.block_ratio ?? 0) * 100).toFixed(1)}%`}
          sub={summaryError ? undefined : pointDelta(summary?.block_ratio, prevSummary?.block_ratio)}
          icon={IconShieldOff}
        />
        <KpiCard
          label="Cache hit"
          value={summaryLoading ? "…" : summaryError ? "—" : `${((summary?.cache_hit_ratio ?? 0) * 100).toFixed(1)}%`}
          sub={summaryError ? undefined : pointDelta(summary?.cache_hit_ratio, prevSummary?.cache_hit_ratio)}
          icon={IconBolt}
        />
        <KpiCard
          label="Active clients"
          value={summaryLoading ? "…" : summaryError ? "—" : (summary?.unique_clients ?? 0).toLocaleString()}
          sub={summaryError ? undefined : relativeDelta(summary?.unique_clients, prevSummary?.unique_clients)}
          icon={IconDevices}
        />
        <KpiCard label="Tenants" value={summaryLoading ? "…" : summaryError ? "—" : (summary?.tenant_count ?? 0).toLocaleString()} sub={summaryError ? undefined : `${summary?.group_count ?? 0} groups`} icon={IconUsers} />
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
