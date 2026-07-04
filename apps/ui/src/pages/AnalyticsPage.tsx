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

import { AreaChart, DonutChart } from "@mantine/charts";
import {
  ActionIcon,
  Badge,
  Button,
  Card,
  Center,
  Grid,
  Group,
  Loader,
  Progress,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useState } from "react";
import { useAnalyticsByGroup, useAnalyticsSummary, useAnalyticsTimeseries } from "../api/hooks";

// ─── Time range options ───────────────────────────────────────────────────────

const TIME_RANGES = [
  { label: "1h",  hours: 1 },
  { label: "6h",  hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d",  hours: 168 },
  { label: "30d", hours: 720 },
] as const;

// ─── KPI card ─────────────────────────────────────────────────────────────────

function KpiCard({
  label,
  value,
  sub,
  accent = "blue",
  bar,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
  bar?: number;
}) {
  return (
    <Card withBorder padding="md">
      <Stack gap={6}>
        <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>
          {label}
        </Text>
        <Text size="xl" fw={700} lh={1}>
          {value}
        </Text>
        {bar !== undefined && (
          <Progress value={bar} color={accent} size="xs" radius="xs" />
        )}
        {sub && (
          <Text size="xs" c="dimmed">
            {sub}
          </Text>
        )}
      </Stack>
    </Card>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function AnalyticsPage() {
  const [hours, setHours] = useState<number>(24);

  const { data, isLoading, error, refetch: refetchSummary } = useAnalyticsSummary(hours);
  const { data: timeseries, refetch: refetchTs } = useAnalyticsTimeseries(hours);
  const { data: byGroup, refetch: refetchGroup } = useAnalyticsByGroup(hours);

  function refresh() {
    refetchSummary();
    refetchTs();
    refetchGroup();
  }

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );
  if (error || !data) return <Text c="red">{error ? String(error) : "No data available"}</Text>;

  // ── Derived values ──────────────────────────────────────────────────────────

  const blockPct = data.block_ratio * 100;

  const qpm =
    timeseries && timeseries.length > 0 && hours > 0
      ? ((data.total_queries / (hours * 60)) ).toFixed(2)
      : "—";

  const chartData = (timeseries ?? []).map((p) => ({
    time: new Date(p.bucket).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
    Allowed: p.allowed,
    Blocked: p.blocked,
  }));

  const hasChart = chartData.some((p) => p.Allowed > 0 || p.Blocked > 0);

  const donutData = [
    { name: "Allowed", value: data.allowed_queries, color: "teal.6" },
    { name: "Blocked", value: data.blocked_queries, color: "red.6" },
  ].filter((d) => d.value > 0);

  const totalBlocked = data.blocked_queries;
  const topDomains = [...(data.top_blocked_domains ?? [])]
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const sortedGroups = [...(byGroup ?? [])].sort((a, b) => b.total - a.total);

  return (
    <Stack gap="lg">
      {/* ── Header ── */}
      <Group justify="space-between" align="center">
        <Stack gap={2}>
          <Title order={2}>Analytics</Title>
          <Text c="dimmed" size="sm">
            DNS query telemetry across all tenants and groups
          </Text>
        </Stack>
        <Group gap="xs">
          <Button.Group>
            {TIME_RANGES.map((r) => (
              <Button
                key={r.hours}
                size="xs"
                variant={hours === r.hours ? "filled" : "default"}
                onClick={() => setHours(r.hours)}
              >
                {r.label}
              </Button>
            ))}
          </Button.Group>
          <Tooltip label="Refresh now">
            <ActionIcon variant="default" onClick={refresh} aria-label="Refresh">
              <IconRefresh size={16} />
            </ActionIcon>
          </Tooltip>
          <Text size="xs" c="dimmed">Auto-refresh 15s</Text>
        </Group>
      </Group>

      {/* ── KPI row ── */}
      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        <KpiCard
          label="Total queries"
          value={data.total_queries.toLocaleString()}
          sub={`${data.tenant_count} tenant${data.tenant_count !== 1 ? "s" : ""} · ${data.group_count} group${data.group_count !== 1 ? "s" : ""}`}
        />
        <KpiCard
          label="Blocked"
          value={data.blocked_queries.toLocaleString()}
          sub={`${data.allowed_queries.toLocaleString()} allowed`}
          accent="red"
        />
        <KpiCard
          label="Block rate"
          value={`${blockPct.toFixed(1)}%`}
          bar={blockPct}
          accent={blockPct > 50 ? "red" : blockPct > 20 ? "orange" : "teal"}
          sub={blockPct > 30 ? "Elevated — review policies" : "Within normal range"}
        />
        <KpiCard
          label="Queries / min"
          value={qpm}
          sub={`over last ${TIME_RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`}`}
        />
      </SimpleGrid>

      {/* ── Chart row ── */}
      <Grid>
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card withBorder padding="md" h="100%">
            <Group justify="space-between" mb="sm">
              <Title order={4}>
                Query volume —{" "}
                {TIME_RANGES.find((r) => r.hours === hours)?.label ?? `${hours}h`}
              </Title>
              <Group gap={6}>
                <Badge size="xs" color="teal" variant="dot">Allowed</Badge>
                <Badge size="xs" color="red" variant="dot">Blocked</Badge>
              </Group>
            </Group>
            {!hasChart ? (
              <Center h={220}>
                <Text c="dimmed" size="sm">No query telemetry in this time window.</Text>
              </Center>
            ) : (
              <AreaChart
                h={220}
                data={chartData}
                dataKey="time"
                series={[
                  { name: "Allowed", color: "teal.6" },
                  { name: "Blocked", color: "red.6" },
                ]}
                type="stacked"
                curveType="monotone"
                withDots={false}
                withLegend={false}
                tickLine="y"
                gridAxis="y"
              />
            )}
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 4 }}>
          <Card withBorder padding="md" h="100%">
            <Title order={4} mb="sm">Decision breakdown</Title>
            {donutData.length === 0 ? (
              <Center h={220}>
                <Text c="dimmed" size="sm">No data yet.</Text>
              </Center>
            ) : (
              <Center>
                <DonutChart
                  data={donutData}
                  size={180}
                  thickness={28}
                  tooltipDataSource="segment"
                  withLabelsLine
                  withLabels
                />
              </Center>
            )}
            {donutData.length > 0 && (
              <Stack gap={4} mt="md">
                {donutData.map((d) => (
                  <Group key={d.name} justify="space-between">
                    <Group gap={6}>
                      <Badge size="xs" color={d.color.split(".")[0]} variant="filled">{d.name}</Badge>
                    </Group>
                    <Text size="sm" fw={500}>{d.value.toLocaleString()}</Text>
                  </Group>
                ))}
              </Stack>
            )}
          </Card>
        </Grid.Col>
      </Grid>

      {/* ── Top blocked domains ── */}
      <Card withBorder padding="md">
        <Title order={4} mb="sm">Top blocked domains</Title>
        {topDomains.length === 0 ? (
          <Text c="dimmed" size="sm">No blocked queries recorded yet.</Text>
        ) : (
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th w={40}>#</Table.Th>
                <Table.Th>Domain</Table.Th>
                <Table.Th w={100}>Decision</Table.Th>
                <Table.Th w={80} style={{ textAlign: "right" }}>Count</Table.Th>
                <Table.Th w={160}>Share of total blocks</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {topDomains.map((d, i) => {
                const pct = totalBlocked > 0 ? (d.count / totalBlocked) * 100 : 0;
                return (
                  <Table.Tr key={d.qname}>
                    <Table.Td>
                      <Text size="sm" c="dimmed">{i + 1}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" ff="monospace">{d.qname}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge size="sm" color="red" variant="light">{d.decision}</Badge>
                    </Table.Td>
                    <Table.Td style={{ textAlign: "right" }}>
                      <Text size="sm" fw={500}>{d.count.toLocaleString()}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={8} wrap="nowrap">
                        <Progress value={pct} color="red" size="sm" radius="xs" style={{ flex: 1 }} />
                        <Text size="xs" c="dimmed" w={36} style={{ textAlign: "right" }}>
                          {pct.toFixed(1)}%
                        </Text>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        )}
      </Card>

      {/* ── Group performance ── */}
      <Card withBorder padding="md">
        <Title order={4} mb="sm">Performance by group</Title>
        {sortedGroups.length === 0 ? (
          <Text c="dimmed" size="sm">No query telemetry recorded for any group yet.</Text>
        ) : (
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>Group</Table.Th>
                <Table.Th w={100} style={{ textAlign: "right" }}>Total</Table.Th>
                <Table.Th w={100} style={{ textAlign: "right" }}>Blocked</Table.Th>
                <Table.Th w={200}>Block rate</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {sortedGroups.map((g) => {
                const pct = g.block_ratio * 100;
                return (
                  <Table.Tr key={g.group_id}>
                    <Table.Td>
                      <Text size="sm">{g.tenant_name}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" fw={500}>{g.group_name}</Text>
                    </Table.Td>
                    <Table.Td style={{ textAlign: "right" }}>
                      <Text size="sm" ff="monospace">{g.total.toLocaleString()}</Text>
                    </Table.Td>
                    <Table.Td style={{ textAlign: "right" }}>
                      <Text size="sm" ff="monospace" c="red">{g.blocked.toLocaleString()}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group gap={8} wrap="nowrap">
                        <Progress
                          value={pct}
                          color={pct > 50 ? "red" : pct > 20 ? "orange" : "teal"}
                          size="sm"
                          radius="xs"
                          style={{ flex: 1 }}
                        />
                        <Text size="xs" fw={500} w={36} style={{ textAlign: "right" }}>
                          {pct.toFixed(0)}%
                        </Text>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}
