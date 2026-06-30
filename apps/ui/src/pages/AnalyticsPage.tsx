import { AreaChart } from "@mantine/charts";
import { Badge, Card, Center, Group, Loader, Progress, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useAnalyticsByGroup, useAnalyticsSummary, useAnalyticsTimeseries } from "../api/hooks";

function MetricCard({ label, value }: { label: string; value: string | number }) {
  return (
    <Card withBorder padding="md">
      <Text size="xs" c="dimmed" tt="uppercase">
        {label}
      </Text>
      <Text size="xl" fw={500}>
        {value}
      </Text>
    </Card>
  );
}

export function AnalyticsPage() {
  const { data, isLoading, error } = useAnalyticsSummary();
  const { data: timeseries } = useAnalyticsTimeseries(24);
  const { data: byGroup } = useAnalyticsByGroup();

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );
  if (error || !data) return <Text c="red">{String(error)}</Text>;

  const chartData = (timeseries ?? []).map((p) => ({
    time: new Date(p.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    Allowed: p.allowed,
    Blocked: p.blocked,
  }));

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Analytics</Title>
        <Text size="xs" c="dimmed">
          Refreshes every 15s
        </Text>
      </Group>

      <SimpleGrid cols={{ base: 2, sm: 3, md: 6 }}>
        <MetricCard label="Total queries" value={data.total_queries.toLocaleString()} />
        <MetricCard label="Blocked" value={data.blocked_queries.toLocaleString()} />
        <MetricCard label="Allowed" value={data.allowed_queries.toLocaleString()} />
        <MetricCard label="Block ratio" value={`${(data.block_ratio * 100).toFixed(1)}%`} />
        <MetricCard label="Tenants" value={data.tenant_count} />
        <MetricCard label="Groups" value={data.group_count} />
      </SimpleGrid>

      <Card withBorder>
        <Title order={4} mb="sm">
          Query volume — last 24h
        </Title>
        {chartData.every((p) => p.Allowed === 0 && p.Blocked === 0) ? (
          <Text c="dimmed" size="sm">
            No query telemetry in the last 24 hours.
          </Text>
        ) : (
          <AreaChart
            h={260}
            data={chartData}
            dataKey="time"
            series={[
              { name: "Allowed", color: "green.6" },
              { name: "Blocked", color: "red.6" },
            ]}
            type="stacked"
            curveType="step"
            withLegend
            tickLine="y"
          />
        )}
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          By group
        </Title>
        {(!byGroup || byGroup.length === 0) && (
          <Text c="dimmed" size="sm">
            No query telemetry recorded for any group yet.
          </Text>
        )}
        {byGroup && byGroup.length > 0 && (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>Group</Table.Th>
                <Table.Th>Total</Table.Th>
                <Table.Th>Blocked</Table.Th>
                <Table.Th>Block ratio</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {byGroup
                .sort((a, b) => b.total - a.total)
                .map((g) => (
                  <Table.Tr key={g.group_id}>
                    <Table.Td>{g.tenant_name}</Table.Td>
                    <Table.Td>{g.group_name}</Table.Td>
                    <Table.Td>{g.total.toLocaleString()}</Table.Td>
                    <Table.Td>{g.blocked.toLocaleString()}</Table.Td>
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
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          Top blocked domains (org-wide)
        </Title>
        {data.top_blocked_domains.length === 0 && (
          <Text c="dimmed" size="sm">
            No blocked queries recorded yet.
          </Text>
        )}
        {data.top_blocked_domains.length > 0 && (
          <Table>
            <Table.Tbody>
              {data.top_blocked_domains.map((d) => (
                <Table.Tr key={d.qname}>
                  <Table.Td>{d.qname}</Table.Td>
                  <Table.Td>
                    <Badge color="red">{d.decision}</Badge>
                  </Table.Td>
                  <Table.Td>{d.count}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>

      <Text size="sm" c="dimmed">
        Per-domain breakdown lives on each group's Policy page. Lower-level dashboards (QPS, cache-hit ratio, p99
        latency) are in Grafana —{" "}
        <a href="http://localhost:3000" target="_blank" rel="noreferrer">
          open Grafana
        </a>
        .
      </Text>
    </Stack>
  );
}
