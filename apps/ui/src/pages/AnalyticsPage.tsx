import { Badge, Card, Center, Group, Loader, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { useAnalyticsSummary } from "../api/hooks";

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

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );
  if (error || !data) return <Text c="red">{String(error)}</Text>;

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
        Per-tenant breakdown lives on each group's Policy page. Detailed dashboards (QPS, cache-hit ratio, p99
        latency) are in Grafana —{" "}
        <a href="http://localhost:3000" target="_blank" rel="noreferrer">
          open Grafana
        </a>
        .
      </Text>
    </Stack>
  );
}
