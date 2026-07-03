import { Alert, Badge, Card, Center, Group, Loader, Select, Stack, Table, Text, Title } from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import { useState } from "react";
import { useAuditLog } from "../api/hooks";

const RESOURCE_TYPES = ["tenant", "group", "policy", "feed", "dns_zone", "dns_record", "user"];

const ACTION_COLOR: Record<string, string> = {
  create: "green",
  update: "blue",
  delete: "red",
  compile: "grape",
};

function colorFor(action: string): string {
  const verb = action.split(".")[1] ?? action;
  return ACTION_COLOR[verb] ?? "gray";
}

export function AuditPage() {
  const [resourceType, setResourceType] = useState<string | null>(null);
  const { data, isLoading, error } = useAuditLog(resourceType ?? undefined);

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Audit log</Title>
        <Select
          placeholder="All resource types"
          data={RESOURCE_TYPES}
          value={resourceType}
          onChange={setResourceType}
          clearable
          w={200}
        />
      </Group>

      <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light">
        Every entry currently shows actor "unauthenticated" — there's no auth yet (design.md §9, Sprint 8 backend).
        The log itself is real and append-only from the moment this shipped; actor identity backfills once OIDC
        lands.
      </Alert>

      {isLoading && (
        <Center h={200}>
          <Loader />
        </Center>
      )}
      {error && <Text c="red">{String(error)}</Text>}

      {data && data.length === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            No audit entries yet. Every create/update/delete on tenants, groups, policies, and feeds gets logged
            here.
          </Text>
        </Card>
      )}

      {data && data.length > 0 && (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Time</Table.Th>
              <Table.Th>Actor</Table.Th>
              <Table.Th>Action</Table.Th>
              <Table.Th>Resource</Table.Th>
              <Table.Th>Detail</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((entry) => (
              <Table.Tr key={entry.id}>
                <Table.Td>{new Date(entry.occurred_at).toLocaleString()}</Table.Td>
                <Table.Td>{entry.actor}</Table.Td>
                <Table.Td>
                  <Badge color={colorFor(entry.action)}>{entry.action}</Badge>
                </Table.Td>
                <Table.Td>
                  {entry.resource_type}:{entry.resource_id.slice(0, 8)}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {entry.detail}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Stack>
  );
}
