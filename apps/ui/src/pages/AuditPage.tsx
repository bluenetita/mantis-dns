import { Badge, Button, Card, Center, Group, Loader, Select, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { AUDIT_PAGE_SIZE, useAuditLog } from "../api/hooks";

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
  const { t } = useTranslation();
  const [resourceType, setResourceType] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const { data, isLoading, error } = useAuditLog(resourceType ?? undefined, offset);

  const page = Math.floor(offset / AUDIT_PAGE_SIZE) + 1;
  const hasPrev = offset > 0;
  const hasNext = (data?.length ?? 0) === AUDIT_PAGE_SIZE;

  function handleResourceTypeChange(v: string | null) {
    setResourceType(v);
    setOffset(0);
  }

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>{t("auditLog.title")}</Title>
        <Select
          placeholder={t("auditLog.filterPlaceholder")}
          data={RESOURCE_TYPES}
          value={resourceType}
          onChange={handleResourceTypeChange}
          clearable
          w={200}
        />
      </Group>

      {isLoading && (
        <Center h={200}>
          <Loader role="status" aria-label={t("common.loading")} />
        </Center>
      )}
      {error && <Text c="red" role="alert">{String(error)}</Text>}

      {data && data.length === 0 && offset === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            {t("auditLog.emptyTitle")}
          </Text>
        </Card>
      )}

      {data && data.length === 0 && offset > 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">{t("auditLog.noMoreEntries")}</Text>
        </Card>
      )}

      {data && data.length > 0 && (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("auditLog.columns.time")}</Table.Th>
              <Table.Th>{t("auditLog.columns.actor")}</Table.Th>
              <Table.Th>{t("auditLog.columns.action")}</Table.Th>
              <Table.Th>{t("auditLog.columns.resource")}</Table.Th>
              <Table.Th>{t("auditLog.columns.detail")}</Table.Th>
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

      <Group justify="center" gap="sm">
        <Button
          variant="default"
          size="xs"
          disabled={!hasPrev || isLoading}
          onClick={() => setOffset(Math.max(0, offset - AUDIT_PAGE_SIZE))}
        >
          {t("auditLog.pagination.previous")}
        </Button>
        <Text size="sm" c="dimmed">
          {t("auditLog.pagination.page", { page })}
        </Text>
        <Button
          variant="default"
          size="xs"
          disabled={!hasNext || isLoading}
          onClick={() => setOffset(offset + AUDIT_PAGE_SIZE)}
        >
          {t("auditLog.pagination.next")}
        </Button>
      </Group>
    </Stack>
  );
}
