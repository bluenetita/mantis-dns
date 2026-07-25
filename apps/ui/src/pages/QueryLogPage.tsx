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
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Select,
  SegmentedControl,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { IconSearch } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { QUERY_LOG_PAGE_SIZE, useCategories, useQueryLog } from "../api/hooks";
import { formatError } from "../api/errors";
import { formatLatency } from "../format";
import { useUrlFilters } from "../hooks/useUrlFilters";

const QTYPE_OPTIONS = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR", "SOA", "ANY"];

const DECISION_COLOR: Record<string, string> = {
  block: "red",
  allow: "green",
};

const HOURS_OPTIONS = [
  { label: "1h", value: "1" },
  { label: "6h", value: "6" },
  { label: "24h", value: "24" },
  { label: "7d", value: "168" },
  { label: "All", value: "" },
];

export function QueryLogPage() {
  const { t } = useTranslation();

  // Filters live in the URL (not useState) so a filtered view is shareable,
  // survives reload, and undoes with the back button.
  const [filters, setFilters] = useUrlFilters({
    decision: "",
    hours: "24",
    qname: "",
    client_ip: "",
    qtype: "",
    category: "",
    offset: "0",
  });

  const [qnameInput, setQnameInput] = useState(filters.qname);
  const [debouncedQname] = useDebouncedValue(qnameInput, 400);
  const [clientIpInput, setClientIpInput] = useState(filters.client_ip);
  const [debouncedClientIp] = useDebouncedValue(clientIpInput, 400);

  const { data: categories } = useCategories();

  const hours = filters.hours ? Number(filters.hours) : undefined;
  const offset = Number(filters.offset || 0);

  const { data, isLoading, error } = useQueryLog({
    offset,
    decision: (filters.decision || undefined) as "allow" | "block" | undefined,
    qname: debouncedQname || undefined,
    client_ip: debouncedClientIp || undefined,
    qtype: filters.qtype || undefined,
    matched_category: filters.category || undefined,
    hours,
  });

  // Debounced text filters sync into the URL once typing settles; offset
  // resets happen immediately in the input's onChange, not here, so this
  // effect firing on mount (debounced value === URL value) can't clobber a
  // shared deep link's offset.
  useEffect(() => {
    setFilters({ qname: debouncedQname });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQname]);

  useEffect(() => {
    setFilters({ client_ip: debouncedClientIp });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedClientIp]);

  function handleDecisionChange(v: string) {
    setFilters({ decision: v, offset: "0" });
  }

  function handleHoursChange(v: string) {
    setFilters({ hours: v, offset: "0" });
  }

  function handleQnameChange(e: React.ChangeEvent<HTMLInputElement>) {
    setQnameInput(e.currentTarget.value);
    setFilters({ offset: "0" });
  }

  function handleClientIpChange(e: React.ChangeEvent<HTMLInputElement>) {
    setClientIpInput(e.currentTarget.value);
    setFilters({ offset: "0" });
  }

  function handleQtypeChange(v: string | null) {
    setFilters({ qtype: v ?? "", offset: "0" });
  }

  function handleCategoryChange(v: string | null) {
    setFilters({ category: v ?? "", offset: "0" });
  }

  const page = Math.floor(offset / QUERY_LOG_PAGE_SIZE) + 1;
  const hasPrev = offset > 0;
  const hasNext = (data?.length ?? 0) === QUERY_LOG_PAGE_SIZE;

  return (
    <Stack>
      <Title order={2}>{t("queryLog.title")}</Title>

      <Group wrap="wrap" gap="sm">
        <SegmentedControl
          value={filters.decision}
          onChange={handleDecisionChange}
          data={[
            { label: t("queryLog.decision.all"), value: "" },
            { label: t("queryLog.decision.allowed"), value: "allow" },
            { label: t("queryLog.decision.blocked"), value: "block" },
          ]}
          size="xs"
        />
        <SegmentedControl
          value={filters.hours}
          onChange={handleHoursChange}
          data={HOURS_OPTIONS}
          size="xs"
        />
        <TextInput
          placeholder={t("queryLog.searchPlaceholder")}
          aria-label={t("queryLog.searchLabel")}
          leftSection={<IconSearch size={14} />}
          value={qnameInput}
          onChange={handleQnameChange}
          size="xs"
          w={220}
        />
        <TextInput
          placeholder={t("queryLog.filters.clientIpPlaceholder")}
          aria-label={t("queryLog.filters.clientIpLabel")}
          leftSection={<IconSearch size={14} />}
          value={clientIpInput}
          onChange={handleClientIpChange}
          size="xs"
          w={180}
        />
        <Select
          placeholder={t("queryLog.filters.qtypeAll")}
          aria-label={t("queryLog.filters.qtypeLabel")}
          data={QTYPE_OPTIONS}
          value={filters.qtype || null}
          onChange={(v) => handleQtypeChange(v)}
          clearable
          size="xs"
          w={140}
        />
        <Select
          placeholder={t("queryLog.filters.categoryAll")}
          aria-label={t("queryLog.filters.categoryLabel")}
          data={(categories ?? []).map((c) => ({ value: c.id, label: c.label }))}
          value={filters.category || null}
          onChange={(v) => handleCategoryChange(v)}
          clearable
          searchable
          size="xs"
          w={180}
        />
      </Group>

      {isLoading && (
        <Center h={200}>
          <Loader role="status" aria-label={t("common.loading")} />
        </Center>
      )}
      {error && <Text c="red" role="alert">{formatError(error)}</Text>}

      {!isLoading && data && data.length === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            {t("queryLog.empty")}
          </Text>
        </Card>
      )}

      {data && data.length > 0 && (
        <Table.ScrollContainer minWidth={640}>
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("queryLog.columns.time")}</Table.Th>
              <Table.Th>{t("queryLog.columns.client")}</Table.Th>
              <Table.Th>{t("queryLog.columns.group")}</Table.Th>
              <Table.Th>{t("queryLog.columns.domain")}</Table.Th>
              <Table.Th>{t("queryLog.columns.type")}</Table.Th>
              <Table.Th>{t("queryLog.columns.decision")}</Table.Th>
              <Table.Th>{t("queryLog.columns.category")}</Table.Th>
              <Table.Th>{t("queryLog.columns.latency")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((entry) => (
              <Table.Tr key={entry.id}>
                <Table.Td>
                  <Text size="xs" style={{ whiteSpace: "nowrap" }}>
                    {new Date(entry.occurred_at).toLocaleString()}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Tooltip label={entry.client_ip ?? "—"} disabled={!entry.client_name}>
                    <Text size="xs">{entry.client_name ?? entry.client_ip ?? "—"}</Text>
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{entry.group_name ?? entry.group_id.slice(0, 8)}</Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace">
                    {entry.qname}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {entry.qtype ?? "A"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="xs" color={DECISION_COLOR[entry.decision] ?? "gray"}>
                    {entry.decision}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {entry.matched_category ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {formatLatency(entry.latency_us)}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        </Table.ScrollContainer>
      )}

      <Group justify="center" gap="sm">
        <Button
          variant="default"
          size="xs"
          disabled={!hasPrev || isLoading}
          onClick={() => setFilters({ offset: String(Math.max(0, offset - QUERY_LOG_PAGE_SIZE)) })}
        >
          {t("queryLog.pagination.previous")}
        </Button>
        <Text size="sm" c="dimmed">
          {t("queryLog.pagination.page", { page })}
        </Text>
        <Button
          variant="default"
          size="xs"
          disabled={!hasNext || isLoading}
          onClick={() => setFilters({ offset: String(offset + QUERY_LOG_PAGE_SIZE) })}
        >
          {t("queryLog.pagination.next")}
        </Button>
      </Group>
    </Stack>
  );
}
