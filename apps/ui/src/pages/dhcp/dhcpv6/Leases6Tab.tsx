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

import { ActionIcon, Badge, Group, Select, Text, Title, Tooltip } from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useDhcpLeases6, type DhcpLease6 } from "../../../api/hooks";
import { CrudTable, type CrudColumn } from "../../../components/crud";
import { fmtExpire } from "../helpers";

const columns: CrudColumn<DhcpLease6>[] = [
  { key: "ip", header: "IP address", render: (l) => <code>{l.ip_address}</code> },
  { key: "duid", header: "DUID", render: (l) => <code style={{ fontSize: 11 }}>{l.duid}</code> },
  { key: "hostname", header: "Hostname", render: (l) => l.hostname || <Text size="xs" c="dimmed">—</Text> },
  {
    key: "type",
    header: "Type",
    render: (l) => (
      <Badge size="xs" color={l.lease_type === 2 ? "grape" : "blue"}>
        {l.lease_type === 2 ? "IA_PD" : "IA_NA"}
      </Badge>
    ),
  },
  { key: "expires", header: "Expires in", render: (l) => <Text size="xs">{fmtExpire(l.expires_at)}</Text> },
];

export function Leases6Tab({
  scopeOptions,
  scopeId,
  onScopeChange,
}: {
  scopeOptions: { value: string; label: string }[];
  scopeId: string | null;
  onScopeChange: (scopeId: string | null) => void;
}) {
  const { data: leases6 = [], isLoading, refetch, isFetching } = useDhcpLeases6(scopeId ?? undefined);

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={5}>Active IPv6 Leases</Title>
        <Group>
          <Select size="xs" placeholder="Select scope" data={scopeOptions} value={scopeId}
            onChange={(v) => onScopeChange(v ?? "")} clearable style={{ minWidth: 220 }} />
          <Tooltip label="Refresh">
            <ActionIcon variant="default" size="sm" loading={isFetching} onClick={() => refetch()}>
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {!scopeId ? (
        <Text c="dimmed" size="sm">Select a scope.</Text>
      ) : (
        <CrudTable
          data={leases6}
          isLoading={isLoading}
          getRowKey={(l, i) => `${l.ip_address}-${i}`}
          columns={columns}
          emptyState={<Text c="dimmed" size="sm">No active leases.</Text>}
        />
      )}
    </>
  );
}
