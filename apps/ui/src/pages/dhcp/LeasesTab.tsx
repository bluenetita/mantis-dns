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
import { useState } from "react";
import { useDhcpLeases, type DhcpLease } from "../../api/hooks";
import { CrudTable, type CrudColumn } from "../../components/crud";
import { fmtExpire, LEASE_STATE } from "./helpers";

const columns: CrudColumn<DhcpLease>[] = [
  { key: "ip", header: "IP", render: (l) => <code>{l.ip_address}</code> },
  { key: "mac", header: "MAC", render: (l) => <code>{l.mac_address}</code> },
  { key: "hostname", header: "Hostname", render: (l) => l.hostname || <Text size="xs" c="dimmed">—</Text> },
  { key: "expires", header: "Expires in", render: (l) => <Text size="xs">{fmtExpire(l.expires_at)}</Text> },
  {
    key: "state",
    header: "State",
    render: (l) => {
      const st = LEASE_STATE[l.state] ?? { label: `State ${l.state}`, color: "gray" };
      return <Badge size="xs" color={st.color}>{st.label}</Badge>;
    },
  },
];

export function LeasesTab({ scopeOptions }: { scopeOptions: { value: string; label: string }[] }) {
  const [scopeId, setScopeId] = useState<string | null>(null);
  const { data: leases = [], isLoading, refetch, isFetching } = useDhcpLeases(scopeId ?? undefined);

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>Active Leases</Title>
        <Group>
          <Select
            size="xs"
            placeholder="Select scope"
            data={scopeOptions}
            value={scopeId}
            onChange={(v) => setScopeId(v ?? "")}
            clearable
            style={{ minWidth: 220 }}
          />
          <Tooltip label="Refresh">
            <ActionIcon variant="default" size="sm" loading={isFetching} onClick={() => refetch()}>
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {!scopeId ? (
        <Text c="dimmed" size="sm">Select a scope to view active leases.</Text>
      ) : (
        <CrudTable
          data={leases}
          isLoading={isLoading}
          getRowKey={(l) => l.ip_address}
          columns={columns}
          emptyState={<Text c="dimmed" size="sm">No active leases. Auto-refreshes every 30 s.</Text>}
        />
      )}
    </>
  );
}
