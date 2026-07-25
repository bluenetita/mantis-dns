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

import { ActionIcon, Badge, Group, Select, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { IconRefresh, IconSearch, IconStar } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import { useDhcpLeases, type DhcpLease } from "../../api/hooks";
import { CrudTable, type CrudColumn } from "../../components/crud";
import { fmtExpire, LEASE_STATE } from "./helpers";

export function LeasesTab({
  scopeOptions,
  scopeId,
  onScopeChange,
  onReserve,
}: {
  scopeOptions: { value: string; label: string }[];
  scopeId: string | null;
  onScopeChange: (scopeId: string | null) => void;
  onReserve: (lease: DhcpLease) => void;
}) {
  const { data: leases = [], isLoading, refetch, isFetching } = useDhcpLeases(scopeId ?? undefined);
  const [search, setSearch] = useState("");

  const scopeName = useMemo(() => {
    const m = new Map(scopeOptions.map((o) => [o.value, o.label]));
    return (id: string) => m.get(id) ?? id;
  }, [scopeOptions]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return leases;
    return leases.filter(
      (l) =>
        l.ip_address.toLowerCase().includes(q) ||
        l.mac_address.toLowerCase().includes(q) ||
        (l.hostname ?? "").toLowerCase().includes(q),
    );
  }, [leases, search]);

  const columns: CrudColumn<DhcpLease>[] = [
    ...(!scopeId
      ? [{ key: "scope", header: "Scope", render: (l: DhcpLease) => <Text size="xs" c="dimmed">{scopeName(l.scope_id)}</Text> } as CrudColumn<DhcpLease>]
      : []),
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

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>Active Leases</Title>
        <Group>
          <TextInput
            size="xs"
            placeholder="Search IP, MAC, hostname…"
            leftSection={<IconSearch size={14} />}
            value={search}
            onChange={(e) => setSearch(e.currentTarget.value)}
            style={{ minWidth: 200 }}
          />
          <Select
            size="xs"
            placeholder="All scopes"
            data={scopeOptions}
            value={scopeId}
            onChange={onScopeChange}
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

      <CrudTable
        data={filtered}
        isLoading={isLoading}
        getRowKey={(l) => `${l.scope_id}-${l.ip_address}`}
        columns={columns}
        renderRowActions={(l) => (
          <Tooltip label="Reserve this IP for this client">
            <ActionIcon aria-label="Reserve" size="sm" variant="subtle" onClick={() => onReserve(l)}>
              <IconStar size={14} />
            </ActionIcon>
          </Tooltip>
        )}
        emptyState={<Text c="dimmed" size="sm">No active leases. Auto-refreshes every 30 s.</Text>}
      />
    </>
  );
}
