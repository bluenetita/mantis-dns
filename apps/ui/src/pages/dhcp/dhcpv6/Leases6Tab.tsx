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
import { useDhcpLeases6, type DhcpLease6 } from "../../../api/hooks";
import { CrudTable, type CrudColumn } from "../../../components/crud";
import { fmtExpire } from "../helpers";

export function Leases6Tab({
  scopeOptions,
  scopeId,
  onScopeChange,
  onReserve,
}: {
  scopeOptions: { value: string; label: string }[];
  scopeId: string | null;
  onScopeChange: (scopeId: string | null) => void;
  onReserve: (lease: DhcpLease6) => void;
}) {
  const { data: leases6 = [], isLoading, refetch, isFetching } = useDhcpLeases6(scopeId ?? undefined);
  const [search, setSearch] = useState("");

  const scopeName = useMemo(() => {
    const m = new Map(scopeOptions.map((o) => [o.value, o.label]));
    return (id: string) => m.get(id) ?? id;
  }, [scopeOptions]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return leases6;
    return leases6.filter(
      (l) =>
        l.ip_address.toLowerCase().includes(q) ||
        l.duid.toLowerCase().includes(q) ||
        (l.hostname ?? "").toLowerCase().includes(q),
    );
  }, [leases6, search]);

  const columns: CrudColumn<DhcpLease6>[] = [
    ...(!scopeId
      ? [{ key: "scope", header: "Scope", render: (l: DhcpLease6) => <Text size="xs" c="dimmed">{scopeName(l.scope_id)}</Text> } as CrudColumn<DhcpLease6>]
      : []),
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

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>Active IPv6 Leases</Title>
        <Group>
          <TextInput
            size="xs"
            placeholder="Search IP, DUID, hostname…"
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
        emptyState={<Text c="dimmed" size="sm">No active leases.</Text>}
      />
    </>
  );
}
