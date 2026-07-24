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

import { Badge, Card, Group, Loader, Progress, Stack, Table, Text, Title } from "@mantine/core";
import { useDhcpHealth, useDhcpStats } from "../../api/hooks";

function timeAgo(iso: string): string {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(`${iso}Z`).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

export function StatusTab() {
  const { data: stats = [], isLoading: statsLoading } = useDhcpStats();
  const { data: instances = [], isLoading: healthLoading } = useDhcpHealth();

  return (
    <Stack gap="lg">
      <Card withBorder p="md">
        <Title order={5} mb="sm">DHCP daemon health</Title>
        {healthLoading ? (
          <Loader size="xs" />
        ) : instances.length === 0 ? (
          <Text c="dimmed" size="sm">
            No mantis-dhcp/mantis-dhcp6 instance has reported in — either none is running, or none has been up long
            enough for its first heartbeat yet.
          </Text>
        ) : (
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Family</Table.Th>
                <Table.Th>Host</Table.Th>
                <Table.Th>Started</Table.Th>
                <Table.Th>Last seen</Table.Th>
                <Table.Th>Status</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {instances.map((i) => (
                <Table.Tr key={i.instance_id}>
                  <Table.Td>DHCPv{i.family}</Table.Td>
                  <Table.Td>{i.hostname ?? <Text c="dimmed" size="xs">unknown</Text>}</Table.Td>
                  <Table.Td>{timeAgo(i.started_at)}</Table.Td>
                  <Table.Td>{timeAgo(i.last_seen_at)}</Table.Td>
                  <Table.Td>
                    {i.stale
                      ? <Badge size="xs" color="red">Not responding</Badge>
                      : <Badge size="xs" color="green">Online</Badge>}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
      <Card withBorder p="md">
        <Title order={5} mb="sm">Subnet utilisation</Title>
        {statsLoading ? (
          <Loader size="xs" />
        ) : stats.length === 0 ? (
          <Text c="dimmed" size="sm">No scopes, or no leases allocated yet.</Text>
        ) : (
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Scope</Table.Th>
                <Table.Th>Subnet</Table.Th>
                <Table.Th>Assigned / Total</Table.Th>
                <Table.Th>Utilisation</Table.Th>
                <Table.Th>Declined</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {stats.map((s) => {
                const pct = s.total_addresses > 0
                  ? Math.round((s.assigned_addresses / s.total_addresses) * 100)
                  : 0;
                return (
                  <Table.Tr key={s.scope_id}>
                    <Table.Td fw={500}>{s.scope_name}</Table.Td>
                    <Table.Td><code>{s.subnet}</code></Table.Td>
                    <Table.Td>{s.assigned_addresses} / {s.total_addresses}</Table.Td>
                    <Table.Td style={{ minWidth: 160 }}>
                      <Group gap="xs" align="center">
                        <Progress
                          value={pct}
                          color={pct > 85 ? "red" : pct > 60 ? "orange" : "blue"}
                          size="sm"
                          style={{ flex: 1 }}
                        />
                        <Text size="xs" w={32} ta="right">{pct}%</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      {s.declined_addresses > 0
                        ? <Badge size="xs" color="red">{s.declined_addresses}</Badge>
                        : <Text size="xs" c="dimmed">0</Text>}
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
