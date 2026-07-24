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
import { useDhcpStats } from "../../api/hooks";

export function StatusTab() {
  const { data: stats = [], isLoading: statsLoading } = useDhcpStats();

  return (
    <Stack gap="lg">
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
