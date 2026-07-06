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

import { Group, Progress, Table, Text } from "@mantine/core";
import type { GroupBreakdown } from "../types";
import { WidgetCard } from "./shared";

export function GroupBreakdownWidget({ data, loading }: { data: GroupBreakdown[] | undefined; loading: boolean }) {
  const sorted = [...(data ?? [])].sort((a, b) => b.total - a.total);

  return (
    <WidgetCard title="Per-group breakdown" loading={loading}>
      {sorted.length === 0 ? (
        <Text c="dimmed" size="sm">
          No group telemetry yet.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Tenant</Table.Th>
              <Table.Th>Group</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Total</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Blocked</Table.Th>
              <Table.Th>Block ratio</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {sorted.map((g) => (
              <Table.Tr key={g.group_id}>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {g.tenant_name}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{g.group_name}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{g.total.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{g.blocked.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" wrap="nowrap">
                    <Progress value={g.block_ratio * 100} color="red" size="sm" w={80} />
                    <Text size="xs">{(g.block_ratio * 100).toFixed(0)}%</Text>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}
