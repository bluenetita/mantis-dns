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

import { Badge, Table, Text } from "@mantine/core";
import type { TopClient } from "../types";
import { WidgetCard } from "./shared";

export function TopClientsWidget({ data, loading }: { data: TopClient[] | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Top clients by query volume" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No client telemetry in this window.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Client</Table.Th>
              <Table.Th>Owner</Table.Th>
              <Table.Th>Group</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Queries</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Block%</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((c) => (
              <Table.Tr key={c.client_ip}>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {c.client_ip}
                  </Text>
                  {c.hostname && (
                    <Text size="xs" c="dimmed">
                      {c.hostname}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {c.owner ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {c.group_name ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{c.total.toLocaleString()}</Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Badge
                    size="sm"
                    color={c.block_ratio > 0.3 ? "red" : c.block_ratio > 0.1 ? "yellow" : "green"}
                    variant="light"
                  >
                    {(c.block_ratio * 100).toFixed(0)}%
                  </Badge>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}
