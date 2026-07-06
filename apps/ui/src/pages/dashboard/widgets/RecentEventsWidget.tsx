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
import type { RecentEvent } from "../types";
import { WidgetCard } from "./shared";

export function RecentEventsWidget({ data, loading }: { data: RecentEvent[] | undefined; loading: boolean }) {
  return (
    <WidgetCard
      title="Recent block events"
      rightSection={
        <Badge size="xs" variant="light" color="red">
          live · last 25
        </Badge>
      }
      loading={loading}
    >
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No block events recorded yet.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Time</Table.Th>
              <Table.Th>Client</Table.Th>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Category</Table.Th>
              <Table.Th>Feed</Table.Th>
              <Table.Th>Group</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((e) => (
              <Table.Tr key={e.id}>
                <Table.Td>
                  <Text ff="monospace" size="xs" c="dimmed">
                    {new Date(e.occurred_at).toLocaleTimeString()}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {e.client_ip ?? "—"}
                  </Text>
                  {e.client_name && (
                    <Text size="xs" c="dimmed">
                      {e.client_name}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {e.qname}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {e.matched_category ? (
                    <Badge size="xs" color="red" variant="light">
                      {e.matched_category}
                    </Badge>
                  ) : (
                    <Text c="dimmed" size="xs">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {e.matched_feed_id ?? "—"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {e.group_name ?? "—"}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}
