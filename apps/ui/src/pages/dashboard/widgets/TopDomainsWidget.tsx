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

import { Table, Text } from "@mantine/core";
import type { DashboardSummary } from "../types";
import { WidgetCard } from "./shared";

export function TopDomainsWidget({
  data,
  loading,
}: {
  data: DashboardSummary["top_blocked_domains"] | undefined;
  loading: boolean;
}) {
  return (
    <WidgetCard title="Top blocked domains" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No blocked queries in this window.
        </Text>
      ) : (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>#</Table.Th>
              <Table.Th>Domain</Table.Th>
              <Table.Th style={{ textAlign: "right" }}>Hits</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {data.map((d, i) => (
              <Table.Tr key={d.qname}>
                <Table.Td>
                  <Text c="dimmed" size="xs">
                    {i + 1}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="xs">
                    {d.qname}
                  </Text>
                </Table.Td>
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="xs">{d.count.toLocaleString()}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </WidgetCard>
  );
}
