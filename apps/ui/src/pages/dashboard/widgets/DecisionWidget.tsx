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

import { DonutChart } from "@mantine/charts";
import { Center, Group, Stack, Text } from "@mantine/core";
import type { DashboardSummary } from "../types";
import { WidgetCard } from "./shared";

export function DecisionWidget({ summary, loading }: { summary: DashboardSummary | undefined; loading: boolean }) {
  const total = summary?.total_queries ?? 0;
  const blocked = summary?.blocked_queries ?? 0;
  const allowed = summary?.allowed_queries ?? 0;

  const data =
    total > 0
      ? [
          { name: "Allowed", value: allowed, color: "blue.5" },
          { name: "Blocked", value: blocked, color: "red.5" },
        ]
      : [{ name: "No data", value: 1, color: "gray.3" }];

  return (
    <WidgetCard title="Decision breakdown" loading={loading} minH={280}>
      <Center>
        <DonutChart
          data={data}
          withTooltip={total > 0}
          tooltipDataSource="segment"
          size={160}
          thickness={28}
          chartLabel={total > 0 ? `${((allowed / total) * 100).toFixed(1)}% allowed` : ""}
        />
      </Center>
      {total > 0 && (
        <Stack gap={4} mt="sm">
          <Group justify="space-between">
            <Group gap="xs">
              <div style={{ width: 10, height: 10, borderRadius: 2, background: "var(--mantine-color-blue-5)" }} />
              <Text size="xs">Allowed</Text>
            </Group>
            <Text size="xs" c="dimmed">
              {allowed.toLocaleString()}
            </Text>
          </Group>
          <Group justify="space-between">
            <Group gap="xs">
              <div style={{ width: 10, height: 10, borderRadius: 2, background: "var(--mantine-color-red-5)" }} />
              <Text size="xs">Blocked</Text>
            </Group>
            <Text size="xs" c="dimmed">
              {blocked.toLocaleString()}
            </Text>
          </Group>
        </Stack>
      )}
    </WidgetCard>
  );
}
