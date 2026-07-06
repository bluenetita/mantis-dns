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

import { Group, Progress, Stack, Text } from "@mantine/core";
import type { CategoryBreakdown } from "../types";
import { WidgetCard } from "./shared";

export function CategoriesWidget({ data, loading }: { data: CategoryBreakdown[] | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Blocks by category" loading={loading}>
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No categorised blocks in this window.
        </Text>
      ) : (
        <Stack gap="xs">
          {data.map((c) => (
            <div key={c.category}>
              <Group justify="space-between" mb={2}>
                <Text size="xs" tt="capitalize">
                  {c.category}
                </Text>
                <Text size="xs" c="dimmed">
                  {c.pct}%
                </Text>
              </Group>
              <Progress value={c.pct} color="red" size="sm" />
            </div>
          ))}
        </Stack>
      )}
    </WidgetCard>
  );
}
