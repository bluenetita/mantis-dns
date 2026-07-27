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

import { Group, Progress, SimpleGrid, Stack, Text } from "@mantine/core";
import type { MixSlice, QueryMix } from "../types";
import { WidgetCard } from "./shared";

function MixColumn({ title, slices, color }: { title: string; slices: MixSlice[]; color: string }) {
  return (
    <Stack gap={4}>
      <Text size="xs" fw={500} c="dimmed">
        {title}
      </Text>
      {slices.length === 0 ? (
        <Text size="xs" c="dimmed">
          No data
        </Text>
      ) : (
        slices.slice(0, 5).map((s) => (
          <div key={s.label}>
            <Group justify="space-between" mb={2}>
              <Text size="xs" ff="monospace">
                {s.label}
              </Text>
              <Text size="xs" c="dimmed">
                {s.pct}%
              </Text>
            </Group>
            <Progress value={s.pct} color={color} size="sm" />
          </div>
        ))
      )}
    </Stack>
  );
}

export function QueryMixWidget({ data, loading }: { data: QueryMix | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Query mix" loading={loading}>
      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        <MixColumn title="Query type" slices={data?.qtype ?? []} color="grape" />
        <MixColumn title="Response code" slices={data?.response_code ?? []} color="orange" />
        <MixColumn title="Matched rule" slices={data?.matched_rule ?? []} color="cyan" />
      </SimpleGrid>
    </WidgetCard>
  );
}
