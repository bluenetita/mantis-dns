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

import { SimpleGrid, Text } from "@mantine/core";
import type { LatencyStats } from "../types";
import { WidgetCard } from "./shared";

function fmtUs(us: number | null): string {
  if (us === null) return "—";
  return us >= 1000 ? `${(us / 1000).toFixed(1)} ms` : `${Math.round(us)} µs`;
}

export function LatencyWidget({ data, loading }: { data: LatencyStats | undefined; loading: boolean }) {
  return (
    <WidgetCard title="Resolver latency" loading={loading}>
      {!data || data.sample_count === 0 ? (
        <Text c="dimmed" size="sm">
          No latency samples in this window.
        </Text>
      ) : (
        <SimpleGrid cols={3}>
          {[
            { label: "p50", value: data.p50_us },
            { label: "p95", value: data.p95_us },
            { label: "p99", value: data.p99_us },
          ].map((s) => (
            <div key={s.label}>
              <Text size="xs" c="dimmed" tt="uppercase">
                {s.label}
              </Text>
              <Text size="lg" fw={600}>
                {fmtUs(s.value)}
              </Text>
            </div>
          ))}
        </SimpleGrid>
      )}
    </WidgetCard>
  );
}
