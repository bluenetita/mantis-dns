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

import { AreaChart } from "@mantine/charts";
import { Text } from "@mantine/core";
import type { TimeseriesPoint } from "../types";
import { WidgetCard } from "./shared";

export function QueryVolumeWidget({ data, loading }: { data: TimeseriesPoint[] | undefined; loading: boolean }) {
  const chartData = (data ?? []).map((p) => ({
    time: new Date(p.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    Allowed: p.allowed,
    Blocked: p.blocked,
  }));

  return (
    <WidgetCard title="Query volume" loading={loading} minH={280}>
      {chartData.every((p) => p.Allowed === 0 && p.Blocked === 0) ? (
        <Text c="dimmed" size="sm">
          No query telemetry in this window.
        </Text>
      ) : (
        <AreaChart
          h={220}
          data={chartData}
          dataKey="time"
          series={[
            { name: "Allowed", color: "blue.5" },
            { name: "Blocked", color: "red.5" },
          ]}
          type="stacked"
          curveType="step"
          withLegend
          tickLine="y"
          withDots={false}
        />
      )}
    </WidgetCard>
  );
}
