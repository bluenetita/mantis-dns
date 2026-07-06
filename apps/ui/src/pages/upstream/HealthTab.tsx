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

import { Card, Stack, Text } from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";

// ── Health placeholder (Sprint 18) ────────────────────────────────────────────

export function HealthTab() {
  return (
    <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
      <Stack align="center" gap="xs">
        <IconInfoCircle size={28} style={{ color: "var(--mantine-color-dimmed)" }} />
        <Text fw={500} c="dimmed">Upstream Health Dashboard</Text>
        <Text size="sm" c="dimmed" ta="center">
          Per-resolver health state timelines, latency P50/P95/P99 charts, error breakdown, and pool utilization will appear here once the Sprint 18 health monitor is active in the filter node.
        </Text>
      </Stack>
    </Card>
  );
}
