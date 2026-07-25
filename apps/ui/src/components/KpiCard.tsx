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

import { Card, Group, Progress, Stack, Text } from "@mantine/core";
import type { IconActivity } from "@tabler/icons-react";

export interface KpiCardProps {
  label: string;
  value: string | number;
  sub?: string;
  /** Optional leading icon. */
  icon?: typeof IconActivity;
  /** Mantine color name, used for the icon and the optional progress bar. */
  accent?: string;
  /** 0–100. Renders a thin progress bar under the value when set. */
  bar?: number;
}

export function KpiCard({ label, value, sub, icon: Icon, accent = "blue", bar }: KpiCardProps) {
  return (
    <Card withBorder padding="sm">
      <Stack gap={4}>
        <Group gap="xs" justify="space-between" wrap="nowrap">
          <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>
            {label}
          </Text>
          {Icon && <Icon size={14} aria-hidden="true" color={`var(--mantine-color-${accent}-6)`} />}
        </Group>
        <Text size="xl" fw={700} lh={1.1}>
          {value}
        </Text>
        {bar !== undefined && <Progress value={bar} color={accent} size="xs" radius="xs" />}
        {sub && (
          <Text size="xs" c="dimmed">
            {sub}
          </Text>
        )}
      </Stack>
    </Card>
  );
}
