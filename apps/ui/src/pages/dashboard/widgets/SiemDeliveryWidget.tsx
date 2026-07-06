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

import { Badge, Group, Stack, Text } from "@mantine/core";
import type { WebhookItem } from "../types";
import { WidgetCard } from "./shared";

function webhookStatus(w: WebhookItem): { color: string; label: string } {
  if (!w.enabled) return { color: "gray", label: "disabled" };
  if (w.consecutive_failures >= 3) return { color: "red", label: `${w.consecutive_failures} failures` };
  if (w.consecutive_failures > 0) return { color: "yellow", label: "retrying" };
  return { color: "green", label: "ok" };
}

export function SiemDeliveryWidget({ data }: { data: WebhookItem[] | undefined }) {
  return (
    <WidgetCard title="SIEM delivery">
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No webhooks configured.
        </Text>
      ) : (
        <Stack gap={6}>
          {data.map((w) => {
            const s = webhookStatus(w);
            return (
              <Group key={w.id} justify="space-between" wrap="nowrap">
                <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                  <Badge size="xs" color={s.color} variant="dot" />
                  <Text size="xs" truncate>
                    {w.name}
                  </Text>
                </Group>
                <Group gap="xs" wrap="nowrap">
                  <Badge size="xs" variant="light" color="gray">
                    {w.format.toUpperCase()}
                  </Badge>
                  <Text size="xs" c={s.color === "green" ? "dimmed" : s.color}>
                    {s.label}
                  </Text>
                </Group>
              </Group>
            );
          })}
        </Stack>
      )}
    </WidgetCard>
  );
}
