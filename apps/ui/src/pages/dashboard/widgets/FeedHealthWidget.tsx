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
import type { FeedItem } from "../types";
import { WidgetCard } from "./shared";

function feedStatus(f: FeedItem): { color: string; label: string } {
  if (!f.enabled) return { color: "gray", label: "disabled" };
  if (f.last_domain_count == null) return { color: "yellow", label: "pending" };
  return { color: "green", label: "ok" };
}

export function FeedHealthWidget({ data }: { data: FeedItem[] | undefined }) {
  return (
    <WidgetCard title="Feed health">
      {!data || data.length === 0 ? (
        <Text c="dimmed" size="sm">
          No feeds configured.
        </Text>
      ) : (
        <Stack gap={6}>
          {data.slice(0, 8).map((f) => {
            const s = feedStatus(f);
            return (
              <Group key={f.id} justify="space-between" wrap="nowrap">
                <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                  <Badge size="xs" color={s.color} variant="dot" />
                  <Text size="xs" truncate>
                    {f.provider || f.id}
                  </Text>
                </Group>
                <Group gap="xs" wrap="nowrap">
                  <Badge size="xs" variant="light" color="gray">
                    {f.category_id}
                  </Badge>
                  {f.last_domain_count != null && (
                    <Text size="xs" c="dimmed">
                      {f.last_domain_count.toLocaleString()} domains
                    </Text>
                  )}
                </Group>
              </Group>
            );
          })}
          {data.length > 8 && (
            <Text size="xs" c="dimmed">
              +{data.length - 8} more
            </Text>
          )}
        </Stack>
      )}
    </WidgetCard>
  );
}
