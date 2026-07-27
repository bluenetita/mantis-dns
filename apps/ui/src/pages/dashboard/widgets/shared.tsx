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

import { Card, Center, Group, Loader, Text } from "@mantine/core";
import type React from "react";

export { KpiCard } from "../../../components/KpiCard";

/** Builds a /query-log href carrying the given filters plus the widget's own time window, so clicking a dashboard row drills into the matching query log rows. */
export function queryLogHref(hours: number, params: Record<string, string | undefined>): string {
  const search = new URLSearchParams({ hours: String(hours) });
  for (const [k, v] of Object.entries(params)) {
    if (v) search.set(k, v);
  }
  return `/query-log?${search.toString()}`;
}

export function WidgetCard({
  title,
  rightSection,
  children,
  loading,
  minH,
}: {
  title: string;
  rightSection?: React.ReactNode;
  children: React.ReactNode;
  loading?: boolean;
  minH?: number;
}) {
  return (
    <Card withBorder h="100%" style={minH ? { minHeight: minH } : undefined}>
      <Group justify="space-between" mb="sm">
        <Text fw={500} size="sm">
          {title}
        </Text>
        {rightSection}
      </Group>
      {loading ? (
        <Center py="xl">
          <Loader size="sm" />
        </Center>
      ) : (
        children
      )}
    </Card>
  );
}
