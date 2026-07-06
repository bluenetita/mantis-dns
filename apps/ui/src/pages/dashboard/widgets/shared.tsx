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
import type { IconActivity } from "@tabler/icons-react";
import type React from "react";

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

export function KpiCard({
  label,
  value,
  sub,
  icon: Icon,
}: {
  label: string;
  value: string;
  sub?: string;
  icon: typeof IconActivity;
}) {
  return (
    <Card withBorder padding="sm">
      <Group gap="xs" mb={4}>
        <Icon size={14} aria-hidden="true" color="var(--mantine-color-dimmed)" />
        <Text size="xs" c="dimmed">
          {label}
        </Text>
      </Group>
      <Text size="xl" fw={500} lh={1.1}>
        {value}
      </Text>
      {sub && (
        <Text size="xs" c="dimmed" mt={2}>
          {sub}
        </Text>
      )}
    </Card>
  );
}
