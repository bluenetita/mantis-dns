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

import { Group, Stack, Text, Title } from "@mantine/core";
import type { IconServer } from "@tabler/icons-react";
import type { ReactNode } from "react";

export interface PageHeaderProps {
  title: string;
  icon?: typeof IconServer;
  description?: string;
  /** Inline badge/status next to the title (e.g. a "daemon not responding" flag). */
  status?: ReactNode;
  /** Right-aligned controls — buttons, filters, segmented controls. */
  actions?: ReactNode;
}

/** One header shape for every page: icon + title + optional status inline,
 * dimmed description underneath, actions right-aligned. */
export function PageHeader({ title, icon: Icon, description, status, actions }: PageHeaderProps) {
  return (
    <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
      <Stack gap={2}>
        <Group gap={8}>
          {Icon && <Icon size={22} aria-hidden />}
          <Title order={2}>{title}</Title>
          {status}
        </Group>
        {description && (
          <Text c="dimmed" size="sm">
            {description}
          </Text>
        )}
      </Stack>
      {actions && (
        <Group gap="sm" wrap="wrap">
          {actions}
        </Group>
      )}
    </Group>
  );
}
