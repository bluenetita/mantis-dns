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

import { Badge, Card, Group, Loader, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconAlertTriangle, IconCircleCheck, IconServerBolt } from "@tabler/icons-react";
import { useKeasStatus } from "../../api/hooks";

export function KeaStatusCard({ compact = false }: { compact?: boolean }) {
  const { data: status, isLoading } = useKeasStatus();
  const isHealthy = status?.ok === true;
  const isDown = !isLoading && !isHealthy;
  const color = isHealthy ? "green" : isDown ? "red" : "gray";
  const label = isLoading ? "Checking" : isHealthy ? "Running" : "Unreachable";
  const Icon = isHealthy ? IconCircleCheck : isDown ? IconAlertTriangle : IconServerBolt;

  return (
    <Card
      withBorder
      p={compact ? "sm" : "md"}
      bg={isDown ? "red.0" : isHealthy ? "green.0" : undefined}
      style={{
        borderColor: isDown ? "var(--mantine-color-red-5)" : isHealthy ? "var(--mantine-color-green-4)" : undefined,
      }}
    >
      <Group justify="space-between" align="center" gap="md" wrap="wrap">
        <Group gap="sm" align="center" wrap="nowrap" style={{ flex: "1 1 260px", minWidth: 0 }}>
          <ThemeIcon color={color} variant={isDown ? "filled" : "light"} size={compact ? 34 : 40} radius="xl">
            <Icon size={compact ? 20 : 22} />
          </ThemeIcon>
          <Stack gap={2} style={{ minWidth: 0 }}>
            <Group gap="xs" align="center">
              <Title order={5}>Kea daemon</Title>
              <Badge color={color} variant={isDown ? "filled" : "light"} size={compact ? "md" : "sm"}>
                {label}
              </Badge>
              {isLoading && <Loader size="xs" />}
            </Group>
            <Text size={compact ? "sm" : "xs"} c={isDown ? "red.9" : "dimmed"} lineClamp={compact ? 1 : undefined}>
              {isLoading
                ? "Checking Kea management API status"
                : isHealthy
                  ? status.version ?? "version unknown"
                  : status?.error ?? "Kea management API could not be reached"}
            </Text>
          </Stack>
        </Group>

        {status?.url && (
          <Text
            size="xs"
            c={isDown ? "red.9" : "dimmed"}
            ta="right"
            lineClamp={1}
            style={{ flex: "0 1 360px", minWidth: 0 }}
          >
            {status.url}
          </Text>
        )}
      </Group>
    </Card>
  );
}
