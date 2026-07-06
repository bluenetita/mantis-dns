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

import { ActionIcon, Drawer, Group, Stack, Switch, Text } from "@mantine/core";
import { IconChevronDown, IconChevronUp } from "@tabler/icons-react";
import { WIDGET_DEFS, type WidgetConfig, type WidgetId } from "./widgetConfig";

export function CustomizeDrawer({
  opened,
  onClose,
  widgetConfig,
  onToggleWidget,
  onMoveWidget,
  onResetConfig,
}: {
  opened: boolean;
  onClose: () => void;
  widgetConfig: WidgetConfig[];
  onToggleWidget: (id: WidgetId) => void;
  onMoveWidget: (id: WidgetId, dir: -1 | 1) => void;
  onResetConfig: () => void;
}) {
  const hiddenCount = widgetConfig.filter((w) => !w.visible).length;

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      title="Customize dashboard"
      position="right"
      size="sm"
    >
      <Stack gap="xs">
        <Text size="xs" c="dimmed">
          Toggle widgets on or off and reorder them. Changes are saved automatically.
        </Text>

        {widgetConfig.map((w, idx) => (
          <Group key={w.id} justify="space-between" wrap="nowrap"
            style={{
              padding: "8px 10px",
              borderRadius: 6,
              background: "var(--mantine-color-default)",
              border: "1px solid var(--mantine-color-default-border)",
              opacity: w.visible ? 1 : 0.5,
            }}
          >
            <Switch
              label={WIDGET_DEFS.find((d) => d.id === w.id)!.label}
              checked={w.visible}
              onChange={() => onToggleWidget(w.id)}
              size="sm"
            />
            <Group gap={2} wrap="nowrap">
              <ActionIcon
                size="xs" variant="subtle"
                disabled={idx === 0}
                onClick={() => onMoveWidget(w.id, -1)}
                aria-label="Move up"
              >
                <IconChevronUp size={13} />
              </ActionIcon>
              <ActionIcon
                size="xs" variant="subtle"
                disabled={idx === widgetConfig.length - 1}
                onClick={() => onMoveWidget(w.id, 1)}
                aria-label="Move down"
              >
                <IconChevronDown size={13} />
              </ActionIcon>
            </Group>
          </Group>
        ))}

        {hiddenCount > 0 && (
          <Text size="xs" c="dimmed" ta="center" mt="xs">
            {hiddenCount} widget{hiddenCount > 1 ? "s" : ""} hidden
          </Text>
        )}

        <ActionIcon
          variant="subtle" color="gray" size="sm"
          onClick={onResetConfig}
          style={{ alignSelf: "flex-end" }}
          aria-label="Reset to defaults"
        >
          Reset to defaults
        </ActionIcon>
      </Stack>
    </Drawer>
  );
}
