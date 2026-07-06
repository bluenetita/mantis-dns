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

import { Group, Stack, Tabs, Text, Title } from "@mantine/core";
import { IconServer } from "@tabler/icons-react";
import { HealthTab, PoolsTab, PolicyTab, ResolversTab, RoutesTab } from "./upstream";

export function UpstreamPage() {
  return (
    <Stack gap="lg">
      <Stack gap={2}>
        <Group gap={8}>
          <IconServer size={22} />
          <Title order={2}>DNS Upstream</Title>
        </Group>
        <Text c="dimmed" size="sm">
          Manage upstream resolver profiles, HA pools, per-tenant routing rules, and forwarding policy. All config is delivered to filter nodes as signed upstream bundles.
        </Text>
      </Stack>

      <Tabs defaultValue="resolvers" keepMounted={false}>
        <Tabs.List mb="lg">
          <Tabs.Tab value="resolvers">Resolvers</Tabs.Tab>
          <Tabs.Tab value="pools">Pools</Tabs.Tab>
          <Tabs.Tab value="routes">Routes</Tabs.Tab>
          <Tabs.Tab value="policy">Tenant policy</Tabs.Tab>
          <Tabs.Tab value="health">Health</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="resolvers"><ResolversTab /></Tabs.Panel>
        <Tabs.Panel value="pools"><PoolsTab /></Tabs.Panel>
        <Tabs.Panel value="routes"><RoutesTab /></Tabs.Panel>
        <Tabs.Panel value="policy"><PolicyTab /></Tabs.Panel>
        <Tabs.Panel value="health"><HealthTab /></Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
