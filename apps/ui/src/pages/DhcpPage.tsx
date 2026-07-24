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

import { Group, Stack, Tabs, Title } from "@mantine/core";
import { IconWifi } from "@tabler/icons-react";
import { useDhcpScopes, useTenants, useZones } from "../api/hooks";
import { LeasesTab, ReservationsTab, ScopesTab, StatusTab } from "./dhcp";
import { Dhcpv6Tab } from "./dhcp/dhcpv6";

export function DhcpPage() {
  const { data: tenants = [] } = useTenants();
  const { data: zones = [] } = useZones();
  const { data: scopes = [] } = useDhcpScopes();

  const tenantOptions = tenants.map((t) => ({ value: t.id, label: t.name }));
  const zoneOptions = (zones as { id: string; name: string; zone_type: string }[])
    .filter((z) => z.zone_type === "local")
    .map((z) => ({ value: z.id, label: z.name }));
  const scopeOptions = scopes.map((s) => ({
    value: s.id,
    label: `${s.name} (${s.subnet})`,
  }));

  return (
    <Stack gap="md">
      <Group gap="xs" align="center">
        <IconWifi size={22} aria-hidden />
        <Title order={2}>DHCP</Title>
      </Group>

      <Tabs defaultValue="scopes" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="scopes">Scopes</Tabs.Tab>
          <Tabs.Tab value="reservations">Reservations</Tabs.Tab>
          <Tabs.Tab value="leases">Leases</Tabs.Tab>
          <Tabs.Tab value="status">Status</Tabs.Tab>
          <Tabs.Tab value="ipv6">DHCPv6</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="scopes" pt="md">
          <ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />
        </Tabs.Panel>
        <Tabs.Panel value="reservations" pt="md">
          <ReservationsTab scopeOptions={scopeOptions} />
        </Tabs.Panel>
        <Tabs.Panel value="leases" pt="md">
          <LeasesTab scopeOptions={scopeOptions} />
        </Tabs.Panel>
        <Tabs.Panel value="status" pt="md">
          <StatusTab />
        </Tabs.Panel>
        <Tabs.Panel value="ipv6" pt="md">
          <Dhcpv6Tab tenantOptions={tenantOptions} />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
