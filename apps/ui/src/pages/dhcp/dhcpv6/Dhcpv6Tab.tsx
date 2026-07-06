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

import { Stack, Tabs } from "@mantine/core";
import { useState } from "react";
import { useDhcpScopes6 } from "../../../api/hooks";
import { Leases6Tab } from "./Leases6Tab";
import { Reservation6sTab } from "./Reservation6sTab";
import { Scope6sTab } from "./Scope6sTab";

export function Dhcpv6Tab({ tenantOptions }: { tenantOptions: { value: string; label: string }[] }) {
  const [activeTab, setActiveTab] = useState<string>("scopes6");
  const [scopeId, setScopeId] = useState<string | null>(null);

  // Same scope selection is shared between the Reservations and Leases
  // sub-tabs, mirroring the original single-component behaviour.
  const { data: scopes6 = [] } = useDhcpScopes6();
  const scope6Options = scopes6.map((s) => ({ value: s.id, label: `${s.name} (${s.subnet})` }));

  return (
    <Stack gap="md">
      <Tabs value={activeTab} onChange={(v) => setActiveTab(v ?? "scopes6")} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="scopes6">Scopes</Tabs.Tab>
          <Tabs.Tab value="reservations6">Reservations</Tabs.Tab>
          <Tabs.Tab value="leases6">Leases</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="scopes6" pt="md">
          <Scope6sTab tenantOptions={tenantOptions} />
        </Tabs.Panel>
        <Tabs.Panel value="reservations6" pt="md">
          <Reservation6sTab scopeOptions={scope6Options} scopeId={scopeId} onScopeChange={setScopeId} />
        </Tabs.Panel>
        <Tabs.Panel value="leases6" pt="md">
          <Leases6Tab scopeOptions={scope6Options} scopeId={scopeId} onScopeChange={setScopeId} />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
