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

import { Badge, Group, SegmentedControl, Stack, Tabs, Title } from "@mantine/core";
import { IconWifi } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useDhcpHealth, useDhcpScopes, useDhcpScopes6, useTenants, useZones } from "../api/hooks";
import { LeasesTab, ReservationsTab, ScopesTab, StatusTab, type ReservePrefill } from "./dhcp";
import { Leases6Tab, Reservation6sTab, Scope6sTab } from "./dhcp/dhcpv6";

const FAMILIES = ["4", "6"] as const;
type Family = (typeof FAMILIES)[number];

export function DhcpPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const family: Family = searchParams.get("family") === "6" ? "6" : "4";
  const tab = searchParams.get("tab") ?? "scopes";

  const setFamily = (f: string) => setSearchParams((p) => { p.set("family", f); return p; }, { replace: true });
  const setTab = (t: string) => setSearchParams((p) => { p.set("tab", t); return p; }, { replace: true });

  const { data: tenants = [] } = useTenants();
  const { data: zones = [] } = useZones();
  const { data: scopes = [] } = useDhcpScopes();
  const { data: scopes6 = [] } = useDhcpScopes6();
  const { data: health = [] } = useDhcpHealth();

  const tenantOptions = tenants.map((t) => ({ value: t.id, label: t.name }));
  const zoneOptions = (zones as { id: string; name: string; zone_type: string }[])
    .filter((z) => z.zone_type === "local")
    .map((z) => ({ value: z.id, label: z.name }));
  const scopeOptions = scopes.map((s) => ({ value: s.id, label: `${s.name} (${s.subnet})` }));
  const scope6Options = scopes6.map((s) => ({ value: s.id, label: `${s.name} (${s.subnet})` }));

  // Scope selection is shared between the Reservations and Leases sub-tabs so
  // switching tabs doesn't lose the admin's place.
  const [scopeId4, setScopeId4] = useState<string | null>(null);
  const [scopeId6, setScopeId6] = useState<string | null>(null);

  // Auto-select the only scope there is — most installs have just one or two.
  useEffect(() => {
    if (!scopeId4 && scopes.length === 1) setScopeId4(scopes[0].id);
  }, [scopeId4, scopes]);
  useEffect(() => {
    if (!scopeId6 && scopes6.length === 1) setScopeId6(scopes6[0].id);
  }, [scopeId6, scopes6]);

  const [prefill4, setPrefill4] = useState<ReservePrefill | null>(null);
  const [prefill6, setPrefill6] = useState<ReservePrefill | null>(null);

  const reserveFromLease = (f: Family, scopeId: string, prefill: ReservePrefill) => {
    setFamily(f);
    if (f === "4") { setScopeId4(scopeId); setPrefill4(prefill); }
    else { setScopeId6(scopeId); setPrefill6(prefill); }
    setTab("reservations");
  };

  const anyStale = health.some((h) => h.stale);

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Group gap="xs" align="center">
          <IconWifi size={22} aria-hidden />
          <Title order={2}>DHCP</Title>
          {anyStale && (
            <Badge
              size="sm"
              color="red"
              style={{ cursor: "pointer" }}
              onClick={() => setTab("status")}
            >
              Daemon not responding
            </Badge>
          )}
        </Group>
        <SegmentedControl
          value={family}
          onChange={setFamily}
          data={[
            { label: "DHCPv4", value: "4" },
            { label: "DHCPv6", value: "6" },
          ]}
        />
      </Group>

      <Tabs value={tab} onChange={(v) => setTab(v ?? "scopes")} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="scopes">Scopes</Tabs.Tab>
          <Tabs.Tab value="reservations">Reservations</Tabs.Tab>
          <Tabs.Tab value="leases">Leases</Tabs.Tab>
          <Tabs.Tab value="status">Status</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="scopes" pt="md">
          {family === "4" ? (
            <ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />
          ) : (
            <Scope6sTab tenantOptions={tenantOptions} />
          )}
        </Tabs.Panel>

        <Tabs.Panel value="reservations" pt="md">
          {family === "4" ? (
            <ReservationsTab
              scopeOptions={scopeOptions}
              scopeId={scopeId4}
              onScopeChange={setScopeId4}
              prefill={prefill4}
              onPrefillConsumed={() => setPrefill4(null)}
            />
          ) : (
            <Reservation6sTab
              scopeOptions={scope6Options}
              scopeId={scopeId6}
              onScopeChange={setScopeId6}
              prefill={prefill6}
              onPrefillConsumed={() => setPrefill6(null)}
            />
          )}
        </Tabs.Panel>

        <Tabs.Panel value="leases" pt="md">
          {family === "4" ? (
            <LeasesTab
              scopeOptions={scopeOptions}
              scopeId={scopeId4}
              onScopeChange={setScopeId4}
              onReserve={(l) => reserveFromLease("4", l.scope_id, { mac_address: l.mac_address, ip_address: l.ip_address })}
            />
          ) : (
            <Leases6Tab
              scopeOptions={scope6Options}
              scopeId={scopeId6}
              onScopeChange={setScopeId6}
              onReserve={(l) => reserveFromLease("6", l.scope_id, { duid: l.duid, ip_address: l.ip_address })}
            />
          )}
        </Tabs.Panel>

        <Tabs.Panel value="status" pt="md">
          <StatusTab />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
