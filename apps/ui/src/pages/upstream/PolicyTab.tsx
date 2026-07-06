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

import { Button, Center, Checkbox, Group, Loader, NumberInput, Select, SimpleGrid, Stack, Text } from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { useState } from "react";
import { useTenants, useUpstreamTenantPolicy, useUpsertUpstreamTenantPolicy } from "../../api/hooks";
import { DNSSEC_OPTIONS } from "./constants";

export function PolicyTab() {
  const { data: tenants = [] } = useTenants();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const { data: policy, isLoading } = useUpstreamTenantPolicy(tenantId ?? undefined);
  const upsertPolicy = useUpsertUpstreamTenantPolicy(tenantId ?? undefined);

  const form = useForm({
    initialValues: {
      require_encrypted: false,
      dnssec_validation: "opportunistic",
      qname_minimization: true,
      blocked_response_type: "nxdomain",
      min_ttl_s: 0,
      max_ttl_s: 86400,
      negative_ttl_s: 300,
    },
  });

  // Sync form when policy loads
  const [synced, setSynced] = useState<string | null>(null);
  if (policy && tenantId && synced !== tenantId) {
    form.setValues({
      require_encrypted: policy.require_encrypted,
      dnssec_validation: policy.dnssec_validation,
      qname_minimization: policy.qname_minimization,
      blocked_response_type: policy.blocked_response_type,
      min_ttl_s: policy.min_ttl_s,
      max_ttl_s: policy.max_ttl_s,
      negative_ttl_s: policy.negative_ttl_s,
    });
    setSynced(tenantId);
  }

  return (
    <Stack gap="md">
      <Text size="sm" c="dimmed">
        Per-tenant upstream DNS behaviour: DNSSEC enforcement, encryption requirements, TTL clamping, and blocked-query response type.
      </Text>

      <Select
        label="Tenant"
        placeholder="Select a tenant"
        data={tenants.map((t) => ({ value: t.id, label: t.name }))}
        value={tenantId}
        onChange={(v) => { setTenantId(v); setSynced(null); }}
        clearable
      />

      {tenantId && isLoading && <Center h={80}><Loader size="sm" /></Center>}

      {tenantId && !isLoading && (
        <form
          onSubmit={form.onSubmit((values) =>
            upsertPolicy.mutate(values, {
              onSuccess: () => notifications.show({ message: "Upstream policy saved", color: "green" }),
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            })
          )}
        >
          <Stack gap="md">
            <Select
              label="DNSSEC validation"
              data={DNSSEC_OPTIONS}
              {...form.getInputProps("dnssec_validation")}
            />
            <Select
              label="Blocked query response"
              data={[
                { value: "nxdomain", label: "NXDOMAIN (default)" },
                { value: "refused", label: "REFUSED" },
                { value: "zero_ip", label: "Zero IP (0.0.0.0)" },
              ]}
              {...form.getInputProps("blocked_response_type")}
            />
            <SimpleGrid cols={3}>
              <NumberInput label="Min TTL (s)" min={0} description="Clamp downstream TTL" {...form.getInputProps("min_ttl_s")} />
              <NumberInput label="Max TTL (s)" min={0} description="Clamp downstream TTL" {...form.getInputProps("max_ttl_s")} />
              <NumberInput label="Negative TTL (s)" min={0} description="TTL for NXDOMAIN/REFUSED responses" {...form.getInputProps("negative_ttl_s")} />
            </SimpleGrid>
            <Group>
              <Checkbox label="Require encrypted upstream (reject do53 resolvers)" {...form.getInputProps("require_encrypted", { type: "checkbox" })} />
            </Group>
            <Checkbox label="QNAME minimization" {...form.getInputProps("qname_minimization", { type: "checkbox" })} />

            <Group justify="flex-end">
              <Button type="submit" loading={upsertPolicy.isPending}>Save policy</Button>
            </Group>
          </Stack>
        </form>
      )}
    </Stack>
  );
}
