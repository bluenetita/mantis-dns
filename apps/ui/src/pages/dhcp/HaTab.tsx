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

import { Button, Card, Center, Group, Loader, NumberInput, Select, Stack, Switch, Text, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import {
  useDeleteDhcpHaConfig,
  useDhcpHaConfig,
  useUpsertDhcpHaConfig,
  type DhcpHaConfig,
} from "../../api/hooks";

export function HaTab({ tenantOptions }: { tenantOptions: { value: string; label: string }[] }) {
  const [tenantId, setTenantId] = useState<string | null>(null);
  const { data: ha, isLoading, error } = useDhcpHaConfig(tenantId ?? undefined);
  const upsert = useUpsertDhcpHaConfig(tenantId ?? undefined);
  const del = useDeleteDhcpHaConfig(tenantId ?? undefined);

  const form = useForm<Omit<DhcpHaConfig, "id" | "tenant_id" | "created_at" | "updated_at" | "kea_push_error">>({
    initialValues: {
      enabled: false,
      mode: "hot-standby",
      this_server_name: "primary",
      this_server_url: "http://kea:8004/",
      peer_name: "secondary",
      peer_url: "http://kea-secondary:8004/",
      peer_role: "standby",
      max_unacked_clients: 10,
      max_ack_delay_ms: 10000,
      heartbeat_delay_ms: 10000,
      retry_wait_time_ms: 5000,
    },
  });

  const loadHa = (data: DhcpHaConfig) => {
    form.setValues({
      enabled: data.enabled,
      mode: data.mode,
      this_server_name: data.this_server_name,
      this_server_url: data.this_server_url,
      peer_name: data.peer_name,
      peer_url: data.peer_url,
      peer_role: data.peer_role,
      max_unacked_clients: data.max_unacked_clients,
      max_ack_delay_ms: data.max_ack_delay_ms,
      heartbeat_delay_ms: data.heartbeat_delay_ms,
      retry_wait_time_ms: data.retry_wait_time_ms,
    });
  };

  // Sync form when ha data arrives
  const [synced, setSynced] = useState(false);
  if (ha && !synced) { loadHa(ha); setSynced(true); }
  if (!ha && synced) setSynced(false);

  const submit = form.onSubmit((v) =>
    upsert.mutateAsync(v)
      .then((res) => {
        loadHa(res);
        if (res.kea_push_error)
          notifications.show({ color: "orange", title: "Saved (Kea push failed)", message: res.kea_push_error });
        else
          notifications.show({ color: "green", message: "HA config saved and pushed" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }))
  );

  const confirmDelete = () =>
    modals.openConfirmModal({
      title: "Delete HA config",
      children: <Text size="sm">Remove HA configuration? Kea will be re-pushed without HA hooks.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        del.mutateAsync()
          .then(() => { setSynced(false); form.reset(); notifications.show({ color: "green", message: "HA config deleted" }); })
          .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message })),
    });

  return (
    <Stack gap="md">
      <Group justify="space-between" mb="xs">
        <Title order={4}>High Availability (Kea HA)</Title>
        <Select
          size="xs"
          placeholder="Select tenant"
          data={tenantOptions}
          value={tenantId}
          onChange={(v) => { setTenantId(v); setSynced(false); form.reset(); }}
          clearable
          style={{ minWidth: 220 }}
        />
      </Group>

      {!tenantId ? (
        <Text c="dimmed" size="sm">Select a tenant to configure HA.</Text>
      ) : isLoading ? (
        <Center p="xl"><Loader /></Center>
      ) : (
        <>
          {error && !ha && (
            <Text size="sm" c="dimmed">No HA config yet — fill the form below to create one.</Text>
          )}
          <Card withBorder p="md">
            <form onSubmit={submit}>
              <Stack gap="sm">
                <Switch label="Enable HA" {...form.getInputProps("enabled", { type: "checkbox" })} />
                <Select
                  label="Mode"
                  data={[
                    { value: "hot-standby", label: "Hot standby (active/passive)" },
                    { value: "load-balancing", label: "Load balancing (active/active)" },
                  ]}
                  {...form.getInputProps("mode")}
                />
                <Title order={6} mt="xs">This server</Title>
                <Group grow>
                  <TextInput label="Name" {...form.getInputProps("this_server_name")} />
                  <TextInput label="Kea management URL" {...form.getInputProps("this_server_url")} />
                </Group>
                <Title order={6} mt="xs">Peer server</Title>
                <Group grow>
                  <TextInput label="Name" {...form.getInputProps("peer_name")} />
                  <TextInput label="Kea management URL" {...form.getInputProps("peer_url")} />
                  <Select
                    label="Role"
                    data={[
                      { value: "standby", label: "Standby" },
                      { value: "primary", label: "Primary" },
                    ]}
                    {...form.getInputProps("peer_role")}
                  />
                </Group>
                <Title order={6} mt="xs">Thresholds</Title>
                <Group grow>
                  <NumberInput label="Heartbeat delay (ms)" min={1000} {...form.getInputProps("heartbeat_delay_ms")} />
                  <NumberInput label="Max ACK delay (ms)" min={1000} {...form.getInputProps("max_ack_delay_ms")} />
                  <NumberInput label="Max unacked clients" min={0} {...form.getInputProps("max_unacked_clients")} />
                  <NumberInput label="Retry wait (ms)" min={1000} {...form.getInputProps("retry_wait_time_ms")} />
                </Group>
                <Group justify="flex-end" mt="sm">
                  {ha && (
                    <Button variant="default" color="red" onClick={confirmDelete} leftSection={<IconTrash size={14} />}>
                      Delete
                    </Button>
                  )}
                  <Button type="submit" loading={upsert.isPending}>
                    {ha ? "Update & push" : "Create & push"}
                  </Button>
                </Group>
              </Stack>
            </form>
          </Card>
        </>
      )}
    </Stack>
  );
}
