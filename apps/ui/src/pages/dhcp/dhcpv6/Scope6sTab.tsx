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

import { ActionIcon, Button, Group, NumberInput, Select, Stack, Switch, Text, TextInput, Title, Tooltip } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconBolt, IconPlus, IconRefresh } from "@tabler/icons-react";
import { useMemo, useState } from "react";
import {
  useCreateDhcpScope6,
  useDeleteDhcpScope6,
  useDhcpPush6,
  useDhcpScopes6,
  useKeaInterfaces6,
  useUpdateDhcpScope6,
  type DhcpScope6,
} from "../../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../../components/crud";

function Scope6Form({
  initial,
  tenantOptions,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<DhcpScope6>;
  tenantOptions: { value: string; label: string }[];
  onSave: (v: Partial<DhcpScope6>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      tenant_id: initial?.tenant_id ?? "",
      name: initial?.name ?? "",
      description: initial?.description ?? "",
      subnet: initial?.subnet ?? "",
      pool_start: initial?.pool_start ?? "",
      pool_end: initial?.pool_end ?? "",
      pd_prefix: initial?.pd_prefix ?? "",
      pd_prefix_len: initial?.pd_prefix_len ?? null as number | null,
      dns_servers: (initial?.dns_servers ?? []).join(", "),
      domain_name: initial?.domain_name ?? "",
      interface: initial?.interface ?? "",
      preferred_lifetime_s: initial?.preferred_lifetime_s ?? 3000,
      valid_lifetime_s: initial?.valid_lifetime_s ?? 4000,
      ddns_enabled: initial?.ddns_enabled ?? false,
      enabled: initial?.enabled ?? true,
    },
    validate: {
      tenant_id: (v) => (!initial?.id && !v ? "Required" : null),
      name: (v) => (!v.trim() ? "Required" : null),
      subnet: (v) => (!v.trim() ? "Required" : null),
      pool_start: (v) => (!v.trim() ? "Required" : null),
      pool_end: (v) => (!v.trim() ? "Required" : null),
    },
  });

  const submit = form.onSubmit((v) =>
    onSave({
      ...v,
      dns_servers: v.dns_servers.split(",").map((s) => s.trim()).filter(Boolean),
      pd_prefix: v.pd_prefix || null,
      domain_name: v.domain_name || null,
      interface: v.interface || null,
      description: v.description || null,
    })
  );

  const { data: ifaceData, isFetching: interfacesFetching, refetch: refetchInterfaces } = useKeaInterfaces6();
  const interfaceOptions = useMemo(() => {
    const opts = (ifaceData?.interfaces ?? []).map((i) => ({
      value: i.name,
      label: `${i.name}${i.addresses.length ? ` - ${i.addresses.join(", ")}` : ""} - ${i.up ? "up" : "down"}`,
      disabled: !i.up && i.name !== initial?.interface,
    }));
    if (initial?.interface && !opts.some((o) => o.value === initial.interface)) {
      opts.push({ value: initial.interface, label: `${initial.interface} (not currently detected)`, disabled: false });
    }
    return opts;
  }, [ifaceData, initial?.interface]);
  const refreshInterfaces = () => {
    void refetchInterfaces();
  };

  return (
    <form onSubmit={submit}>
      <Stack gap="sm">
        {!initial?.id && (
          <Select label="Tenant" data={tenantOptions} required searchable {...form.getInputProps("tenant_id")} />
        )}
        <TextInput label="Name" required {...form.getInputProps("name")} />
        <TextInput label="Description" {...form.getInputProps("description")} />
        <TextInput label="Subnet (CIDR)" placeholder="2001:db8::/48" required {...form.getInputProps("subnet")} />
        <Group grow>
          <TextInput label="Pool start" placeholder="2001:db8::1000" required {...form.getInputProps("pool_start")} />
          <TextInput label="Pool end" placeholder="2001:db8::2000" required {...form.getInputProps("pool_end")} />
        </Group>
        <Group grow>
          <TextInput label="PD prefix (optional)" placeholder="2001:db8:1::/48" {...form.getInputProps("pd_prefix")} />
          <NumberInput label="Delegated prefix len" min={1} max={128} {...form.getInputProps("pd_prefix_len")} />
        </Group>
        <TextInput label="DNS servers" placeholder="2001:4860:4860::8888" {...form.getInputProps("dns_servers")} />
        <TextInput label="Domain name" {...form.getInputProps("domain_name")} />
        <Group align="flex-end" gap="xs" wrap="nowrap">
          {ifaceData?.ok ? (
            <Select
              label="Interface (optional)"
              placeholder={interfaceOptions.length > 0 ? "Select interface" : "No interfaces detected"}
              description={interfaceOptions.length > 0 ? "Interfaces visible to Kea" : "Kea is reachable but returned no interfaces"}
              data={interfaceOptions}
              searchable
              clearable
              nothingFoundMessage="No interfaces detected"
              inputWrapperOrder={["label", "input", "description", "error"]}
              style={{ flex: 1 }}
              {...form.getInputProps("interface")}
            />
          ) : (
            <TextInput
              label="Interface (optional)"
              placeholder="eth0"
              description={ifaceData && !ifaceData.ok ? "Couldn't reach Kea to list interfaces — enter manually." : undefined}
              inputWrapperOrder={["label", "input", "description", "error"]}
              style={{ flex: 1 }}
              {...form.getInputProps("interface")}
            />
          )}
          <Tooltip label="Refresh Kea interfaces">
            <ActionIcon
              aria-label="Refresh Kea interfaces"
              variant="default"
              size="lg"
              loading={interfacesFetching}
              onClick={refreshInterfaces}
            >
              <IconRefresh size={16} />
            </ActionIcon>
          </Tooltip>
        </Group>
        <Group grow>
          <NumberInput label="Preferred lifetime (s)" min={60} {...form.getInputProps("preferred_lifetime_s")} />
          <NumberInput label="Valid lifetime (s)" min={60} {...form.getInputProps("valid_lifetime_s")} />
        </Group>
        <Switch label="DDNS" {...form.getInputProps("ddns_enabled", { type: "checkbox" })} />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

export function Scope6sTab({ tenantOptions }: { tenantOptions: { value: string; label: string }[] }) {
  const { data: scopes6 = [], isLoading } = useDhcpScopes6();
  const create6 = useCreateDhcpScope6();
  const update6 = useUpdateDhcpScope6();
  const del6 = useDeleteDhcpScope6();
  const push6 = useDhcpPush6();

  const [editing, setEditing] = useState<DhcpScope6 | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditing(null); open(); };
  const openEdit = (s: DhcpScope6) => { setEditing(s); open(); };

  const save = (body: Partial<DhcpScope6>) => {
    const mut = editing
      ? update6.mutateAsync({ id: editing.id, body })
      : create6.mutateAsync(body);
    mut
      .then((res) => {
        close();
        if (res.kea_push_error)
          notifications.show({ color: "orange", title: "Saved (push failed)", message: res.kea_push_error });
        else
          notifications.show({ color: "green", message: editing ? "Scope updated" : "Scope created" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDelete = (s: DhcpScope6) =>
    modals.openConfirmModal({
      title: "Delete IPv6 scope",
      children: <Text size="sm">Delete <b>{s.name}</b> ({s.subnet})?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => del6.mutateAsync(s.id).catch(() => {}),
    });

  const columns: CrudColumn<DhcpScope6>[] = [
    { key: "name", header: "Name", render: (s) => <Text fw={500}>{s.name}</Text> },
    { key: "subnet", header: "Subnet", render: (s) => <code>{s.subnet}</code> },
    {
      key: "pool",
      header: "Pool",
      render: (s) => <Text size="xs" c="dimmed">{s.pool_start} –<br />{s.pool_end}</Text>,
    },
    { key: "lifetime", header: "Lifetime (s)", render: (s) => s.valid_lifetime_s.toLocaleString() },
    {
      key: "enabled",
      header: "Enabled",
      render: (s) => (
        <Switch
          size="xs"
          checked={s.enabled}
          onChange={() => update6.mutateAsync({ id: s.id, body: { enabled: !s.enabled } }).catch(() => {})}
        />
      ),
    },
  ];

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={5}>IPv6 Scopes</Title>
        <Group>
          <Button size="xs" variant="default" leftSection={<IconBolt size={14} />}
            loading={push6.isPending}
            onClick={() => push6.mutateAsync()
              .then((r) => r.ok
                ? notifications.show({ color: "green", message: "DHCPv6 config pushed" })
                : notifications.show({ color: "red", title: "Push failed", message: r.error ?? "" })
              ).catch(() => {})}
          >
            Push to Kea
          </Button>
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>
            Add scope
          </Button>
        </Group>
      </Group>

      <CrudTable
        data={scopes6}
        isLoading={isLoading}
        getRowKey={(s) => s.id}
        columns={columns}
        onEdit={openEdit}
        onDelete={confirmDelete}
        emptyState={<Text c="dimmed" size="sm">No IPv6 scopes configured.</Text>}
      />

      <EntityModal opened={modalOpen} onClose={close} title={editing ? "Edit IPv6 scope" : "Add IPv6 scope"} size="lg">
        <Scope6Form
          initial={editing ?? undefined}
          tenantOptions={tenantOptions}
          onSave={save}
          onCancel={close}
          saving={create6.isPending || update6.isPending}
        />
      </EntityModal>
    </>
  );
}
