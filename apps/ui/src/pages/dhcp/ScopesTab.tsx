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

import { Badge, Button, Group, NumberInput, Select, Stack, Switch, Text, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateDhcpScope,
  useDeleteDhcpScope,
  useDhcpScopes,
  useUpdateDhcpScope,
  type DhcpScope,
} from "../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../components/crud";

function ScopeForm({
  initial,
  tenantOptions,
  zoneOptions,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<DhcpScope>;
  tenantOptions: { value: string; label: string }[];
  zoneOptions: { value: string; label: string }[];
  onSave: (v: Partial<DhcpScope>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      tenant_id: initial?.tenant_id ?? "",
      name: initial?.name ?? "",
      description: initial?.description ?? "",
      subnet: initial?.subnet ?? "",
      range_start: initial?.range_start ?? "",
      range_end: initial?.range_end ?? "",
      router_ip: initial?.router_ip ?? "",
      dns_servers: (initial?.dns_servers ?? []).join(", "),
      ntp_server: initial?.ntp_server ?? "",
      domain_name: initial?.domain_name ?? "",
      interface: initial?.interface ?? "",
      lease_time_s: initial?.lease_time_s ?? 86400,
      max_lease_time_s: initial?.max_lease_time_s ?? 604800,
      ddns_enabled: initial?.ddns_enabled ?? false,
      ddns_zone_id: initial?.ddns_zone_id ?? "",
      ddns_ttl_s: initial?.ddns_ttl_s ?? 300,
      pxe_next_server: initial?.pxe_next_server ?? "",
      pxe_boot_filename: initial?.pxe_boot_filename ?? "",
      pxe_uefi_boot_filename: initial?.pxe_uefi_boot_filename ?? "",
      enabled: initial?.enabled ?? true,
    },
    validate: {
      tenant_id: (v) => (!initial?.id && !v ? "Required" : null),
      name: (v) => (!v.trim() ? "Required" : null),
      subnet: (v) => (!v.trim() ? "Required" : !/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(v.trim()) ? "Must be CIDR (e.g. 10.0.1.0/24)" : null),
      range_start: (v) => (!v.trim() ? "Required" : null),
      range_end: (v) => (!v.trim() ? "Required" : null),
    },
  });

  const submit = form.onSubmit((v) => {
    const payload: Partial<DhcpScope> = {
      ...v,
      dns_servers: v.dns_servers.split(",").map((s) => s.trim()).filter(Boolean),
      router_ip: v.router_ip || null,
      ntp_server: v.ntp_server || null,
      domain_name: v.domain_name || null,
      interface: v.interface || null,
      description: v.description || null,
      pxe_next_server: v.pxe_next_server || null,
      pxe_boot_filename: v.pxe_boot_filename || null,
      pxe_uefi_boot_filename: v.pxe_uefi_boot_filename || null,
      ddns_zone_id: v.ddns_zone_id || null,
    };
    if (!initial?.id) payload.tenant_id = v.tenant_id;
    onSave(payload);
  });

  return (
    <form onSubmit={submit}>
      <Stack gap="sm">
        {!initial?.id && (
          <Select
            label="Tenant"
            data={tenantOptions}
            required
            searchable
            {...form.getInputProps("tenant_id")}
          />
        )}
        <TextInput label="Name" required {...form.getInputProps("name")} />
        <TextInput label="Description" {...form.getInputProps("description")} />
        <TextInput label="Subnet (CIDR)" placeholder="10.8.1.0/24" required {...form.getInputProps("subnet")} />
        <Group grow>
          <TextInput label="Pool start" placeholder="10.8.1.10" required {...form.getInputProps("range_start")} />
          <TextInput label="Pool end" placeholder="10.8.1.200" required {...form.getInputProps("range_end")} />
        </Group>
        <TextInput label="Router (option 3)" placeholder="10.8.1.1" {...form.getInputProps("router_ip")} />
        <TextInput
          label="DNS servers (option 6)"
          placeholder="10.0.0.1, 8.8.8.8"
          description="Comma-separated; empty = Mantis filter node"
          {...form.getInputProps("dns_servers")}
        />
        <Group grow>
          <TextInput label="NTP server (option 42)" {...form.getInputProps("ntp_server")} />
          <TextInput label="Domain name (option 15)" {...form.getInputProps("domain_name")} />
        </Group>
        <Group grow>
          <NumberInput label="Lease time (s)" min={60} {...form.getInputProps("lease_time_s")} />
          <NumberInput label="Max lease time (s)" min={60} {...form.getInputProps("max_lease_time_s")} />
        </Group>
        <Switch label="DDNS — push A records to DNS zone" {...form.getInputProps("ddns_enabled", { type: "checkbox" })} />
        {form.values.ddns_enabled && (
          <Group grow>
            <Select
              label="DDNS zone"
              data={zoneOptions}
              clearable
              {...form.getInputProps("ddns_zone_id")}
            />
            <NumberInput label="DDNS TTL (s)" min={30} {...form.getInputProps("ddns_ttl_s")} />
          </Group>
        )}
        <Group grow>
          <TextInput label="PXE next-server (siaddr)" placeholder="192.168.1.10" {...form.getInputProps("pxe_next_server")} />
          <TextInput label="PXE boot filename (BIOS)" placeholder="pxelinux.0" {...form.getInputProps("pxe_boot_filename")} />
          <TextInput
            label="PXE boot filename (UEFI)"
            placeholder="shimx64.efi"
            description="Used when the client's arch option (93) is UEFI"
            {...form.getInputProps("pxe_uefi_boot_filename")}
          />
        </Group>
        <TextInput
          label="Interface (optional)"
          placeholder="eth0 — empty serves all interfaces"
          {...form.getInputProps("interface")}
        />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

export function ScopesTab({
  tenantOptions,
  zoneOptions,
}: {
  tenantOptions: { value: string; label: string }[];
  zoneOptions: { value: string; label: string }[];
}) {
  const { data: scopes = [], isLoading } = useDhcpScopes();
  const create = useCreateDhcpScope();
  const update = useUpdateDhcpScope();
  const del = useDeleteDhcpScope();

  const [editing, setEditing] = useState<DhcpScope | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditing(null); open(); };
  const openEdit = (s: DhcpScope) => { setEditing(s); open(); };

  const save = (body: Partial<DhcpScope>) => {
    const mut = editing
      ? update.mutateAsync({ id: editing.id, body })
      : create.mutateAsync(body);
    mut
      .then(() => {
        close();
        notifications.show({ color: "green", message: editing ? "Scope updated" : "Scope created" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDelete = (s: DhcpScope) =>
    modals.openConfirmModal({
      title: "Delete scope",
      children: <Text size="sm">Delete <b>{s.name}</b> ({s.subnet})? mantis-dhcp stops serving it immediately.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        del.mutateAsync(s.id)
          .then(() => notifications.show({ color: "green", message: "Scope deleted" }))
          .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message })),
    });

  const saving = create.isPending || update.isPending;

  const columns: CrudColumn<DhcpScope>[] = [
    { key: "name", header: "Name", render: (s) => <Text fw={500}>{s.name}</Text> },
    { key: "subnet", header: "Subnet", render: (s) => <code>{s.subnet}</code> },
    {
      key: "pool",
      header: "Pool",
      render: (s) => <Text size="xs" c="dimmed">{s.range_start} – {s.range_end}</Text>,
    },
    { key: "lease", header: "Lease (s)", render: (s) => s.lease_time_s.toLocaleString() },
    {
      key: "ddns",
      header: "DDNS",
      render: (s) => (s.ddns_enabled ? <Badge size="xs" color="blue">DDNS</Badge> : <Text size="xs" c="dimmed">—</Text>),
    },
    {
      key: "enabled",
      header: "Enabled",
      render: (s) => (
        <Switch
          size="xs"
          checked={s.enabled}
          onChange={() => update.mutateAsync({ id: s.id, body: { enabled: !s.enabled } }).catch(() => {})}
        />
      ),
    },
  ];

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>DHCP Scopes</Title>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>
          Add scope
        </Button>
      </Group>

      <CrudTable
        data={scopes}
        isLoading={isLoading}
        getRowKey={(s) => s.id}
        columns={columns}
        onEdit={openEdit}
        onDelete={confirmDelete}
        emptyState={<Text c="dimmed" size="sm">No scopes configured. Add one to start serving DHCP.</Text>}
      />

      <EntityModal opened={modalOpen} onClose={close} title={editing ? "Edit scope" : "Add scope"} size="lg">
        <ScopeForm
          initial={editing ?? undefined}
          tenantOptions={tenantOptions}
          zoneOptions={zoneOptions}
          onSave={save}
          onCancel={close}
          saving={saving}
        />
      </EntityModal>
    </>
  );
}
