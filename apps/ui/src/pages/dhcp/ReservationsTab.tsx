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

import { Badge, Button, Group, Select, Stack, Switch, Text, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateDhcpReservation,
  useDeleteDhcpReservation,
  useDhcpReservations,
  useUpdateDhcpReservation,
  type DhcpReservation,
} from "../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../components/crud";

function ReservationForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<DhcpReservation>;
  onSave: (v: Partial<DhcpReservation>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      mac_address: initial?.mac_address ?? "",
      ip_address: initial?.ip_address ?? "",
      hostname: initial?.hostname ?? "",
      description: initial?.description ?? "",
      client_id: initial?.client_id ?? "",
      next_server: initial?.next_server ?? "",
      boot_filename: initial?.boot_filename ?? "",
      enabled: initial?.enabled ?? true,
    },
    validate: {
      mac_address: (v) =>
        !v.trim()
          ? "Required"
          : !/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v.trim())
          ? "Format: aa:bb:cc:dd:ee:ff"
          : null,
      ip_address: (v) => (!v.trim() ? "Required" : null),
    },
  });

  const submit = form.onSubmit((v) =>
    onSave({
      ...v,
      hostname: v.hostname || null,
      description: v.description || null,
      client_id: v.client_id || null,
      next_server: v.next_server || null,
      boot_filename: v.boot_filename || null,
    })
  );

  return (
    <form onSubmit={submit}>
      <Stack gap="sm">
        <Group grow>
          <TextInput label="MAC address" placeholder="aa:bb:cc:dd:ee:ff" required {...form.getInputProps("mac_address")} />
          <TextInput label="IP address" placeholder="10.8.1.50" required {...form.getInputProps("ip_address")} />
        </Group>
        <TextInput label="Hostname" placeholder="mydevice" {...form.getInputProps("hostname")} />
        <TextInput label="Description" {...form.getInputProps("description")} />
        <TextInput label="Client ID (hex)" {...form.getInputProps("client_id")} />
        <Group grow>
          <TextInput label="PXE next-server" {...form.getInputProps("next_server")} />
          <TextInput label="PXE boot file" {...form.getInputProps("boot_filename")} />
        </Group>
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

export function ReservationsTab({ scopeOptions }: { scopeOptions: { value: string; label: string }[] }) {
  const [scopeId, setScopeId] = useState<string | null>(null);
  const { data: reservations = [], isLoading } = useDhcpReservations(scopeId ?? undefined);
  const create = useCreateDhcpReservation(scopeId ?? undefined);
  const update = useUpdateDhcpReservation(scopeId ?? undefined);
  const del = useDeleteDhcpReservation(scopeId ?? undefined);

  const [editing, setEditing] = useState<DhcpReservation | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditing(null); open(); };
  const openEdit = (r: DhcpReservation) => { setEditing(r); open(); };

  const save = (body: Partial<DhcpReservation>) => {
    const mut = editing
      ? update.mutateAsync({ id: editing.id, body })
      : create.mutateAsync(body);
    mut
      .then((res) => {
        close();
        if (res.kea_push_error)
          notifications.show({ color: "orange", title: "Saved (Kea push failed)", message: res.kea_push_error });
        else
          notifications.show({ color: "green", message: editing ? "Reservation updated" : "Reservation created" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDelete = (r: DhcpReservation) =>
    modals.openConfirmModal({
      title: "Delete reservation",
      children: <Text size="sm">Remove reservation for <b>{r.mac_address}</b> → {r.ip_address}?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        del.mutateAsync(r.id)
          .then(() => notifications.show({ color: "green", message: "Reservation deleted" }))
          .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message })),
    });

  const saving = create.isPending || update.isPending;

  const columns: CrudColumn<DhcpReservation>[] = [
    { key: "mac", header: "MAC", render: (r) => <code>{r.mac_address}</code> },
    { key: "ip", header: "IP", render: (r) => <code>{r.ip_address}</code> },
    { key: "hostname", header: "Hostname", render: (r) => r.hostname ?? <Text size="xs" c="dimmed">—</Text> },
    {
      key: "description",
      header: "Description",
      render: (r) => <Text size="xs" c="dimmed">{r.description ?? "—"}</Text>,
    },
    {
      key: "pxe",
      header: "PXE",
      render: (r) => (r.boot_filename ? <Badge size="xs" color="grape">PXE</Badge> : <Text size="xs" c="dimmed">—</Text>),
    },
    {
      key: "enabled",
      header: "Enabled",
      render: (r) => (
        <Switch
          size="xs"
          checked={r.enabled}
          onChange={() => update.mutateAsync({ id: r.id, body: { enabled: !r.enabled } }).catch(() => {})}
        />
      ),
    },
  ];

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>Host Reservations</Title>
        <Group>
          <Select
            size="xs"
            placeholder="Select scope"
            data={scopeOptions}
            value={scopeId}
            onChange={(v) => setScopeId(v ?? "")}
            clearable
            style={{ minWidth: 220 }}
          />
          <Button
            size="xs"
            leftSection={<IconPlus size={14} />}
            disabled={!scopeId}
            onClick={openCreate}
          >
            Add reservation
          </Button>
        </Group>
      </Group>

      {!scopeId ? (
        <Text c="dimmed" size="sm">Select a scope to view reservations.</Text>
      ) : (
        <CrudTable
          data={reservations}
          isLoading={isLoading}
          getRowKey={(r) => r.id}
          columns={columns}
          onEdit={openEdit}
          onDelete={confirmDelete}
          emptyState={<Text c="dimmed" size="sm">No reservations in this scope.</Text>}
        />
      )}

      <EntityModal
        opened={modalOpen}
        onClose={close}
        title={editing ? "Edit reservation" : "Add reservation"}
        size="md"
      >
        <ReservationForm
          initial={editing ?? undefined}
          onSave={save}
          onCancel={close}
          saving={saving}
        />
      </EntityModal>
    </>
  );
}
