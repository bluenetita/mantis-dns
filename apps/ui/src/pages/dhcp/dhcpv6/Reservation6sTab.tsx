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

import { Button, Group, Select, Stack, Switch, Text, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateDhcpReservation6,
  useDeleteDhcpReservation6,
  useDhcpReservations6,
  useUpdateDhcpReservation6,
  type DhcpReservation6,
} from "../../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../../components/crud";

function Reservation6Form({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<DhcpReservation6>;
  onSave: (v: Partial<DhcpReservation6>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      duid: initial?.duid ?? "",
      ip_address: initial?.ip_address ?? "",
      hostname: initial?.hostname ?? "",
      description: initial?.description ?? "",
      enabled: initial?.enabled ?? true,
    },
    validate: {
      duid: (v) => (!v.trim() ? "Required" : null),
      ip_address: (v) => (!v.trim() ? "Required" : null),
    },
  });

  const submit = form.onSubmit((v) =>
    onSave({ ...v, hostname: v.hostname || null, description: v.description || null })
  );

  return (
    <form onSubmit={submit}>
      <Stack gap="sm">
        <TextInput label="DUID (hex)" placeholder="00:03:00:01:aa:bb:cc:dd:ee:ff" required {...form.getInputProps("duid")} />
        <TextInput label="IPv6 address" placeholder="2001:db8::1" required {...form.getInputProps("ip_address")} />
        <TextInput label="Hostname" {...form.getInputProps("hostname")} />
        <TextInput label="Description" {...form.getInputProps("description")} />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

export function Reservation6sTab({
  scopeOptions,
  scopeId,
  onScopeChange,
}: {
  scopeOptions: { value: string; label: string }[];
  scopeId: string | null;
  onScopeChange: (scopeId: string | null) => void;
}) {
  const { data: reservations6 = [], isLoading } = useDhcpReservations6(scopeId ?? undefined);
  const createRes6 = useCreateDhcpReservation6(scopeId ?? undefined);
  const updateRes6 = useUpdateDhcpReservation6(scopeId ?? undefined);
  const delRes6 = useDeleteDhcpReservation6(scopeId ?? undefined);

  const [editing, setEditing] = useState<DhcpReservation6 | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditing(null); open(); };
  const openEdit = (r: DhcpReservation6) => { setEditing(r); open(); };

  const save = (body: Partial<DhcpReservation6>) => {
    const mut = editing
      ? updateRes6.mutateAsync({ id: editing.id, body })
      : createRes6.mutateAsync(body);
    mut
      .then(() => { close(); notifications.show({ color: "green", message: "Reservation saved" }); })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDelete = (r: DhcpReservation6) =>
    modals.openConfirmModal({
      title: "Delete reservation",
      children: <Text size="sm">Remove reservation for <b>{r.duid}</b>?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => delRes6.mutateAsync(r.id).catch(() => {}),
    });

  const columns: CrudColumn<DhcpReservation6>[] = [
    { key: "duid", header: "DUID", render: (r) => <code style={{ fontSize: 11 }}>{r.duid}</code> },
    { key: "ip", header: "IP address", render: (r) => <code>{r.ip_address}</code> },
    { key: "hostname", header: "Hostname", render: (r) => r.hostname ?? <Text size="xs" c="dimmed">—</Text> },
    {
      key: "enabled",
      header: "Enabled",
      render: (r) => (
        <Switch
          size="xs"
          checked={r.enabled}
          onChange={() => updateRes6.mutateAsync({ id: r.id, body: { enabled: !r.enabled } }).catch(() => {})}
        />
      ),
    },
  ];

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={5}>IPv6 Reservations</Title>
        <Group>
          <Select size="xs" placeholder="Select scope" data={scopeOptions} value={scopeId}
            onChange={(v) => onScopeChange(v ?? "")} clearable style={{ minWidth: 220 }} />
          <Button size="xs" leftSection={<IconPlus size={14} />} disabled={!scopeId} onClick={openCreate}>
            Add
          </Button>
        </Group>
      </Group>

      {!scopeId ? (
        <Text c="dimmed" size="sm">Select a scope.</Text>
      ) : (
        <CrudTable
          data={reservations6}
          isLoading={isLoading}
          getRowKey={(r) => r.id}
          columns={columns}
          onEdit={openEdit}
          onDelete={confirmDelete}
          emptyState={<Text c="dimmed" size="sm">No reservations.</Text>}
        />
      )}

      <EntityModal opened={modalOpen} onClose={close} title={editing ? "Edit reservation" : "Add IPv6 reservation"} size="md">
        <Reservation6Form
          initial={editing ?? undefined}
          onSave={save}
          onCancel={close}
          saving={createRes6.isPending || updateRes6.isPending}
        />
      </EntityModal>
    </>
  );
}
