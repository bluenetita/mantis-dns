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

import {
  ActionIcon,
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Modal,
  NumberInput,
  Progress,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconBolt,
  IconEdit,
  IconPlus,
  IconRefresh,
  IconTrash,
  IconWifi,
} from "@tabler/icons-react";
import { useState } from "react";
import {
  type DhcpHaConfig,
  type DhcpLease,
  type DhcpLease6,
  type DhcpReservation,
  type DhcpReservation6,
  type DhcpScope,
  type DhcpScope6,
  useCreateDhcpReservation,
  useCreateDhcpReservation6,
  useCreateDhcpScope,
  useCreateDhcpScope6,
  useDeleteDhcpHaConfig,
  useDeleteDhcpReservation,
  useDeleteDhcpReservation6,
  useDeleteDhcpScope,
  useDeleteDhcpScope6,
  useDhcpHaConfig,
  useDhcpLeases,
  useDhcpLeases6,
  useDhcpPush,
  useDhcpPush6,
  useDhcpReservations,
  useDhcpReservations6,
  useDhcpScopes,
  useDhcpScopes6,
  useDhcpStats,
  useKeasStatus,
  useTenants,
  useUpdateDhcpReservation,
  useUpdateDhcpReservation6,
  useUpdateDhcpScope,
  useUpdateDhcpScope6,
  useUpsertDhcpHaConfig,
  useZones,
} from "../api/hooks";

// ── Helpers ────────────────────────────────────────────────────────────────────

const LEASE_STATE: Record<number, { label: string; color: string }> = {
  0: { label: "Active", color: "green" },
  1: { label: "Declined", color: "red" },
  2: { label: "Expired", color: "gray" },
};

function fmtExpire(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Math.round((d.getTime() - Date.now()) / 1000);
  if (diff < 0) return "expired";
  if (diff < 3600) return `${Math.round(diff / 60)}m`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h`;
  return `${Math.round(diff / 86400)}d`;
}

// ── Scope form ─────────────────────────────────────────────────────────────────

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
          <TextInput label="PXE boot filename" placeholder="pxelinux.0" {...form.getInputProps("pxe_boot_filename")} />
        </Group>
        <TextInput label="Interface (optional)" placeholder="eth0" {...form.getInputProps("interface")} />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

// ── Reservation form ───────────────────────────────────────────────────────────

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

// ── Scopes tab ─────────────────────────────────────────────────────────────────

function ScopesTab({
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
  const push = useDhcpPush();

  const [editing, setEditing] = useState<DhcpScope | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditing(null); open(); };
  const openEdit = (s: DhcpScope) => { setEditing(s); open(); };

  const save = (body: Partial<DhcpScope>) => {
    const mut = editing
      ? update.mutateAsync({ id: editing.id, body })
      : create.mutateAsync(body);
    mut
      .then((res) => {
        close();
        if (res.kea_push_error)
          notifications.show({ color: "orange", title: "Saved (Kea push failed)", message: res.kea_push_error });
        else
          notifications.show({ color: "green", message: editing ? "Scope updated" : "Scope created" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDelete = (s: DhcpScope) =>
    modals.openConfirmModal({
      title: "Delete scope",
      children: <Text size="sm">Delete <b>{s.name}</b> ({s.subnet})? This removes it from Kea immediately.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        del.mutateAsync(s.id)
          .then(() => notifications.show({ color: "green", message: "Scope deleted" }))
          .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message })),
    });

  if (isLoading) return <Center p="xl"><Loader /></Center>;

  const saving = create.isPending || update.isPending;

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>DHCP Scopes</Title>
        <Group>
          <Tooltip label="Re-push all scopes to Kea">
            <Button
              size="xs"
              variant="default"
              leftSection={<IconBolt size={14} />}
              loading={push.isPending}
              onClick={() =>
                push.mutateAsync()
                  .then((r) => r.ok
                    ? notifications.show({ color: "green", message: "Config pushed to Kea" })
                    : notifications.show({ color: "red", title: "Push failed", message: r.error ?? "" })
                  )
                  .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }))
              }
            >
              Push to Kea
            </Button>
          </Tooltip>
          <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>
            Add scope
          </Button>
        </Group>
      </Group>

      {scopes.length === 0 ? (
        <Text c="dimmed" size="sm">No scopes configured. Add one to start serving DHCP.</Text>
      ) : (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Subnet</Table.Th>
              <Table.Th>Pool</Table.Th>
              <Table.Th>Lease (s)</Table.Th>
              <Table.Th>DDNS</Table.Th>
              <Table.Th>Kea ID</Table.Th>
              <Table.Th>Enabled</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {scopes.map((s) => (
              <Table.Tr key={s.id}>
                <Table.Td fw={500}>{s.name}</Table.Td>
                <Table.Td><code>{s.subnet}</code></Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">{s.range_start} – {s.range_end}</Text>
                </Table.Td>
                <Table.Td>{s.lease_time_s.toLocaleString()}</Table.Td>
                <Table.Td>
                  {s.ddns_enabled
                    ? <Badge size="xs" color="blue">DDNS</Badge>
                    : <Text size="xs" c="dimmed">—</Text>}
                </Table.Td>
                <Table.Td>
                  {s.kea_subnet_id != null
                    ? <Text size="xs" c="dimmed">#{s.kea_subnet_id}</Text>
                    : <Text size="xs" c="dimmed">—</Text>}
                </Table.Td>
                <Table.Td>
                  <Switch
                    size="xs"
                    checked={s.enabled}
                    onChange={() =>
                      update.mutateAsync({ id: s.id, body: { enabled: !s.enabled } }).catch(() => {})
                    }
                  />
                </Table.Td>
                <Table.Td>
                  <Group gap={4} justify="flex-end">
                    <ActionIcon variant="subtle" onClick={() => openEdit(s)}><IconEdit size={14} /></ActionIcon>
                    <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(s)}><IconTrash size={14} /></ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
        opened={modalOpen}
        onClose={close}
        title={editing ? "Edit scope" : "Add scope"}
        size="lg"
      >
        <ScopeForm
          initial={editing ?? undefined}
          tenantOptions={tenantOptions}
          zoneOptions={zoneOptions}
          onSave={save}
          onCancel={close}
          saving={saving}
        />
      </Modal>
    </>
  );
}

// ── Reservations tab ───────────────────────────────────────────────────────────

function ReservationsTab({ scopeOptions }: { scopeOptions: { value: string; label: string }[] }) {
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
      ) : isLoading ? (
        <Center p="xl"><Loader /></Center>
      ) : reservations.length === 0 ? (
        <Text c="dimmed" size="sm">No reservations in this scope.</Text>
      ) : (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>MAC</Table.Th>
              <Table.Th>IP</Table.Th>
              <Table.Th>Hostname</Table.Th>
              <Table.Th>Description</Table.Th>
              <Table.Th>PXE</Table.Th>
              <Table.Th>Enabled</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {reservations.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td><code>{r.mac_address}</code></Table.Td>
                <Table.Td><code>{r.ip_address}</code></Table.Td>
                <Table.Td>{r.hostname ?? <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{r.description ?? "—"}</Text></Table.Td>
                <Table.Td>
                  {r.boot_filename
                    ? <Badge size="xs" color="grape">PXE</Badge>
                    : <Text size="xs" c="dimmed">—</Text>}
                </Table.Td>
                <Table.Td>
                  <Switch
                    size="xs"
                    checked={r.enabled}
                    onChange={() =>
                      update.mutateAsync({ id: r.id, body: { enabled: !r.enabled } }).catch(() => {})
                    }
                  />
                </Table.Td>
                <Table.Td>
                  <Group gap={4} justify="flex-end">
                    <ActionIcon variant="subtle" onClick={() => openEdit(r)}><IconEdit size={14} /></ActionIcon>
                    <ActionIcon variant="subtle" color="red" onClick={() => confirmDelete(r)}><IconTrash size={14} /></ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal
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
      </Modal>
    </>
  );
}

// ── Leases tab ─────────────────────────────────────────────────────────────────

function LeasesTab({ scopeOptions }: { scopeOptions: { value: string; label: string }[] }) {
  const [scopeId, setScopeId] = useState<string | null>(null);
  const { data: leases = [], isLoading, refetch, isFetching } = useDhcpLeases(scopeId ?? undefined);

  return (
    <>
      <Group justify="space-between" mb="md">
        <Title order={4}>Active Leases</Title>
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
          <Tooltip label="Refresh">
            <ActionIcon variant="default" size="sm" loading={isFetching} onClick={() => refetch()}>
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {!scopeId ? (
        <Text c="dimmed" size="sm">Select a scope to view active leases.</Text>
      ) : isLoading ? (
        <Center p="xl"><Loader /></Center>
      ) : leases.length === 0 ? (
        <Text c="dimmed" size="sm">No active leases. Auto-refreshes every 30 s.</Text>
      ) : (
        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>IP</Table.Th>
              <Table.Th>MAC</Table.Th>
              <Table.Th>Hostname</Table.Th>
              <Table.Th>Expires in</Table.Th>
              <Table.Th>State</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {leases.map((l: DhcpLease) => {
              const st = LEASE_STATE[l.state] ?? { label: `State ${l.state}`, color: "gray" };
              return (
                <Table.Tr key={l.ip_address}>
                  <Table.Td><code>{l.ip_address}</code></Table.Td>
                  <Table.Td><code>{l.mac_address ?? "—"}</code></Table.Td>
                  <Table.Td>{l.hostname || <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                  <Table.Td><Text size="xs">{fmtExpire(l.expire)}</Text></Table.Td>
                  <Table.Td><Badge size="xs" color={st.color}>{st.label}</Badge></Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      )}
    </>
  );
}

// ── Status tab ─────────────────────────────────────────────────────────────────

function StatusTab() {
  const { data: status, isLoading: statusLoading } = useKeasStatus();
  const { data: stats = [], isLoading: statsLoading } = useDhcpStats();

  return (
    <Stack gap="lg">
      <Card withBorder p="md">
        <Title order={5} mb="sm">Kea daemon</Title>
        {statusLoading ? (
          <Loader size="xs" />
        ) : status?.ok ? (
          <Stack gap={4}>
            <Group gap="xs">
              <Badge color="green" size="sm">Running</Badge>
              <Text size="sm" c="dimmed">{status.version ?? "version unknown"}</Text>
            </Group>
            <Text size="xs" c="dimmed">{status.url}</Text>
          </Stack>
        ) : (
          <Stack gap={4}>
            <Group gap="xs">
              <Badge color="red" size="sm">Unreachable</Badge>
              {status?.error && <Text size="xs" c="dimmed">{status.error}</Text>}
            </Group>
            {status?.url && <Text size="xs" c="dimmed">{status.url}</Text>}
          </Stack>
        )}
      </Card>

      <Card withBorder p="md">
        <Title order={5} mb="sm">Subnet utilisation</Title>
        {statsLoading ? (
          <Loader size="xs" />
        ) : stats.length === 0 ? (
          <Text c="dimmed" size="sm">No scopes or Kea not running.</Text>
        ) : (
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Scope</Table.Th>
                <Table.Th>Subnet</Table.Th>
                <Table.Th>Assigned / Total</Table.Th>
                <Table.Th>Utilisation</Table.Th>
                <Table.Th>Declined</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {stats.map((s) => {
                const pct = s.total_addresses > 0
                  ? Math.round((s.assigned_addresses / s.total_addresses) * 100)
                  : 0;
                return (
                  <Table.Tr key={s.scope_id}>
                    <Table.Td fw={500}>{s.scope_name}</Table.Td>
                    <Table.Td><code>{s.subnet}</code></Table.Td>
                    <Table.Td>{s.assigned_addresses} / {s.total_addresses}</Table.Td>
                    <Table.Td style={{ minWidth: 160 }}>
                      <Group gap="xs" align="center">
                        <Progress
                          value={pct}
                          color={pct > 85 ? "red" : pct > 60 ? "orange" : "blue"}
                          size="sm"
                          style={{ flex: 1 }}
                        />
                        <Text size="xs" w={32} ta="right">{pct}%</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      {s.declined_addresses > 0
                        ? <Badge size="xs" color="red">{s.declined_addresses}</Badge>
                        : <Text size="xs" c="dimmed">0</Text>}
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}

// ── HA tab ─────────────────────────────────────────────────────────────────────

function HaTab({ tenantOptions }: { tenantOptions: { value: string; label: string }[] }) {
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

// ── DHCPv6 tab ─────────────────────────────────────────────────────────────────

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
        <TextInput label="Interface (optional)" placeholder="eth0" {...form.getInputProps("interface")} />
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

function Dhcpv6Tab({ tenantOptions }: { tenantOptions: { value: string; label: string }[] }) {
  const [activeTab, setActiveTab] = useState<string>("scopes6");
  const [scopeId, setScopeId] = useState<string | null>(null);

  const { data: scopes6 = [], isLoading: scopesLoading } = useDhcpScopes6();
  const create6 = useCreateDhcpScope6();
  const update6 = useUpdateDhcpScope6();
  const del6 = useDeleteDhcpScope6();
  const push6 = useDhcpPush6();

  const { data: reservations6 = [], isLoading: resLoading } = useDhcpReservations6(scopeId ?? undefined);
  const createRes6 = useCreateDhcpReservation6(scopeId ?? undefined);
  const updateRes6 = useUpdateDhcpReservation6(scopeId ?? undefined);
  const delRes6 = useDeleteDhcpReservation6(scopeId ?? undefined);

  const { data: leases6 = [], isLoading: leasesLoading, refetch: refetchLeases, isFetching: leasesFetching } =
    useDhcpLeases6(scopeId ?? undefined);

  const [editingScope, setEditingScope] = useState<DhcpScope6 | null>(null);
  const [scopeModalOpen, { open: openScopeModal, close: closeScopeModal }] = useDisclosure(false);
  const [editingRes, setEditingRes] = useState<DhcpReservation6 | null>(null);
  const [resModalOpen, { open: openResModal, close: closeResModal }] = useDisclosure(false);

  const scope6Options = scopes6.map((s) => ({ value: s.id, label: `${s.name} (${s.subnet})` }));

  const saveScope = (body: Partial<DhcpScope6>) => {
    const mut = editingScope
      ? update6.mutateAsync({ id: editingScope.id, body })
      : create6.mutateAsync(body);
    mut
      .then((res) => {
        closeScopeModal();
        if (res.kea_push_error)
          notifications.show({ color: "orange", title: "Saved (push failed)", message: res.kea_push_error });
        else
          notifications.show({ color: "green", message: editingScope ? "Scope updated" : "Scope created" });
      })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDeleteScope = (s: DhcpScope6) =>
    modals.openConfirmModal({
      title: "Delete IPv6 scope",
      children: <Text size="sm">Delete <b>{s.name}</b> ({s.subnet})?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => del6.mutateAsync(s.id).catch(() => {}),
    });

  const saveRes = (body: Partial<DhcpReservation6>) => {
    const mut = editingRes
      ? updateRes6.mutateAsync({ id: editingRes.id, body })
      : createRes6.mutateAsync(body);
    mut
      .then(() => { closeResModal(); notifications.show({ color: "green", message: "Reservation saved" }); })
      .catch((e: Error) => notifications.show({ color: "red", title: "Error", message: e.message }));
  };

  const confirmDeleteRes = (r: DhcpReservation6) =>
    modals.openConfirmModal({
      title: "Delete reservation",
      children: <Text size="sm">Remove reservation for <b>{r.duid}</b>?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () => delRes6.mutateAsync(r.id).catch(() => {}),
    });

  return (
    <Stack gap="md">
      <Tabs value={activeTab} onChange={(v) => setActiveTab(v ?? "scopes6")} keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="scopes6">Scopes</Tabs.Tab>
          <Tabs.Tab value="reservations6">Reservations</Tabs.Tab>
          <Tabs.Tab value="leases6">Leases</Tabs.Tab>
        </Tabs.List>

        {/* ── IPv6 Scopes ── */}
        <Tabs.Panel value="scopes6" pt="md">
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
              <Button size="xs" leftSection={<IconPlus size={14} />}
                onClick={() => { setEditingScope(null); openScopeModal(); }}>
                Add scope
              </Button>
            </Group>
          </Group>
          {scopesLoading ? <Center p="xl"><Loader /></Center> : scopes6.length === 0 ? (
            <Text c="dimmed" size="sm">No IPv6 scopes configured.</Text>
          ) : (
            <Table striped highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Subnet</Table.Th>
                  <Table.Th>Pool</Table.Th>
                  <Table.Th>Lifetime (s)</Table.Th>
                  <Table.Th>Enabled</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {scopes6.map((s) => (
                  <Table.Tr key={s.id}>
                    <Table.Td fw={500}>{s.name}</Table.Td>
                    <Table.Td><code>{s.subnet}</code></Table.Td>
                    <Table.Td><Text size="xs" c="dimmed">{s.pool_start} –<br />{s.pool_end}</Text></Table.Td>
                    <Table.Td>{s.valid_lifetime_s.toLocaleString()}</Table.Td>
                    <Table.Td>
                      <Switch size="xs" checked={s.enabled}
                        onChange={() => update6.mutateAsync({ id: s.id, body: { enabled: !s.enabled } }).catch(() => {})} />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} justify="flex-end">
                        <ActionIcon variant="subtle" onClick={() => { setEditingScope(s); openScopeModal(); }}><IconEdit size={14} /></ActionIcon>
                        <ActionIcon variant="subtle" color="red" onClick={() => confirmDeleteScope(s)}><IconTrash size={14} /></ActionIcon>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Tabs.Panel>

        {/* ── IPv6 Reservations ── */}
        <Tabs.Panel value="reservations6" pt="md">
          <Group justify="space-between" mb="md">
            <Title order={5}>IPv6 Reservations</Title>
            <Group>
              <Select size="xs" placeholder="Select scope" data={scope6Options} value={scopeId}
                onChange={(v) => setScopeId(v ?? "")} clearable style={{ minWidth: 220 }} />
              <Button size="xs" leftSection={<IconPlus size={14} />} disabled={!scopeId}
                onClick={() => { setEditingRes(null); openResModal(); }}>
                Add
              </Button>
            </Group>
          </Group>
          {!scopeId ? <Text c="dimmed" size="sm">Select a scope.</Text>
            : resLoading ? <Center p="xl"><Loader /></Center>
            : reservations6.length === 0 ? <Text c="dimmed" size="sm">No reservations.</Text>
            : (
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>DUID</Table.Th>
                    <Table.Th>IP address</Table.Th>
                    <Table.Th>Hostname</Table.Th>
                    <Table.Th>Enabled</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {reservations6.map((r) => (
                    <Table.Tr key={r.id}>
                      <Table.Td><code style={{ fontSize: 11 }}>{r.duid}</code></Table.Td>
                      <Table.Td><code>{r.ip_address}</code></Table.Td>
                      <Table.Td>{r.hostname ?? <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                      <Table.Td>
                        <Switch size="xs" checked={r.enabled}
                          onChange={() => updateRes6.mutateAsync({ id: r.id, body: { enabled: !r.enabled } }).catch(() => {})} />
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4} justify="flex-end">
                          <ActionIcon variant="subtle" onClick={() => { setEditingRes(r); openResModal(); }}><IconEdit size={14} /></ActionIcon>
                          <ActionIcon variant="subtle" color="red" onClick={() => confirmDeleteRes(r)}><IconTrash size={14} /></ActionIcon>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
        </Tabs.Panel>

        {/* ── IPv6 Leases ── */}
        <Tabs.Panel value="leases6" pt="md">
          <Group justify="space-between" mb="md">
            <Title order={5}>Active IPv6 Leases</Title>
            <Group>
              <Select size="xs" placeholder="Select scope" data={scope6Options} value={scopeId}
                onChange={(v) => setScopeId(v ?? "")} clearable style={{ minWidth: 220 }} />
              <Tooltip label="Refresh">
                <ActionIcon variant="default" size="sm" loading={leasesFetching} onClick={() => refetchLeases()}>
                  <IconRefresh size={14} />
                </ActionIcon>
              </Tooltip>
            </Group>
          </Group>
          {!scopeId ? <Text c="dimmed" size="sm">Select a scope.</Text>
            : leasesLoading ? <Center p="xl"><Loader /></Center>
            : leases6.length === 0 ? <Text c="dimmed" size="sm">No active leases.</Text>
            : (
              <Table striped highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>IP address</Table.Th>
                    <Table.Th>DUID</Table.Th>
                    <Table.Th>Hostname</Table.Th>
                    <Table.Th>Type</Table.Th>
                    <Table.Th>Expires in</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {leases6.map((l: DhcpLease6, i) => (
                    <Table.Tr key={`${l.ip_address}-${i}`}>
                      <Table.Td><code>{l.ip_address}</code></Table.Td>
                      <Table.Td><code style={{ fontSize: 11 }}>{l.duid ?? "—"}</code></Table.Td>
                      <Table.Td>{l.hostname || <Text size="xs" c="dimmed">—</Text>}</Table.Td>
                      <Table.Td>
                        <Badge size="xs" color={l.lease_type === 2 ? "grape" : "blue"}>
                          {l.lease_type === 2 ? "IA_PD" : "IA_NA"}
                        </Badge>
                      </Table.Td>
                      <Table.Td><Text size="xs">{fmtExpire(l.expire)}</Text></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
        </Tabs.Panel>
      </Tabs>

      {/* Scope modal */}
      <Modal opened={scopeModalOpen} onClose={closeScopeModal}
        title={editingScope ? "Edit IPv6 scope" : "Add IPv6 scope"} size="lg">
        <Scope6Form
          initial={editingScope ?? undefined}
          tenantOptions={tenantOptions}
          onSave={saveScope}
          onCancel={closeScopeModal}
          saving={create6.isPending || update6.isPending}
        />
      </Modal>

      {/* Reservation modal */}
      <Modal opened={resModalOpen} onClose={closeResModal}
        title={editingRes ? "Edit reservation" : "Add IPv6 reservation"} size="md">
        <Reservation6Form
          initial={editingRes ?? undefined}
          onSave={saveRes}
          onCancel={closeResModal}
          saving={createRes6.isPending || updateRes6.isPending}
        />
      </Modal>
    </Stack>
  );
}

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

// ── Page ───────────────────────────────────────────────────────────────────────

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
          <Tabs.Tab value="ha">High Availability</Tabs.Tab>
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
        <Tabs.Panel value="ha" pt="md">
          <HaTab tenantOptions={tenantOptions} />
        </Tabs.Panel>
        <Tabs.Panel value="ipv6" pt="md">
          <Dhcpv6Tab tenantOptions={tenantOptions} />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
