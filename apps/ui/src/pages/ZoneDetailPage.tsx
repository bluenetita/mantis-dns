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
  Anchor,
  Badge,
  Breadcrumbs,
  Button,
  Group,
  Loader,
  Modal,
  NumberInput,
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
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconCircleFilled,
  IconDownload,
  IconEdit,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  useCreateRecord,
  useDeleteRecord,
  useDeleteZone,
  useRecords,
  useUpdateRecord,
  useUpdateZone,
  useZone,
} from "../api/hooks";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type Zone = components["schemas"]["ZoneOut"];
type DnsRecord = components["schemas"]["RecordOut"];

// ─── helpers ─────────────────────────────────────────────────────────────────

const ZONE_TYPE_META: Record<string, { color: string; label: string }> = {
  local:       { color: "blue",   label: "Local" },
  forward:     { color: "violet", label: "Forward" },
  passthrough: { color: "teal",   label: "Passthrough" },
};

function typeMeta(t: string) {
  return ZONE_TYPE_META[t] ?? { color: "gray", label: t };
}

const RECORD_TYPE_OPTIONS = [
  "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA",
].map((t) => ({ value: t, label: t }));

const RECORD_TYPE_COLOR: Record<string, string> = {
  A: "blue", AAAA: "indigo", CNAME: "cyan", MX: "violet",
  TXT: "gray", NS: "teal", PTR: "orange", SRV: "pink", CAA: "red",
};

function hasPriority(type: string) {
  return type === "MX" || type === "SRV";
}

// ─── Add / Edit record modal ──────────────────────────────────────────────────

interface RecordModalProps {
  zoneId: string;
  record: DnsRecord | null;
  onClose: () => void;
}

function RecordModal({ zoneId, record, onClose }: RecordModalProps) {
  const createRecord = useCreateRecord(zoneId);
  const updateRecord = useUpdateRecord(zoneId);
  const isEdit = !!record;

  const form = useForm({
    initialValues: {
      name:        record?.name        ?? "@",
      record_type: record?.record_type ?? "A",
      data:        record?.data        ?? "",
      ttl:         record?.ttl         ?? (null as number | null),
      priority:    record?.priority    ?? (null as number | null),
      enabled:     record?.enabled     ?? true,
    },
    validate: {
      name: (v) => (v.trim().length < 1 ? "Name is required" : null),
      data: (v) => (v.trim().length < 1 ? "Data is required" : null),
    },
  });

  const showPriority = hasPriority(form.values.record_type);

  function handleClose() {
    form.reset();
    onClose();
  }

  function handleSubmit(values: typeof form.values) {
    const body = {
      ...values,
      ttl:      values.ttl      ?? null,
      priority: showPriority ? (values.priority ?? null) : null,
    };

    if (isEdit) {
      updateRecord.mutate(
        { recordId: record.id, body },
        {
          onSuccess: () => { notifications.show({ message: "Record updated", color: "green" }); handleClose(); },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }
      );
    } else {
      createRecord.mutate(body, {
        onSuccess: () => { notifications.show({ message: "Record added", color: "green" }); handleClose(); },
        onError: (e) => notifications.show({ message: String(e), color: "red" }),
      });
    }
  }

  return (
    <Modal
      opened={true}
      onClose={handleClose}
      title={isEdit ? `Edit record: ${record.name} ${record.record_type}` : "Add DNS record"}
      size="lg"
    >
      <form onSubmit={form.onSubmit(handleSubmit)}>
        <Stack>
          <Group grow>
            <TextInput
              label="Name"
              placeholder="@ / www / mail"
              description='Use "@" for zone apex'
              required
              {...form.getInputProps("name")}
            />
            <Select
              label="Type"
              data={RECORD_TYPE_OPTIONS}
              required
              {...form.getInputProps("record_type")}
            />
          </Group>

          <TextInput
            label="Data"
            placeholder={
              form.values.record_type === "A"     ? "10.0.0.1" :
              form.values.record_type === "AAAA"  ? "2001:db8::1" :
              form.values.record_type === "CNAME" ? "target.example.com." :
              form.values.record_type === "MX"    ? "mail.corp.local." :
              form.values.record_type === "TXT"   ? "v=spf1 include:example.com ~all" :
              "value"
            }
            required
            {...form.getInputProps("data")}
          />

          <Group grow>
            {showPriority && (
              <NumberInput
                label="Priority"
                description="Lower value = higher priority"
                min={0}
                max={65535}
                placeholder="10"
                {...form.getInputProps("priority")}
              />
            )}
            <NumberInput
              label="TTL (seconds)"
              description="Leave blank to inherit zone default"
              min={0}
              placeholder="(zone default)"
              {...form.getInputProps("ttl")}
            />
            <Switch label="Enabled" mt="xl" {...form.getInputProps("enabled", { type: "checkbox" })} />
          </Group>

          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={createRecord.isPending || updateRecord.isPending}>
              {isEdit ? "Save changes" : "Add record"}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Records tab ──────────────────────────────────────────────────────────────

function RecordsTab({ zone, canWrite }: { zone: Zone; canWrite: boolean }) {
  const { data: records = [], isLoading } = useRecords(zone.id);
  const deleteRecord = useDeleteRecord(zone.id);
  const [showModal, setShowModal] = useState(false);
  const [editRecord, setEditRecord] = useState<DnsRecord | null>(null);

  function confirmDelete(r: DnsRecord) {
    modals.openConfirmModal({
      title: "Delete record",
      children: (
        <Text size="sm">
          Delete <strong>{r.name} {r.record_type} {r.data}</strong>?
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteRecord.mutate(r.id, {
          onSuccess: () => notifications.show({ message: "Record deleted", color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  async function handleExport() {
    const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
    const res = await fetch(`${API_BASE}/api/v1/dns-zones/${zone.id}/export`, {
      credentials: "include",
    });
    if (!res.ok) {
      notifications.show({ message: `Export failed: ${res.status}`, color: "red" });
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${zone.name}.zone`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (isLoading) return <Loader size="sm" mt="md" />;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {records.length} record{records.length !== 1 ? "s" : ""} ·{" "}
          {records.filter((r) => r.enabled).length} active
        </Text>
        <Group gap="xs">
          <Tooltip label="Export as BIND zone file">
            <Button
              size="xs"
              variant="default"
              leftSection={<IconDownload size={13} />}
              onClick={handleExport}
            >
              Export zone file
            </Button>
          </Tooltip>
          {canWrite && (
            <Button size="xs" leftSection={<IconPlus size={13} />} onClick={() => setShowModal(true)}>
              Add record
            </Button>
          )}
        </Group>
      </Group>

      <Table striped highlightOnHover withTableBorder withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={50} />
            <Table.Th>Name</Table.Th>
            <Table.Th w={80}>Type</Table.Th>
            <Table.Th w={75} style={{ textAlign: "right" }}>TTL</Table.Th>
            <Table.Th w={80} style={{ textAlign: "right" }}>Priority</Table.Th>
            <Table.Th>Data</Table.Th>
            <Table.Th w={50}>On</Table.Th>
            <Table.Th w={80} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {records.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={8}>
                <Text c="dimmed" ta="center" py="md">
                  No records yet.{canWrite ? ' Click “Add record” to create the first one.' : ""}
                </Text>
              </Table.Td>
            </Table.Tr>
          )}
          {records.map((r) => (
            <Table.Tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.5 }}>
              <Table.Td>
                <IconCircleFilled
                  size={8}
                  style={{ color: `var(--mantine-color-${r.enabled ? "green" : "gray"}-6)` }}
                />
              </Table.Td>
              <Table.Td>
                <Text size="sm" ff="monospace" fw={r.name === "@" ? 700 : 400}>{r.name}</Text>
              </Table.Td>
              <Table.Td>
                <Badge
                  size="sm"
                  variant="light"
                  color={RECORD_TYPE_COLOR[r.record_type] ?? "gray"}
                >
                  {r.record_type}
                </Badge>
              </Table.Td>
              <Table.Td style={{ textAlign: "right" }}>
                <Text size="sm" c="dimmed" ff="monospace">
                  {r.ttl != null ? r.ttl : <Text span c="dimmed" size="xs">default</Text>}
                </Text>
              </Table.Td>
              <Table.Td style={{ textAlign: "right" }}>
                <Text size="sm" ff="monospace">{r.priority ?? "—"}</Text>
              </Table.Td>
              <Table.Td>
                <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>{r.data}</Text>
              </Table.Td>
              <Table.Td>
                <Text size="sm" c={r.enabled ? "green" : "dimmed"}>{r.enabled ? "Yes" : "No"}</Text>
              </Table.Td>
              <Table.Td>
                {canWrite && (
                  <Group gap={2} wrap="nowrap" justify="flex-end">
                    <Tooltip label="Edit">
                      <ActionIcon size="sm" variant="subtle" onClick={() => setEditRecord(r)}>
                        <IconEdit size={13} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Delete">
                      <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(r)}>
                        <IconTrash size={13} />
                      </ActionIcon>
                    </Tooltip>
                  </Group>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>

      {(showModal) && (
        <RecordModal zoneId={zone.id} record={null} onClose={() => setShowModal(false)} />
      )}
      {editRecord && (
        <RecordModal zoneId={zone.id} record={editRecord} onClose={() => setEditRecord(null)} />
      )}
    </Stack>
  );
}

// ─── Settings tab ─────────────────────────────────────────────────────────────

const ZONE_TYPE_OPTIONS = [
  { value: "local",       label: "Local — authoritative zone" },
  { value: "forward",     label: "Forward — relay to upstream resolver" },
  { value: "passthrough", label: "Passthrough — exempt from filtering" },
];

function SettingsTab({ zone, canWrite }: { zone: Zone; canWrite: boolean }) {
  const updateZone = useUpdateZone();
  const form = useForm({
    initialValues: {
      zone_type:   zone.zone_type,
      description: zone.description,
      enabled:     zone.enabled,
      ttl_default: zone.ttl_default,
      forwarder:   zone.forwarder ?? "",
    },
  });

  const isForward = form.values.zone_type === "forward";

  return (
    <form
      onSubmit={form.onSubmit((values) =>
        updateZone.mutate(
          {
            zoneId: zone.id,
            body: { ...values, forwarder: isForward ? values.forwarder || null : null },
          },
          {
            onSuccess: () => notifications.show({ message: "Zone settings saved", color: "green" }),
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          }
        )
      )}
    >
      <Stack maw={520} gap="md">
        <TextInput label="Zone name" value={zone.name} disabled description="Zone name cannot be changed after creation" />
        <Select label="Zone type" data={ZONE_TYPE_OPTIONS} disabled={!canWrite} {...form.getInputProps("zone_type")} />
        {isForward && (
          <TextInput label="Forwarder address" placeholder="10.0.0.53" disabled={!canWrite} {...form.getInputProps("forwarder")} />
        )}
        <TextInput label="Description" disabled={!canWrite} {...form.getInputProps("description")} />
        <NumberInput label="Default TTL (seconds)" min={0} max={86400} disabled={!canWrite} {...form.getInputProps("ttl_default")} />
        <Switch label="Zone enabled" disabled={!canWrite} {...form.getInputProps("enabled", { type: "checkbox" })} />
        {canWrite && (
          <Group>
            <Button type="submit" loading={updateZone.isPending}>Save settings</Button>
          </Group>
        )}
      </Stack>
    </form>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ZoneDetailPage() {
  const { zoneId } = useParams<{ zoneId: string }>();
  const { data: zone, isLoading } = useZone(zoneId!);
  const deleteZone = useDeleteZone();
  const navigate = useNavigate();
  const { hasRole } = useAuth();
  const canWrite = hasRole("operator");

  if (isLoading) {
    return (
      <Group justify="center" mt="xl">
        <Loader />
      </Group>
    );
  }

  if (!zone) {
    return <Text c="dimmed">Zone not found.</Text>;
  }

  const tm = typeMeta(zone.zone_type);

  function confirmDelete() {
    modals.openConfirmModal({
      title: "Delete zone",
      children: (
        <Text size="sm">
          Delete <strong>{zone!.name}</strong>? All {zone!.record_count} records will be removed.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteZone.mutate(zone!.id, {
          onSuccess: () => { notifications.show({ message: `Zone deleted`, color: "green" }); navigate("/zones"); },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  return (
    <Stack gap="lg">
      {/* Breadcrumb */}
      <Breadcrumbs>
        <Anchor component={Link} to="/zones" size="sm">DNS Zones</Anchor>
        <Text size="sm">{zone.name}</Text>
      </Breadcrumbs>

      {/* Zone header */}
      <Group justify="space-between" align="flex-start">
        <Stack gap={4}>
          <Group gap="sm">
            <Title order={2} ff="monospace">{zone.name}</Title>
            <Badge color={tm.color} variant="light" size="lg">{tm.label}</Badge>
            <Badge
              color={zone.enabled ? "green" : "gray"}
              variant="dot"
              size="sm"
            >
              {zone.enabled ? "Active" : "Disabled"}
            </Badge>
          </Group>
          {zone.description && <Text c="dimmed" size="sm">{zone.description}</Text>}
          <Group gap="xs">
            <Text size="xs" c="dimmed">Default TTL: {zone.ttl_default}s</Text>
            {zone.forwarder && (
              <>
                <Text size="xs" c="dimmed">·</Text>
                <Text size="xs" c="dimmed">Forwarder: {zone.forwarder}</Text>
              </>
            )}
            <Text size="xs" c="dimmed">·</Text>
            <Text size="xs" c="dimmed">Created: {new Date(zone.created_at).toLocaleDateString()}</Text>
          </Group>
        </Stack>
        {canWrite && (
          <Group gap="xs">
            <Tooltip label="Delete zone">
              <ActionIcon variant="light" color="red" onClick={confirmDelete}>
                <IconTrash size={16} />
              </ActionIcon>
            </Tooltip>
          </Group>
        )}
      </Group>

      {/* Tabs */}
      <Tabs defaultValue="records">
        <Tabs.List>
          <Tabs.Tab value="records">
            Records{zone.record_count > 0 ? ` (${zone.record_count})` : ""}
          </Tabs.Tab>
          <Tabs.Tab value="settings">Settings</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="records" pt="md">
          {zone.zone_type === "passthrough" ? (
            <Text c="dimmed" size="sm" mt="sm">
              Passthrough zones do not contain DNS records — all queries for this zone bypass filtering and are forwarded to the default resolver.
            </Text>
          ) : (
            <RecordsTab zone={zone} canWrite={canWrite} />
          )}
        </Tabs.Panel>

        <Tabs.Panel value="settings" pt="md">
          <SettingsTab zone={zone} canWrite={canWrite} />
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
