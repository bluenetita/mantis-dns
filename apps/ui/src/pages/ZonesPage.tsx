import {
  ActionIcon,
  Badge,
  Button,
  Center,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
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
  IconCircleFilled,
  IconEdit,
  IconExternalLink,
  IconPlus,
  IconSearch,
  IconTrash,
} from "@tabler/icons-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  useCreateZone,
  useDeleteZone,
  useTenants,
  useUpdateZone,
  useZones,
} from "../api/hooks";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type Zone = components["schemas"]["ZoneOut"];

// ─── helpers ────────────────────────────────────────────────────────────────

const ZONE_TYPE_META: Record<string, { color: string; label: string; description: string }> = {
  local:       { color: "blue",   label: "Local",       description: "Authoritative — answers queries from records defined here" },
  forward:     { color: "violet", label: "Forward",     description: "Forwards queries for this zone to a specific upstream resolver" },
  passthrough: { color: "teal",   label: "Passthrough", description: "Exempts this zone from policy filtering" },
};

function typeMeta(t: string) {
  return ZONE_TYPE_META[t] ?? { color: "gray", label: t, description: "" };
}

function zoneStatus(z: Zone): { color: string; label: string } {
  if (!z.enabled) return { color: "gray", label: "Disabled" };
  return { color: "green", label: "Active" };
}

// ─── KPI card ────────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <Stack gap={2} style={{ borderLeft: "3px solid var(--mantine-color-blue-5)", paddingLeft: 12 }}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>{label}</Text>
      <Text size="xl" fw={700} lh={1}>{value}</Text>
      {sub && <Text size="xs" c="dimmed">{sub}</Text>}
    </Stack>
  );
}

// ─── Add Zone modal ───────────────────────────────────────────────────────────

const ZONE_TYPE_OPTIONS = [
  { value: "local",       label: "Local — authoritative zone with records" },
  { value: "forward",     label: "Forward — relay queries to upstream resolver" },
  { value: "passthrough", label: "Passthrough — exempt from filtering" },
];

function AddZoneModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const createZone = useCreateZone();
  const { data: tenants = [] } = useTenants();
  const tenantOptions = tenants.map((t) => ({ value: t.id, label: t.name }));
  const form = useForm({
    initialValues: {
      tenant_id: "",
      name: "",
      zone_type: "local",
      description: "",
      enabled: true,
      ttl_default: 300,
      forwarder: "",
    },
    validate: {
      tenant_id: (v) => (!v ? "Tenant is required" : null),
      name: (v) => (v.trim().length < 1 ? "Zone name is required" : null),
      zone_type: (v) => (!v ? "Zone type is required" : null),
      forwarder: (v, values) =>
        values.zone_type === "forward" && !v.trim() ? "Forwarder IP is required for forward zones" : null,
    },
  });

  const isForward = form.values.zone_type === "forward";

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={opened} onClose={handleClose} title="Add DNS zone" size="lg">
      <form
        onSubmit={form.onSubmit((values) =>
          createZone.mutate(
            { ...values, forwarder: isForward ? values.forwarder : null },
            {
              onSuccess: () => {
                notifications.show({ message: `Zone "${values.name}" created`, color: "green" });
                handleClose();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            }
          )
        )}
      >
        <Stack>
          <Select
            label="Tenant"
            data={tenantOptions}
            required
            searchable
            {...form.getInputProps("tenant_id")}
          />
          <SimpleGrid cols={2}>
            <TextInput
              label="Zone name"
              placeholder="corp.local"
              description="Fully qualified domain name (FQDN)"
              required
              {...form.getInputProps("name")}
            />
            <Select
              label="Zone type"
              data={ZONE_TYPE_OPTIONS}
              required
              {...form.getInputProps("zone_type")}
            />
          </SimpleGrid>
          {isForward && (
            <TextInput
              label="Forwarder address"
              placeholder="10.0.0.53"
              description="IP address of the upstream DNS resolver"
              required
              {...form.getInputProps("forwarder")}
            />
          )}
          <TextInput
            label="Description"
            placeholder="Internal corporate domain"
            {...form.getInputProps("description")}
          />
          <SimpleGrid cols={2}>
            <NumberInput
              label="Default TTL (seconds)"
              min={0}
              max={86400}
              {...form.getInputProps("ttl_default")}
            />
            <Switch
              label="Enable zone"
              mt="xl"
              {...form.getInputProps("enabled", { type: "checkbox" })}
            />
          </SimpleGrid>
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={createZone.isPending}>Create zone</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Edit Zone modal ──────────────────────────────────────────────────────────

function EditZoneModal({ zone, onClose }: { zone: Zone | null; onClose: () => void }) {
  const updateZone = useUpdateZone();
  const form = useForm({
    initialValues: {
      zone_type: zone?.zone_type ?? "local",
      description: zone?.description ?? "",
      enabled: zone?.enabled ?? true,
      ttl_default: zone?.ttl_default ?? 300,
      forwarder: zone?.forwarder ?? "",
    },
  });

  if (!zone) return null;

  const isForward = form.values.zone_type === "forward";

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={!!zone} onClose={handleClose} title={`Edit zone: ${zone.name}`} size="lg">
      <form
        onSubmit={form.onSubmit((values) =>
          updateZone.mutate(
            {
              zoneId: zone.id,
              body: { ...values, forwarder: isForward ? values.forwarder || null : null },
            },
            {
              onSuccess: () => {
                notifications.show({ message: `Zone "${zone.name}" updated`, color: "green" });
                handleClose();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            }
          )
        )}
      >
        <Stack>
          <TextInput label="Zone name" value={zone.name} disabled />
          <Select label="Zone type" data={ZONE_TYPE_OPTIONS} {...form.getInputProps("zone_type")} />
          {isForward && (
            <TextInput label="Forwarder address" placeholder="10.0.0.53" {...form.getInputProps("forwarder")} />
          )}
          <TextInput label="Description" {...form.getInputProps("description")} />
          <SimpleGrid cols={2}>
            <NumberInput label="Default TTL (seconds)" min={0} max={86400} {...form.getInputProps("ttl_default")} />
            <Switch label="Enable zone" mt="xl" {...form.getInputProps("enabled", { type: "checkbox" })} />
          </SimpleGrid>
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={updateZone.isPending}>Save changes</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ZonesPage() {
  const { data: zones = [], isLoading } = useZones();
  const { data: tenants = [] } = useTenants();
  const tenantName = (id: string | null) => tenants.find((t) => t.id === id)?.name ?? "—";
  const deleteZone = useDeleteZone();
  const navigate = useNavigate();
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [editZone, setEditZone] = useState<Zone | null>(null);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const { hasRole } = useAuth();
  const canWrite = hasRole("operator");

  const sorted = [...zones].sort((a, b) => a.name.localeCompare(b.name));

  const visible = sorted.filter((z) => {
    if (search && !z.name.toLowerCase().includes(search.toLowerCase()) &&
        !(z.description ?? "").toLowerCase().includes(search.toLowerCase())) return false;
    if (typeFilter && z.zone_type !== typeFilter) return false;
    if (statusFilter === "active" && !z.enabled) return false;
    if (statusFilter === "disabled" && z.enabled) return false;
    return true;
  });

  const totalRecords = zones.reduce((s, z) => s + z.record_count, 0);
  const byType = (t: string) => zones.filter((z) => z.zone_type === t).length;

  const typeOptions = [...new Set(zones.map((z) => z.zone_type))].sort().map((t) => ({
    value: t,
    label: typeMeta(t).label,
  }));

  function confirmDelete(z: Zone) {
    modals.openConfirmModal({
      title: "Delete zone",
      children: (
        <Text size="sm">
          Delete <strong>{z.name}</strong>? All {z.record_count} records will be removed.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteZone.mutate(z.id, {
          onSuccess: () => notifications.show({ message: `Zone "${z.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  if (isLoading) return <Center h={200}><Loader /></Center>;

  return (
    <Stack gap="lg">
      {/* Header */}
      <Group justify="space-between" align="flex-start">
        <Stack gap={2}>
          <Title order={2}>DNS Zones</Title>
          <Text c="dimmed" size="sm">
            Manage local authoritative zones, forwarders, and passthrough exemptions.
          </Text>
        </Stack>
        {canWrite && (
          <Button leftSection={<IconPlus size={16} />} onClick={openAdd}>
            Add zone
          </Button>
        )}
      </Group>

      {/* KPIs */}
      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        <KpiCard label="Total zones" value={zones.length} sub={`${zones.filter((z) => z.enabled).length} active`} />
        <KpiCard label="Local (authoritative)" value={byType("local")} sub="Own records defined here" />
        <KpiCard label="Forward" value={byType("forward")} sub="Relay to upstream resolver" />
        <KpiCard label="Total records" value={totalRecords.toLocaleString()} sub="Across all local zones" />
      </SimpleGrid>

      {/* Filters */}
      <Group>
        <TextInput
          placeholder="Search by name or description…"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => setSearch(e.currentTarget.value)}
          style={{ flex: 1, maxWidth: 360 }}
        />
        <Select
          placeholder="All types"
          clearable
          data={typeOptions}
          value={typeFilter}
          onChange={(v) => setTypeFilter(v ?? "")}
          style={{ width: 180 }}
        />
        <Select
          placeholder="All statuses"
          clearable
          data={[
            { value: "active", label: "Active" },
            { value: "disabled", label: "Disabled" },
          ]}
          value={statusFilter}
          onChange={(v) => setStatusFilter(v ?? "")}
          style={{ width: 150 }}
        />
      </Group>

      {/* Table */}
      <Table striped highlightOnHover withTableBorder withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Zone</Table.Th>
            <Table.Th w={140}>Tenant</Table.Th>
            <Table.Th w={120}>Type</Table.Th>
            <Table.Th w={110}>Status</Table.Th>
            <Table.Th w={90} style={{ textAlign: "right" }}>Records</Table.Th>
            <Table.Th w={70} style={{ textAlign: "right" }}>TTL</Table.Th>
            <Table.Th w={160}>Forwarder</Table.Th>
            <Table.Th w={110} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {visible.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={8}>
                <Text c="dimmed" ta="center" py="md">No zones match the current filters</Text>
              </Table.Td>
            </Table.Tr>
          )}
          {visible.map((z) => {
            const st = zoneStatus(z);
            const tm = typeMeta(z.zone_type);
            return (
              <Table.Tr key={z.id}>
                {/* Zone name */}
                <Table.Td>
                  <Stack gap={2}>
                    <Group gap={6} wrap="nowrap">
                      <Text
                        size="sm" fw={600} ff="monospace"
                        style={{ cursor: "pointer", textDecoration: "underline dotted" }}
                        onClick={() => navigate(`/zones/${z.id}`)}
                      >
                        {z.name}
                      </Text>
                      <ActionIcon
                        size="xs" variant="subtle" color="gray"
                        onClick={() => navigate(`/zones/${z.id}`)}
                      >
                        <IconExternalLink size={11} />
                      </ActionIcon>
                    </Group>
                    {z.description && <Text size="xs" c="dimmed">{z.description}</Text>}
                  </Stack>
                </Table.Td>

                {/* Tenant */}
                <Table.Td>
                  <Text size="sm">{tenantName(z.tenant_id)}</Text>
                </Table.Td>

                {/* Type */}
                <Table.Td>
                  <Tooltip label={tm.description} multiline maw={260} position="right">
                    <Badge color={tm.color} variant="light" size="sm">{tm.label}</Badge>
                  </Tooltip>
                </Table.Td>

                {/* Status */}
                <Table.Td>
                  <Group gap={5} wrap="nowrap">
                    <IconCircleFilled size={8} style={{ color: `var(--mantine-color-${st.color}-6)` }} />
                    <Text size="sm">{st.label}</Text>
                  </Group>
                </Table.Td>

                {/* Records */}
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="sm" ff="monospace">{z.record_count > 0 ? z.record_count : "—"}</Text>
                </Table.Td>

                {/* TTL */}
                <Table.Td style={{ textAlign: "right" }}>
                  <Text size="sm" c="dimmed">{z.ttl_default}s</Text>
                </Table.Td>

                {/* Forwarder */}
                <Table.Td>
                  <Text size="sm" ff="monospace" c={z.forwarder ? undefined : "dimmed"}>
                    {z.forwarder ?? "—"}
                  </Text>
                </Table.Td>

                {/* Actions */}
                <Table.Td>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    <Tooltip label="Open zone">
                      <ActionIcon size="sm" variant="subtle" onClick={() => navigate(`/zones/${z.id}`)}>
                        <IconExternalLink size={14} />
                      </ActionIcon>
                    </Tooltip>
                    {canWrite && (
                      <>
                        <Tooltip label="Edit">
                          <ActionIcon size="sm" variant="subtle" onClick={() => setEditZone(z)}>
                            <IconEdit size={14} />
                          </ActionIcon>
                        </Tooltip>
                        <Tooltip label="Delete">
                          <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(z)}>
                            <IconTrash size={14} />
                          </ActionIcon>
                        </Tooltip>
                      </>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>

      {visible.length > 0 && (
        <Text size="xs" c="dimmed" ta="right">{visible.length} of {zones.length} zones</Text>
      )}

      <AddZoneModal opened={addOpened} onClose={closeAdd} />
      <EditZoneModal zone={editZone} onClose={() => setEditZone(null)} />
    </Stack>
  );
}
