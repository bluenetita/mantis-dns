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
  Checkbox,
  Code,
  Group,
  Loader,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
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
  IconInfoCircle,
  IconPlus,
  IconServer,
  IconTrash,
} from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateUpstreamPool,
  useCreateUpstreamResolver,
  useCreateUpstreamRoute,
  useDeleteUpstreamPool,
  useDeleteUpstreamResolver,
  useDeleteUpstreamRoute,
  useProbeUpstreamResolver,
  useUpdateUpstreamPool,
  useUpdateUpstreamResolver,
  useUpdateUpstreamRoute,
  useUpstreamPools,
  useUpstreamResolvers,
  useUpstreamRoutes,
  useUpstreamTenantPolicy,
  useUpsertUpstreamTenantPolicy,
  type UpstreamPool,
  type UpstreamResolver,
  type UpstreamRoute,
} from "../api/hooks";
import { useTenants } from "../api/hooks";

// ── Helpers ────────────────────────────────────────────────────────────────────


const STRATEGY_LABELS: Record<string, string> = {
  round_robin: "Round-robin",
  weighted_round_robin: "Weighted RR",
  failover: "Failover",
  latency: "Latency",
};

const MATCH_TYPE_OPTIONS = [
  { value: "domain_suffix", label: "Domain suffix" },
  { value: "domain_exact", label: "Exact domain" },
  { value: "qtype", label: "Query type" },
  { value: "category", label: "Category" },
  { value: "default", label: "Default (catch-all)" },
];

const DNSSEC_OPTIONS = [
  { value: "strict", label: "Strict — require AD bit" },
  { value: "opportunistic", label: "Opportunistic — propagate AD bit" },
  { value: "disabled", label: "Disabled — strip AD bit" },
];

// ── Resolver form ─────────────────────────────────────────────────────────────

function ResolverForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<UpstreamResolver>;
  onSave: (values: Partial<UpstreamResolver>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      name: initial?.name ?? "",
      protocol: initial?.protocol ?? "dot",
      address: initial?.address ?? "",
      port: initial?.port ?? 853,
      tls_hostname: initial?.tls_hostname ?? "",
      dnssec_validation: initial?.dnssec_validation ?? "opportunistic",
      qname_minimization: initial?.qname_minimization ?? true,
      edns_client_subnet: initial?.edns_client_subnet ?? false,
      timeout_ms: initial?.timeout_ms ?? 5000,
      max_retries: initial?.max_retries ?? 2,
      connect_timeout_ms: initial?.connect_timeout_ms ?? 3000,
      tags: initial?.tags ?? [],
      enabled: initial?.enabled ?? true,
    },
    validate: {
      name: (v) => (!v.trim() ? "Required" : null),
      address: (v) => (!v.trim() ? "Required" : null),
      port: (v) => (v < 1 || v > 65535 ? "1–65535" : null),
    },
  });

  const needsTls = ["dot", "doh"].includes(form.values.protocol);

  function submit(values: typeof form.values) {
    const out: Partial<UpstreamResolver> = {
      ...values,
      tls_hostname: needsTls && values.tls_hostname ? values.tls_hostname : undefined,
    };
    onSave(out);
  }

  return (
    <form onSubmit={form.onSubmit(submit)}>
      <Stack>
        <TextInput label="Name" placeholder="Cloudflare DoT #1" required {...form.getInputProps("name")} />
        <SimpleGrid cols={2}>
          <Select
            label="Protocol"
            data={[
              { value: "dot", label: "DNS-over-TLS (DoT)" },
              { value: "doh", label: "DNS-over-HTTPS (DoH)" },
              { value: "do53", label: "Plain DNS (do53)" },
            ]}
            {...form.getInputProps("protocol")}
          />
          <NumberInput label="Port" min={1} max={65535} {...form.getInputProps("port")} />
        </SimpleGrid>
        <SimpleGrid cols={needsTls ? 2 : 1}>
          <TextInput label="Address" placeholder="1.1.1.1" required {...form.getInputProps("address")} />
          {needsTls && (
            <TextInput
              label="TLS hostname (SNI)"
              placeholder="cloudflare-dns.com"
              description="Defaults to Address if blank"
              {...form.getInputProps("tls_hostname")}
            />
          )}
        </SimpleGrid>
        <Select label="DNSSEC validation" data={DNSSEC_OPTIONS} {...form.getInputProps("dnssec_validation")} />
        <SimpleGrid cols={3}>
          <NumberInput label="Timeout (ms)" min={100} max={30000} {...form.getInputProps("timeout_ms")} />
          <NumberInput label="Retries" min={0} max={5} {...form.getInputProps("max_retries")} />
          <NumberInput label="Connect timeout (ms)" min={100} max={15000} {...form.getInputProps("connect_timeout_ms")} />
        </SimpleGrid>
        <SimpleGrid cols={2}>
          <Checkbox label="QNAME minimization" {...form.getInputProps("qname_minimization", { type: "checkbox" })} />
          <Checkbox label="EDNS Client Subnet" {...form.getInputProps("edns_client_subnet", { type: "checkbox" })} />
        </SimpleGrid>
        <MultiSelect
          label="Tags"
          placeholder="public, internal, threat-intel…"
          data={["public", "internal", "threat-intel", "doh", "do53"]}
          searchable
          {...form.getInputProps("tags")}
        />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

// ── Resolvers tab ─────────────────────────────────────────────────────────────

function ResolversTab() {
  const { data: resolvers = [], isLoading } = useUpstreamResolvers();
  const createResolver = useCreateUpstreamResolver();
  const updateResolver = useUpdateUpstreamResolver();
  const deleteResolver = useDeleteUpstreamResolver();
  const probeResolver = useProbeUpstreamResolver();
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [editTarget, setEditTarget] = useState<UpstreamResolver | null>(null);
  const [probingId, setProbingId] = useState<string | null>(null);

  function probe(r: UpstreamResolver) {
    setProbingId(r.id);
    probeResolver.mutate(r.id, {
      onSuccess: (result) => {
        if (result.ok) {
          notifications.show({
            color: "green",
            title: `${r.name} — OK`,
            message: `${result.latency_ms?.toFixed(0)} ms · ${result.response_code}${result.dnssec_ad ? " · AD" : ""}${result.tls_subject ? ` · ${result.tls_subject}` : ""}`,
          });
        } else {
          notifications.show({
            color: "red",
            title: `${r.name} — Failed`,
            message: result.error ?? "Unknown error",
          });
        }
      },
      onError: (e) => notifications.show({ color: "red", message: String(e) }),
      onSettled: () => setProbingId(null),
    });
  }

  function confirmDelete(r: UpstreamResolver) {
    modals.openConfirmModal({
      title: "Delete resolver",
      children: <Text size="sm">Delete <strong>{r.name}</strong>? Any pools referencing it will lose this member.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteResolver.mutate(r.id, {
          onSuccess: () => notifications.show({ message: `Resolver "${r.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  if (isLoading) return <Center h={160}><Loader /></Center>;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Named upstream DNS server profiles. Group them into pools for load-balancing and failover.
        </Text>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openAdd}>Add resolver</Button>
      </Group>

      {resolvers.length === 0 && (
        <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
          <Text c="dimmed" size="sm" ta="center">No resolvers configured. Add one to get started.</Text>
        </Card>
      )}

      {resolvers.length > 0 && (
        <Table striped highlightOnHover withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th w={100}>Protocol</Table.Th>
              <Table.Th>Address</Table.Th>
              <Table.Th w={120}>DNSSEC</Table.Th>
              <Table.Th w={60}>On</Table.Th>
              <Table.Th w={140} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {resolvers.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text size="sm" fw={500}>{r.name}</Text>
                  {r.tags.length > 0 && (
                    <Group gap={4} mt={2}>
                      {r.tags.map((t) => (
                        <Badge key={t} size="xs" variant="outline" color="gray">{t}</Badge>
                      ))}
                    </Group>
                  )}
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light" color={r.protocol === "dot" ? "blue" : r.protocol === "doh" ? "violet" : "gray"}>
                    {r.protocol.toUpperCase()}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Code>{r.address}:{r.port}</Code>
                  {r.tls_hostname && r.tls_hostname !== r.address && (
                    <Text size="xs" c="dimmed">{r.tls_hostname}</Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{r.dnssec_validation}</Text>
                </Table.Td>
                <Table.Td>
                  <Switch
                    checked={r.enabled}
                    size="sm"
                    onChange={() =>
                      updateResolver.mutate(
                        { id: r.id, body: { enabled: !r.enabled } },
                        { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
                      )
                    }
                  />
                </Table.Td>
                <Table.Td>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    <Tooltip label="Live probe (SOA query)">
                      <Button
                        size="xs" variant="default"
                        leftSection={<IconBolt size={12} />}
                        loading={probingId === r.id}
                        onClick={() => probe(r)}
                      >
                        Test
                      </Button>
                    </Tooltip>
                    <ActionIcon size="sm" variant="subtle" onClick={() => setEditTarget(r)}>
                      <IconEdit size={14} />
                    </ActionIcon>
                    <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(r)}>
                      <IconTrash size={14} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={addOpened} onClose={closeAdd} title="Add resolver" size="lg">
        <ResolverForm
          onSave={(values) =>
            createResolver.mutate(values, {
              onSuccess: (r) => {
                notifications.show({ message: `Resolver "${r.name}" created`, color: "green" });
                closeAdd();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            })
          }
          onCancel={closeAdd}
          saving={createResolver.isPending}
        />
      </Modal>

      <Modal opened={!!editTarget} onClose={() => setEditTarget(null)} title="Edit resolver" size="lg">
        {editTarget && (
          <ResolverForm
            initial={editTarget}
            onSave={(values) =>
              updateResolver.mutate(
                { id: editTarget.id, body: values },
                {
                  onSuccess: () => {
                    notifications.show({ message: "Resolver updated", color: "green" });
                    setEditTarget(null);
                  },
                  onError: (e) => notifications.show({ message: String(e), color: "red" }),
                }
              )
            }
            onCancel={() => setEditTarget(null)}
            saving={updateResolver.isPending}
          />
        )}
      </Modal>
    </Stack>
  );
}

// ── Pool form ─────────────────────────────────────────────────────────────────

function PoolForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<UpstreamPool>;
  onSave: (values: Partial<UpstreamPool>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      name: initial?.name ?? "",
      strategy: initial?.strategy ?? "round_robin",
      health_check_interval_s: initial?.health_check_interval_s ?? 30,
      health_check_timeout_ms: initial?.health_check_timeout_ms ?? 2000,
      health_check_query: initial?.health_check_query ?? ".",
      health_check_type: initial?.health_check_type ?? "soa",
      unhealthy_threshold: initial?.unhealthy_threshold ?? 3,
      healthy_threshold: initial?.healthy_threshold ?? 2,
      min_healthy_members: initial?.min_healthy_members ?? 1,
    },
    validate: { name: (v) => (!v.trim() ? "Required" : null) },
  });

  return (
    <form onSubmit={form.onSubmit(onSave)}>
      <Stack>
        <TextInput label="Pool name" placeholder="public-dot-ha" required {...form.getInputProps("name")} />
        <Select
          label="Strategy"
          data={[
            { value: "round_robin", label: "Round-robin" },
            { value: "weighted_round_robin", label: "Weighted round-robin" },
            { value: "failover", label: "Failover (priority order)" },
            { value: "latency", label: "Latency (lowest P50 wins)" },
          ]}
          {...form.getInputProps("strategy")}
        />
        <Text size="sm" fw={500} mt={4}>Health check</Text>
        <SimpleGrid cols={3}>
          <NumberInput label="Interval (s)" min={5} max={3600} {...form.getInputProps("health_check_interval_s")} />
          <NumberInput label="Timeout (ms)" min={100} max={10000} {...form.getInputProps("health_check_timeout_ms")} />
          <Select
            label="Query type"
            data={[
              { value: "soa", label: "SOA (root)" },
              { value: "a", label: "A record" },
              { value: "txt", label: "TXT record" },
            ]}
            {...form.getInputProps("health_check_type")}
          />
        </SimpleGrid>
        <TextInput label="Probe domain" {...form.getInputProps("health_check_query")} />
        <SimpleGrid cols={3}>
          <NumberInput label="Unhealthy threshold" min={1} max={10} description="Failures before ejection" {...form.getInputProps("unhealthy_threshold")} />
          <NumberInput label="Healthy threshold" min={1} max={10} description="Successes before re-admission" {...form.getInputProps("healthy_threshold")} />
          <NumberInput label="Min healthy members" min={1} description="Alert + use fallback below this" {...form.getInputProps("min_healthy_members")} />
        </SimpleGrid>
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

// ── Pools tab ─────────────────────────────────────────────────────────────────

function PoolsTab() {
  const { data: pools = [], isLoading } = useUpstreamPools();
  const { data: resolvers = [] } = useUpstreamResolvers();
  const createPool = useCreateUpstreamPool();
  const updatePool = useUpdateUpstreamPool();
  const deletePool = useDeleteUpstreamPool();
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [editTarget, setEditTarget] = useState<UpstreamPool | null>(null);

  const resolverName = (id: string) =>
    resolvers.find((r) => r.id === id)?.name ?? id.slice(0, 8);

  function confirmDelete(p: UpstreamPool) {
    modals.openConfirmModal({
      title: "Delete pool",
      children: <Text size="sm">Delete pool <strong>{p.name}</strong>? Routes referencing it will break.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deletePool.mutate(p.id, {
          onSuccess: () => notifications.show({ message: `Pool "${p.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  if (isLoading) return <Center h={160}><Loader /></Center>;

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Pools group resolvers under a load-balancing / failover strategy. Assign pools to upstream routes.
        </Text>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openAdd}>Add pool</Button>
      </Group>

      {pools.length === 0 && (
        <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
          <Text c="dimmed" size="sm" ta="center">No pools. Create resolvers first, then group them into pools.</Text>
        </Card>
      )}

      {pools.length > 0 && (
        <Table striped highlightOnHover withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Pool</Table.Th>
              <Table.Th w={130}>Strategy</Table.Th>
              <Table.Th>Members</Table.Th>
              <Table.Th w={90}>Health check</Table.Th>
              <Table.Th w={80} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {pools.map((p) => (
              <Table.Tr key={p.id}>
                <Table.Td>
                  <Text size="sm" fw={500}>{p.name}</Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light">{STRATEGY_LABELS[p.strategy] ?? p.strategy}</Badge>
                </Table.Td>
                <Table.Td>
                  <Group gap={4} wrap="wrap">
                    {p.members.map((m) => (
                      <Badge key={m.id} size="xs" variant="outline">
                        {resolverName(m.resolver_id)}
                        {p.strategy === "failover" && ` (p${m.priority})`}
                        {p.strategy === "weighted_round_robin" && ` ×${m.weight}`}
                      </Badge>
                    ))}
                    {p.members.length === 0 && <Text size="xs" c="dimmed">No members</Text>}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="xs">{p.health_check_interval_s}s / {p.health_check_timeout_ms}ms</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    <ActionIcon size="sm" variant="subtle" onClick={() => setEditTarget(p)}>
                      <IconEdit size={14} />
                    </ActionIcon>
                    <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(p)}>
                      <IconTrash size={14} />
                    </ActionIcon>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={addOpened} onClose={closeAdd} title="Add pool" size="lg">
        <PoolForm
          onSave={(values) =>
            createPool.mutate(values, {
              onSuccess: (p) => {
                notifications.show({ message: `Pool "${p.name}" created`, color: "green" });
                closeAdd();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            })
          }
          onCancel={closeAdd}
          saving={createPool.isPending}
        />
      </Modal>

      <Modal opened={!!editTarget} onClose={() => setEditTarget(null)} title="Edit pool" size="lg">
        {editTarget && (
          <PoolForm
            initial={editTarget}
            onSave={(values) =>
              updatePool.mutate(
                { id: editTarget.id, body: values },
                {
                  onSuccess: () => {
                    notifications.show({ message: "Pool updated", color: "green" });
                    setEditTarget(null);
                  },
                  onError: (e) => notifications.show({ message: String(e), color: "red" }),
                }
              )
            }
            onCancel={() => setEditTarget(null)}
            saving={updatePool.isPending}
          />
        )}
      </Modal>
    </Stack>
  );
}

// ── Routes tab ────────────────────────────────────────────────────────────────

function RouteForm({
  tenantId: _tenantId,
  initial,
  onSave,
  onCancel,
  saving,
}: {
  tenantId: string;
  initial?: Partial<UpstreamRoute>;
  onSave: (values: Partial<UpstreamRoute>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const { data: pools = [] } = useUpstreamPools();

  const form = useForm({
    initialValues: {
      name: initial?.name ?? "",
      match_type: initial?.match_type ?? "default",
      match_value: initial?.match_value ?? "",
      pool_id: initial?.pool_id ?? "",
      priority: initial?.priority ?? 100,
      enabled: initial?.enabled ?? true,
    },
    validate: {
      name: (v) => (!v.trim() ? "Required" : null),
      pool_id: (v) => (!v ? "Select a pool" : null),
    },
  });

  const needsValue = form.values.match_type !== "default";

  return (
    <form onSubmit={form.onSubmit((v) => onSave({ ...v, match_value: needsValue ? v.match_value : null }))}>
      <Stack>
        <TextInput label="Name" placeholder="corp-internal-domains" required {...form.getInputProps("name")} />
        <SimpleGrid cols={2}>
          <Select label="Match type" data={MATCH_TYPE_OPTIONS} {...form.getInputProps("match_type")} />
          <NumberInput label="Priority" min={0} max={9999} description="Lower = evaluated first" {...form.getInputProps("priority")} />
        </SimpleGrid>
        {needsValue && (
          <TextInput
            label="Match value"
            placeholder={
              form.values.match_type === "domain_suffix"
                ? ".corp.local"
                : form.values.match_type === "qtype"
                ? "PTR"
                : form.values.match_type === "category"
                ? "threat-intel"
                : "example.com"
            }
            {...form.getInputProps("match_value")}
          />
        )}
        <Select
          label="Target pool"
          placeholder="Select pool"
          data={pools.map((p) => ({ value: p.id, label: `${p.name} (${STRATEGY_LABELS[p.strategy] ?? p.strategy}, ${p.members.length} members)` }))}
          required
          {...form.getInputProps("pool_id")}
        />
        <Switch label="Enabled" {...form.getInputProps("enabled", { type: "checkbox" })} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

function RoutesTab() {
  const { data: tenants = [] } = useTenants();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const { data: routes = [], isLoading } = useUpstreamRoutes(tenantId ?? undefined);
  const { data: pools = [] } = useUpstreamPools();
  const createRoute = useCreateUpstreamRoute(tenantId ?? undefined);
  const updateRoute = useUpdateUpstreamRoute(tenantId ?? undefined);
  const deleteRoute = useDeleteUpstreamRoute(tenantId ?? undefined);
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [editTarget, setEditTarget] = useState<UpstreamRoute | null>(null);

  const poolName = (id: string) => pools.find((p) => p.id === id)?.name ?? id.slice(0, 8);

  function confirmDelete(r: UpstreamRoute) {
    modals.openConfirmModal({
      title: "Delete route",
      children: <Text size="sm">Delete route <strong>{r.name}</strong>?</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteRoute.mutate(r.id, {
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Routes map a (tenant, qname pattern) to an upstream pool. Evaluated in priority order.
        </Text>
      </Group>

      <Select
        label="Tenant"
        placeholder="Select a tenant to manage routes"
        data={tenants.map((t) => ({ value: t.id, label: t.name }))}
        value={tenantId}
        onChange={(v) => setTenantId(v ?? "")}
        clearable
      />

      {tenantId && (
        <>
          <Group justify="flex-end">
            <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openAdd}>Add route</Button>
          </Group>

          {isLoading && <Center h={100}><Loader size="sm" /></Center>}

          {!isLoading && routes.length === 0 && (
            <Card withBorder padding="md" style={{ borderStyle: "dashed" }}>
              <Text c="dimmed" size="sm" ta="center">No routes for this tenant. Add one to override the default forwarding.</Text>
            </Card>
          )}

          {!isLoading && routes.length > 0 && (
            <Table striped highlightOnHover withTableBorder withColumnBorders>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={60}>Priority</Table.Th>
                  <Table.Th>Name</Table.Th>
                  <Table.Th w={130}>Match</Table.Th>
                  <Table.Th>Value</Table.Th>
                  <Table.Th w={130}>Pool</Table.Th>
                  <Table.Th w={60}>On</Table.Th>
                  <Table.Th w={80} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {routes.map((rt) => (
                  <Table.Tr key={rt.id}>
                    <Table.Td>
                      <Badge size="sm" variant="outline">{rt.priority}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{rt.name}</Text>
                      {rt.tenant_id === null && <Badge size="xs" color="orange" variant="light">global</Badge>}
                    </Table.Td>
                    <Table.Td>
                      <Badge size="sm" variant="light">{rt.match_type}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Code>{rt.match_value ?? "—"}</Code>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{poolName(rt.pool_id)}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Switch
                        checked={rt.enabled}
                        size="sm"
                        onChange={() =>
                          updateRoute.mutate(
                            { id: rt.id, body: { enabled: !rt.enabled } },
                            { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
                          )
                        }
                      />
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} wrap="nowrap" justify="flex-end">
                        <ActionIcon size="sm" variant="subtle" onClick={() => setEditTarget(rt)}>
                          <IconEdit size={14} />
                        </ActionIcon>
                        <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(rt)}>
                          <IconTrash size={14} />
                        </ActionIcon>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}

          <Modal opened={addOpened} onClose={closeAdd} title="Add route" size="md">
            <RouteForm
              tenantId={tenantId}
              onSave={(values) =>
                createRoute.mutate(values, {
                  onSuccess: () => {
                    notifications.show({ message: "Route created", color: "green" });
                    closeAdd();
                  },
                  onError: (e) => notifications.show({ message: String(e), color: "red" }),
                })
              }
              onCancel={closeAdd}
              saving={createRoute.isPending}
            />
          </Modal>

          <Modal opened={!!editTarget} onClose={() => setEditTarget(null)} title="Edit route" size="md">
            {editTarget && (
              <RouteForm
                tenantId={tenantId}
                initial={editTarget}
                onSave={(values) =>
                  updateRoute.mutate(
                    { id: editTarget.id, body: values },
                    {
                      onSuccess: () => {
                        notifications.show({ message: "Route updated", color: "green" });
                        setEditTarget(null);
                      },
                      onError: (e) => notifications.show({ message: String(e), color: "red" }),
                    }
                  )
                }
                onCancel={() => setEditTarget(null)}
                saving={updateRoute.isPending}
              />
            )}
          </Modal>
        </>
      )}
    </Stack>
  );
}

// ── Policy tab ────────────────────────────────────────────────────────────────

function PolicyTab() {
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

// ── Health placeholder (Sprint 18) ────────────────────────────────────────────

function HealthTab() {
  return (
    <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
      <Stack align="center" gap="xs">
        <IconInfoCircle size={28} style={{ color: "var(--mantine-color-dimmed)" }} />
        <Text fw={500} c="dimmed">Upstream Health Dashboard</Text>
        <Text size="sm" c="dimmed" ta="center">
          Per-resolver health state timelines, latency P50/P95/P99 charts, error breakdown, and pool utilization will appear here once the Sprint 18 health monitor is active in the filter node.
        </Text>
      </Stack>
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function UpstreamPage() {
  return (
    <Stack gap="lg">
      <Stack gap={2}>
        <Group gap={8}>
          <IconServer size={22} />
          <Title order={2}>DNS Upstream</Title>
        </Group>
        <Text c="dimmed" size="sm">
          Manage upstream resolver profiles, HA pools, per-tenant routing rules, and forwarding policy. All config is delivered to filter nodes as signed upstream bundles.
        </Text>
      </Stack>

      <Tabs defaultValue="resolvers" keepMounted={false}>
        <Tabs.List mb="lg">
          <Tabs.Tab value="resolvers">Resolvers</Tabs.Tab>
          <Tabs.Tab value="pools">Pools</Tabs.Tab>
          <Tabs.Tab value="routes">Routes</Tabs.Tab>
          <Tabs.Tab value="policy">Tenant policy</Tabs.Tab>
          <Tabs.Tab value="health">Health</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="resolvers"><ResolversTab /></Tabs.Panel>
        <Tabs.Panel value="pools"><PoolsTab /></Tabs.Panel>
        <Tabs.Panel value="routes"><RoutesTab /></Tabs.Panel>
        <Tabs.Panel value="policy"><PolicyTab /></Tabs.Panel>
        <Tabs.Panel value="health"><HealthTab /></Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
