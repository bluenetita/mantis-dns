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

import { useState } from "react";
import {
  Anchor,
  Badge,
  Button,
  Card,
  Center,
  CopyButton,
  Divider,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconChevronRight,
  IconCircleFilled,
  IconCopy,
  IconExternalLink,
  IconKey,
  IconLock,
  IconPlus,
  IconSend,
  IconServer,
  IconShield,
  IconTrash,
  IconUsers,
  IconWebhook,
} from "@tabler/icons-react";
import { useAuth } from "../auth/AuthContext";
import {
  useCreateSiemWebhook,
  useDeleteSiemWebhook,
  useSiemWebhooks,
  useTestSiemWebhook,
  useUpdateSiemWebhook,
} from "../api/hooks";
import type { components } from "../api/schema";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

type SiemWebhook = components["schemas"]["SiemWebhookOut"];

// ─── SIEM webhook form ────────────────────────────────────────────────────────

function AddWebhookForm({ onDone }: { onDone: () => void }) {
  const createWebhook = useCreateSiemWebhook();
  const form = useForm({
    initialValues: {
      name: "",
      url: "",
      secret: "",
      format: "json" as const,
      batch_size: 200,
      flush_interval_s: 30,
      filter_decision: "all" as const,
      enabled: true,
    },
    validate: {
      name: (v) => (v.trim().length < 2 ? "Required" : null),
      url: (v) => {
        try { new URL(v); return null; } catch { return "Must be a valid URL"; }
      },
      secret: (v) => (v.trim().length < 8 ? "At least 8 characters" : null),
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        createWebhook.mutate(values, {
          onSuccess: () => {
            notifications.show({ message: `Webhook "${values.name}" created`, color: "green" });
            onDone();
          },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        });
      })}
    >
      <Stack>
        <TextInput label="Name" placeholder="Splunk HEC prod" required {...form.getInputProps("name")} />
        <TextInput label="Endpoint URL" placeholder="https://splunk.internal:8088/services/collector" required {...form.getInputProps("url")} />
        <TextInput label="Signing secret" description="HMAC-signs the X-Mantis-Signature header — share with the SIEM side" required {...form.getInputProps("secret")} />
        <SimpleGrid cols={2}>
          <Select label="Format" data={[{ value: "json", label: "JSON" }, { value: "cef", label: "CEF (ArcSight)" }]} {...form.getInputProps("format")} />
          <Select
            label="Event filter"
            data={[
              { value: "all", label: "All queries" },
              { value: "block", label: "Blocked only" },
              { value: "allow", label: "Allowed only" },
            ]}
            {...form.getInputProps("filter_decision")}
          />
        </SimpleGrid>
        <SimpleGrid cols={2}>
          <NumberInput label="Batch size" min={1} max={1000} {...form.getInputProps("batch_size")} />
          <NumberInput label="Flush interval (s)" min={5} {...form.getInputProps("flush_interval_s")} />
        </SimpleGrid>
        <Group justify="flex-end">
          <Button variant="default" onClick={onDone}>Cancel</Button>
          <Button type="submit" loading={createWebhook.isPending}>Add webhook</Button>
        </Group>
      </Stack>
    </form>
  );
}

// ─── SIEM section ─────────────────────────────────────────────────────────────

function SiemSection() {
  const { data: webhooks, isLoading } = useSiemWebhooks();
  const updateWebhook = useUpdateSiemWebhook();
  const deleteWebhook = useDeleteSiemWebhook();
  const testWebhook = useTestSiemWebhook();
  const [testingId, setTestingId] = useState<string | null>(null);
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);

  function toggleEnabled(w: SiemWebhook) {
    updateWebhook.mutate(
      { webhookId: w.id, body: { enabled: !w.enabled } },
      { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
    );
  }

  function test(w: SiemWebhook) {
    setTestingId(w.id);
    testWebhook.mutate(w.id, {
      onSuccess: (r) =>
        notifications.show({
          message: r.success
            ? `${w.name}: delivered (HTTP ${r.status_code})`
            : `${w.name}: failed — ${r.error}`,
          color: r.success ? "green" : "red",
        }),
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
      onSettled: () => setTestingId(null),
    });
  }

  function confirmDelete(w: SiemWebhook) {
    modals.openConfirmModal({
      title: "Delete SIEM webhook",
      children: <Text size="sm">Delete <strong>{w.name}</strong>? This stops all delivery to {w.url}.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteWebhook.mutate(w.id, {
          onSuccess: () => notifications.show({ message: `Webhook "${w.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Stack gap={2}>
          <Group gap={8}>
            <ThemeIcon size="sm" variant="light" color="violet"><IconWebhook size={14} /></ThemeIcon>
            <Text fw={600}>SIEM webhooks</Text>
          </Group>
          <Text size="xs" c="dimmed">
            Push enriched DNS events to Splunk, Microsoft Sentinel, or any HTTP collector. Pull-based access via <code>GET /api/v1/siem/events</code>.
          </Text>
        </Stack>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openAdd}>
          Add webhook
        </Button>
      </Group>

      {isLoading && <Center h={80}><Loader size="sm" /></Center>}

      {!isLoading && (!webhooks || webhooks.length === 0) && (
        <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
          <Text c="dimmed" size="sm" ta="center">No SIEM webhooks configured. Add one to start streaming DNS events.</Text>
        </Card>
      )}

      {webhooks && webhooks.length > 0 && (
        <Table striped highlightOnHover withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Destination</Table.Th>
              <Table.Th w={80}>Format</Table.Th>
              <Table.Th w={110}>Filter</Table.Th>
              <Table.Th w={160}>Last delivery</Table.Th>
              <Table.Th w={70}>On</Table.Th>
              <Table.Th w={130} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {webhooks.map((w) => (
              <Table.Tr key={w.id}>
                <Table.Td>
                  <Text size="sm" fw={500}>{w.name}</Text>
                  <Text size="xs" c="dimmed" ff="monospace">{w.url}</Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light">{w.format.toUpperCase()}</Badge>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{w.filter_decision}</Text>
                </Table.Td>
                <Table.Td>
                  {w.last_error ? (
                    <Badge size="sm" color="red">{w.consecutive_failures} failures</Badge>
                  ) : w.last_delivered_at ? (
                    <Badge size="sm" color="green">
                      {new Date(w.last_delivered_at).toLocaleTimeString()}
                    </Badge>
                  ) : (
                    <Badge size="sm" color="gray">no deliveries yet</Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Switch checked={w.enabled} onChange={() => toggleEnabled(w)} size="sm" />
                </Table.Td>
                <Table.Td>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    <Button size="xs" variant="default" leftSection={<IconSend size={12} />} onClick={() => test(w)} loading={testingId === w.id}>
                      Test
                    </Button>
                    <Button size="xs" variant="subtle" color="red" leftSection={<IconTrash size={12} />} onClick={() => confirmDelete(w)}>
                      Delete
                    </Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={addOpened} onClose={closeAdd} title="Add SIEM webhook" size="lg">
        <AddWebhookForm onDone={closeAdd} />
      </Modal>
    </Stack>
  );
}

// ─── Endpoint row ─────────────────────────────────────────────────────────────

function EndpointRow({ label, url, description }: { label: string; url: string; description: string }) {
  return (
    <Group justify="space-between" wrap="nowrap" py={10}>
      <Stack gap={2} style={{ flex: 1, minWidth: 0 }}>
        <Text size="sm" fw={500}>{label}</Text>
        <Text size="xs" c="dimmed">{description}</Text>
      </Stack>
      <Group gap={6} wrap="nowrap">
        <Text size="xs" ff="monospace" c="dimmed" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {url}
        </Text>
        <CopyButton value={url} timeout={1500}>
          {({ copied, copy }) => (
            <Tooltip label={copied ? "Copied" : "Copy URL"} withArrow>
              <Button size="xs" variant="subtle" color={copied ? "teal" : "gray"} onClick={copy} px={6}>
                {copied ? <IconCheck size={12} /> : <IconCopy size={12} />}
              </Button>
            </Tooltip>
          )}
        </CopyButton>
        <Anchor href={url} target="_blank" rel="noreferrer">
          <Button size="xs" variant="default" rightSection={<IconExternalLink size={12} />}>Open</Button>
        </Anchor>
      </Group>
    </Group>
  );
}

// ─── Role capability table ────────────────────────────────────────────────────

const CAPABILITIES = [
  { capability: "View dashboard & analytics",  admin: true, operator: true,  viewer: true  },
  { capability: "View tenants, groups, feeds", admin: true, operator: true,  viewer: true  },
  { capability: "View DNS zones & records",    admin: true, operator: true,  viewer: true  },
  { capability: "View audit log",              admin: true, operator: true,  viewer: false },
  { capability: "Edit tenants & groups",       admin: true, operator: true,  viewer: false },
  { capability: "Edit policies & feeds",       admin: true, operator: true,  viewer: false },
  { capability: "Manage DNS zones & records",  admin: true, operator: true,  viewer: false },
  { capability: "Configure SIEM webhooks",     admin: true, operator: false, viewer: false },
  { capability: "Manage users",                admin: true, operator: false, viewer: false },
  { capability: "System settings",             admin: true, operator: false, viewer: false },
];

function Cap({ yes }: { yes: boolean }) {
  return yes
    ? <IconCircleFilled size={12} style={{ color: "var(--mantine-color-teal-6)" }} />
    : <IconCircleFilled size={12} style={{ color: "var(--mantine-color-dark-4)" }} />;
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function SettingsPage() {
  const { hasRole } = useAuth();
  const isAdmin = hasRole("admin");

  return (
    <Stack gap="lg">
      <Stack gap={2}>
        <Title order={2}>Settings</Title>
        <Text c="dimmed" size="sm">System configuration, security, and integrations.</Text>
      </Stack>

      <Tabs defaultValue="system" keepMounted={false}>
        <Tabs.List mb="lg">
          <Tabs.Tab value="system"       leftSection={<IconServer size={15} />}>System</Tabs.Tab>
          <Tabs.Tab value="security"     leftSection={<IconShield size={15} />}>Security</Tabs.Tab>
          <Tabs.Tab value="integrations" leftSection={<IconWebhook size={15} />}>Integrations</Tabs.Tab>
        </Tabs.List>

        {/* ── System tab ── */}
        <Tabs.Panel value="system">
          <Stack gap="md">
            {/* Platform */}
            <Card withBorder padding="md">
              <Group gap={8} mb="md">
                <ThemeIcon size="sm" variant="light" color="blue"><IconServer size={14} /></ThemeIcon>
                <Text fw={600}>Platform</Text>
              </Group>
              <SimpleGrid cols={{ base: 1, sm: 3 }}>
                {[
                  { label: "Product",     value: "Mantis-DNS" },
                  { label: "Control API", value: "FastAPI / Python" },
                  { label: "Filter node", value: "Rust (mantis-filter)" },
                  { label: "UI",          value: "React + Mantine 9" },
                  { label: "Auth",        value: "JWT (HS256)" },
                  { label: "Database",    value: "PostgreSQL 17 (psycopg3)" },
                ].map(({ label, value }) => (
                  <Stack key={label} gap={2}>
                    <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>{label}</Text>
                    <Text size="sm">{value}</Text>
                  </Stack>
                ))}
              </SimpleGrid>
            </Card>

            {/* Infrastructure endpoints */}
            <Card withBorder padding="md">
              <Group gap={8} mb="xs">
                <ThemeIcon size="sm" variant="light" color="blue"><IconServer size={14} /></ThemeIcon>
                <Text fw={600}>Infrastructure endpoints</Text>
              </Group>
              <Text size="xs" c="dimmed" mb="sm">Service URLs for this deployment.</Text>

              <Stack gap={0} style={{ borderTop: "1px solid var(--mantine-color-dark-4)" }}>
                {[
                  { label: "Control plane API",  url: API_BASE,             description: "FastAPI REST API — all management operations" },
                  { label: "OpenAPI / Swagger",  url: `${API_BASE}/docs`,   description: "Interactive API documentation" },
                  { label: "ReDoc reference",    url: `${API_BASE}/redoc`,  description: "Structured API reference" },
                ].map((ep, i, arr) => (
                  <div key={ep.label} style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--mantine-color-dark-4)" : undefined }}>
                    <EndpointRow {...ep} />
                  </div>
                ))}
              </Stack>
            </Card>
          </Stack>
        </Tabs.Panel>

        {/* ── Security tab ── */}
        <Tabs.Panel value="security">
          <Stack gap="md">
            {/* RBAC */}
            <Card withBorder padding="md">
              <Group justify="space-between" mb="md">
                <Group gap={8}>
                  <ThemeIcon size="sm" variant="light" color="teal"><IconUsers size={14} /></ThemeIcon>
                  <Text fw={600}>Role-based access control</Text>
                </Group>
                <Badge color="teal">Active</Badge>
              </Group>
              <Text size="xs" c="dimmed" mb="md">
                JWT-authenticated role hierarchy. Every mutating API endpoint is gated by role. Manage users via the{" "}
                <Anchor href="/users" size="xs">Users page</Anchor>.
              </Text>

              <Table withTableBorder withColumnBorders>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Capability</Table.Th>
                    <Table.Th w={90} style={{ textAlign: "center" }}>
                      <Badge color="red" size="sm">Admin</Badge>
                    </Table.Th>
                    <Table.Th w={90} style={{ textAlign: "center" }}>
                      <Badge color="blue" size="sm">Operator</Badge>
                    </Table.Th>
                    <Table.Th w={90} style={{ textAlign: "center" }}>
                      <Badge color="gray" size="sm">Viewer</Badge>
                    </Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {CAPABILITIES.map((row) => (
                    <Table.Tr key={row.capability}>
                      <Table.Td><Text size="sm">{row.capability}</Text></Table.Td>
                      <Table.Td style={{ textAlign: "center" }}><Cap yes={row.admin} /></Table.Td>
                      <Table.Td style={{ textAlign: "center" }}><Cap yes={row.operator} /></Table.Td>
                      <Table.Td style={{ textAlign: "center" }}><Cap yes={row.viewer} /></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Card>

            {/* SSO */}
            <Card withBorder padding="md">
              <Group justify="space-between" mb="md">
                <Group gap={8}>
                  <ThemeIcon size="sm" variant="light" color="violet"><IconKey size={14} /></ThemeIcon>
                  <Text fw={600}>Single sign-on (SSO / OIDC)</Text>
                </Group>
                <Badge color="gray" variant="outline">Planned — Sprint 8</Badge>
              </Group>
              <Text size="xs" c="dimmed" mb="md">
                OIDC/SAML integration with Keycloak, Okta, or Azure AD. Requires backend work (design.md §9).
                Fields below are a preview of the configuration surface.
              </Text>

              <Stack gap="sm" style={{ opacity: 0.45, pointerEvents: "none", userSelect: "none" }}>
                <SimpleGrid cols={2}>
                  <TextInput label="Issuer URL" placeholder="https://keycloak.corp.local/realms/mantis" disabled />
                  <TextInput label="Client ID" placeholder="mantis-dns" disabled />
                </SimpleGrid>
                <TextInput label="Client secret" placeholder="••••••••••••••••" disabled />
                <SimpleGrid cols={2}>
                  <TextInput label="Redirect URI" placeholder={`${window.location.origin}/auth/callback`} disabled />
                  <Select label="Claim mapping (role)" data={["groups", "roles", "mantis_role"]} disabled />
                </SimpleGrid>
                <Group>
                  <Button size="sm" disabled leftSection={<IconLock size={14} />}>Save SSO configuration</Button>
                  <Button size="sm" variant="default" disabled>Test connection</Button>
                </Group>
              </Stack>
            </Card>

            {/* Password policy */}
            <Card withBorder padding="md">
              <Group justify="space-between" mb="md">
                <Group gap={8}>
                  <ThemeIcon size="sm" variant="light" color="orange"><IconLock size={14} /></ThemeIcon>
                  <Text fw={600}>Password policy</Text>
                </Group>
                <Badge color="orange">Local accounts only</Badge>
              </Group>
              <Stack gap={4}>
                {[
                  "Minimum 12 characters",
                  "No maximum length limit",
                  "Passwords are bcrypt-hashed (cost 12)",
                  "No password rotation enforcement (planned for Sprint 9)",
                ].map((rule) => (
                  <Group key={rule} gap={8} wrap="nowrap">
                    <IconChevronRight size={12} style={{ color: "var(--mantine-color-dimmed)", flexShrink: 0 }} />
                    <Text size="sm" c="dimmed">{rule}</Text>
                  </Group>
                ))}
              </Stack>
            </Card>
          </Stack>
        </Tabs.Panel>

        {/* ── Integrations tab ── */}
        <Tabs.Panel value="integrations">
          <Stack gap="md">
            {isAdmin ? (
              <Card withBorder padding="md">
                <SiemSection />
              </Card>
            ) : (
              <Card withBorder padding="md">
                <Text c="dimmed" size="sm">Admin role required to manage integrations.</Text>
              </Card>
            )}

            {/* API access */}
            <Card withBorder padding="md">
              <Group justify="space-between" mb="md">
                <Group gap={8}>
                  <ThemeIcon size="sm" variant="light" color="blue"><IconKey size={14} /></ThemeIcon>
                  <Text fw={600}>API access</Text>
                </Group>
                <Badge color="gray" variant="outline">API keys — Planned</Badge>
              </Group>
              <Text size="xs" c="dimmed" mb="sm">
                Currently the API is authenticated via the same JWT tokens issued at login (Bearer header).
                Dedicated long-lived API keys for service accounts are planned for Sprint 9.
              </Text>
              <Divider my="sm" />
              <Group gap="md">
                <Stack gap={2}>
                  <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>Authentication</Text>
                  <Text size="sm">Bearer JWT (Authorization header)</Text>
                </Stack>
                <Stack gap={2}>
                  <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>Token expiry</Text>
                  <Text size="sm">8 hours</Text>
                </Stack>
                <Stack gap={2}>
                  <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>Docs</Text>
                  <Anchor href={`${API_BASE}/docs`} size="sm" target="_blank" rel="noreferrer">
                    {API_BASE}/docs
                  </Anchor>
                </Stack>
              </Group>
            </Card>
          </Stack>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
