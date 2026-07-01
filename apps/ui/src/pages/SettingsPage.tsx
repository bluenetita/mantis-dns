import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconInfoCircle, IconPlus, IconSend, IconTrash } from "@tabler/icons-react";
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
        try {
          new URL(v);
          return null;
        } catch {
          return "Must be a valid URL";
        }
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
        <TextInput label="URL" placeholder="https://splunk.internal:8088/services/collector" required {...form.getInputProps("url")} />
        <TextInput label="Signing secret" description="Used to HMAC-sign the X-Aegis-Signature header — share this with the SIEM side" required {...form.getInputProps("secret")} />
        <Select
          label="Format"
          data={[
            { value: "json", label: "JSON" },
            { value: "cef", label: "CEF" },
          ]}
          {...form.getInputProps("format")}
        />
        <Select
          label="Decision filter"
          data={[
            { value: "all", label: "All queries" },
            { value: "block", label: "Blocked only" },
            { value: "allow", label: "Allowed only" },
          ]}
          {...form.getInputProps("filter_decision")}
        />
        <NumberInput label="Delivery interval (seconds)" min={5} {...form.getInputProps("flush_interval_s")} />
        <Button type="submit" loading={createWebhook.isPending}>
          Add webhook
        </Button>
      </Stack>
    </form>
  );
}

function SiemSection() {
  const { data: webhooks, isLoading } = useSiemWebhooks();
  const updateWebhook = useUpdateSiemWebhook();
  const deleteWebhook = useDeleteSiemWebhook();
  const testWebhook = useTestSiemWebhook();
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);

  function toggleEnabled(webhook: SiemWebhook) {
    updateWebhook.mutate(
      { webhookId: webhook.id, body: { enabled: !webhook.enabled } },
      { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
    );
  }

  function test(webhook: SiemWebhook) {
    testWebhook.mutate(webhook.id, {
      onSuccess: (result) =>
        notifications.show({
          message: result.success
            ? `${webhook.name}: test event delivered (HTTP ${result.status_code})`
            : `${webhook.name}: delivery failed — ${result.error}`,
          color: result.success ? "green" : "red",
        }),
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
    });
  }

  function confirmDelete(webhook: SiemWebhook) {
    modals.openConfirmModal({
      title: "Delete SIEM webhook",
      children: <Text size="sm">Delete "{webhook.name}"? This stops all delivery to {webhook.url}.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteWebhook.mutate(webhook.id, {
          onSuccess: () => notifications.show({ message: `Webhook "${webhook.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <Title order={4}>SIEM export</Title>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openAdd}>
          Add webhook
        </Button>
      </Group>
      <Text size="sm" c="dimmed" mb="sm">
        Push enriched DNS query events to a SIEM via signed webhook (design.md §20.4). Pull-based access is also
        available at <code>GET /api/v1/siem/events</code> for any SIEM that polls instead.
      </Text>

      {isLoading && (
        <Center h={100}>
          <Loader size="sm" />
        </Center>
      )}

      {!isLoading && webhooks?.length === 0 && (
        <Text c="dimmed" size="sm">
          No SIEM webhooks configured yet.
        </Text>
      )}

      {webhooks && webhooks.length > 0 && (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Format</Table.Th>
              <Table.Th>Filter</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Enabled</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {webhooks.map((w) => (
              <Table.Tr key={w.id}>
                <Table.Td>
                  <Text size="sm" fw={500}>
                    {w.name}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {w.url}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Badge size="sm" variant="light">
                    {w.format.toUpperCase()}
                  </Badge>
                </Table.Td>
                <Table.Td>{w.filter_decision}</Table.Td>
                <Table.Td>
                  {w.last_error ? (
                    <Badge size="sm" color="red">
                      {w.consecutive_failures} failures
                    </Badge>
                  ) : w.last_delivered_at ? (
                    <Badge size="sm" color="green">
                      delivered {new Date(w.last_delivered_at).toLocaleTimeString()}
                    </Badge>
                  ) : (
                    <Badge size="sm" color="gray">
                      no deliveries yet
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Switch checked={w.enabled} onChange={() => toggleEnabled(w)} />
                </Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    <Button size="xs" variant="default" leftSection={<IconSend size={14} />} onClick={() => test(w)} loading={testWebhook.isPending}>
                      Test
                    </Button>
                    <Button size="xs" variant="subtle" color="red" leftSection={<IconTrash size={14} />} onClick={() => confirmDelete(w)}>
                      Delete
                    </Button>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={addOpened} onClose={closeAdd} title="Add SIEM webhook" size="md">
        <AddWebhookForm onDone={closeAdd} />
      </Modal>
    </Card>
  );
}

export function SettingsPage() {
  const isAdmin = useAuth().hasRole("admin");

  return (
    <Stack>
      <Title order={2}>Settings</Title>

      <Card withBorder>
        <Title order={4} mb="sm">
          System
        </Title>
        <Table>
          <Table.Tbody>
            <Table.Tr>
              <Table.Td>Control plane API</Table.Td>
              <Table.Td>
                <Anchor href={API_BASE} target="_blank" rel="noreferrer">
                  {API_BASE}
                </Anchor>
              </Table.Td>
            </Table.Tr>
            <Table.Tr>
              <Table.Td>API docs (OpenAPI)</Table.Td>
              <Table.Td>
                <Anchor href={`${API_BASE}/docs`} target="_blank" rel="noreferrer">
                  {API_BASE}/docs
                </Anchor>
              </Table.Td>
            </Table.Tr>
            <Table.Tr>
              <Table.Td>Metrics (Prometheus)</Table.Td>
              <Table.Td>
                <Anchor href="http://localhost:9091" target="_blank" rel="noreferrer">
                  localhost:9091
                </Anchor>
              </Table.Td>
            </Table.Tr>
            <Table.Tr>
              <Table.Td>Dashboards (Grafana)</Table.Td>
              <Table.Td>
                <Anchor href="http://localhost:3000" target="_blank" rel="noreferrer">
                  localhost:3000
                </Anchor>
              </Table.Td>
            </Table.Tr>
          </Table.Tbody>
        </Table>
      </Card>

      <Card withBorder>
        <Group justify="space-between" mb="sm">
          <Title order={4}>Single sign-on (SSO)</Title>
          <Badge color="gray">Not configured</Badge>
        </Group>
        <Alert icon={<IconInfoCircle size={16} />} color="blue" variant="light">
          OIDC/SAML login isn't wired up yet — this requires backend work (design.md §9, Sprint 8: "Python OIDC/SSO
          integration, Keycloak target") plus a real identity provider to point at. There's nothing to configure
          here until that lands; this section isn't a working form because a non-functional SSO config screen
          would be worse than no screen at all.
        </Alert>
      </Card>

      <Card withBorder>
        <Group justify="space-between" mb="sm">
          <Title order={4}>Role-based access control</Title>
          <Badge color="green">Enabled</Badge>
        </Group>
        <Text size="sm" c="dimmed">
          JWT auth + a fixed role hierarchy (admin &gt; operator &gt; viewer) gate every mutating endpoint (Sprint 8,
          design.md §9). SSO/OIDC as a login method — rather than local email/password — is the remaining gap; user
          management is via <code>POST /api/v1/users</code> today (admin-only), no dedicated UI screen yet.
        </Text>
      </Card>

      {isAdmin && <SiemSection />}

      <Card withBorder>
        <Group justify="space-between" mb="sm">
          <Title order={4}>White-label / branding</Title>
          <Badge color="gray">Not built</Badge>
        </Group>
        <Text size="sm" c="dimmed">
          Per-tenant branding for MSP resale scenarios — design.md §19.2 (U11). Not started.
        </Text>
      </Card>
    </Stack>
  );
}
