import { Alert, Anchor, Badge, Card, Group, Stack, Table, Text, Title } from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export function SettingsPage() {
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
          <Badge color="gray">Not configured</Badge>
        </Group>
        <Text size="sm" c="dimmed">
          Today every API call is unauthenticated and unrestricted — anyone who can reach the control plane has
          full access. RBAC roles (super-admin, tenant-admin, policy-author, auditor) are scoped in design.md §19.2
          (U2) and depend on SSO landing first.
        </Text>
      </Card>

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
