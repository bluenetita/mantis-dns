import { Button, Group, Stack, Table, Title, Card, Text, Loader, Center, TextInput, Badge, Breadcrumbs, Anchor, Modal } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconUsers } from "@tabler/icons-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCreateGroup, useGroups, useTenants } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";

const CIDR_RE = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;

function CreateGroupForm({ tenantId, onDone }: { tenantId: string; onDone: () => void }) {
  const createGroup = useCreateGroup(tenantId);
  const form = useForm({
    initialValues: { name: "", vpn_subnet: "" },
    validate: {
      name: (v) => (v.trim().length < 2 ? "Name must be at least 2 characters" : null),
      vpn_subnet: (v) => (v.trim() === "" || CIDR_RE.test(v.trim()) ? null : "Must be a CIDR like 10.8.1.0/24"),
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        createGroup.mutate(
          { name: values.name, vpn_subnet: values.vpn_subnet.trim() || null },
          {
            onSuccess: () => {
              notifications.show({ message: `Group "${values.name}" created`, color: "green" });
              onDone();
            },
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          }
        );
      })}
    >
      <Stack>
        <TextInput label="Group name" placeholder="engineering" required {...form.getInputProps("name")} />
        <TextInput
          label="VPN subnet (CIDR)"
          description="OpenVPN AS/CE IP pool for this group — enables source-IP tenant routing (design.md §7.3)"
          placeholder="10.8.1.0/24"
          {...form.getInputProps("vpn_subnet")}
        />
        <Button type="submit" loading={createGroup.isPending}>
          Create group
        </Button>
      </Stack>
    </form>
  );
}

export function GroupsPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { data: tenants } = useTenants();
  const { data: groups, isLoading, error } = useGroups(tenantId);
  const navigate = useNavigate();

  const tenant = tenants?.find((t) => t.id === tenantId);
  const [createOpened, { open: openCreateModal, close: closeCreateModal }] = useDisclosure(false);
  const canWrite = useAuth().hasRole("operator");

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );
  if (error) return <Text c="red">{String(error)}</Text>;

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/tenants">
          Tenants
        </Anchor>
        <Text>{tenant?.name ?? tenantId}</Text>
      </Breadcrumbs>

      <Group justify="space-between">
        <Title order={2}>Groups</Title>
        <Group>
          <Button variant="default" leftSection={<IconUsers size={16} />} onClick={() => navigate(`/tenants/${tenantId}/clients`)}>
            Clients
          </Button>
          {canWrite && (
            <Button leftSection={<IconPlus size={16} />} onClick={openCreateModal}>
              New group
            </Button>
          )}
        </Group>
      </Group>

      {groups?.length === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            No groups yet. A group maps to an OpenVPN AS/CE user-group and carries its own DNS policy.
          </Text>
        </Card>
      )}

      {groups && groups.length > 0 && (
        <Table highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>VPN subnet</Table.Th>
              <Table.Th>Created</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {groups.map((g) => (
              <Table.Tr
                key={g.id}
                style={{ cursor: "pointer" }}
                onClick={() => navigate(`/tenants/${tenantId}/groups/${g.id}`)}
              >
                <Table.Td>{g.name}</Table.Td>
                <Table.Td>
                  {g.vpn_subnet ? <Badge variant="light">{g.vpn_subnet}</Badge> : <Text c="dimmed">not set</Text>}
                </Table.Td>
                <Table.Td>{new Date(g.created_at).toLocaleString()}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {tenantId && (
        <Modal opened={createOpened} onClose={closeCreateModal} title="New group">
          <CreateGroupForm tenantId={tenantId} onDone={closeCreateModal} />
        </Modal>
      )}
    </Stack>
  );
}
