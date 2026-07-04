import { Button, Group, Stack, Table, Title, Card, Text, Loader, Center, Modal } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { TextInput } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useNavigate } from "react-router-dom";
import { useCreateTenant, useDeleteTenant, useTenants } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";

function CreateTenantForm({ onDone }: { onDone: () => void }) {
  const createTenant = useCreateTenant();
  const form = useForm({
    initialValues: { name: "" },
    validate: {
      name: (v) => (v.trim().length < 2 ? "Name must be at least 2 characters" : null),
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        createTenant.mutate(values, {
          onSuccess: () => {
            notifications.show({ message: `Tenant "${values.name}" created`, color: "green" });
            onDone();
          },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        });
      })}
    >
      <Stack>
        <TextInput label="Tenant name" placeholder="acme-corp" required {...form.getInputProps("name")} />
        <Button type="submit" loading={createTenant.isPending}>
          Create tenant
        </Button>
      </Stack>
    </form>
  );
}

export function TenantsPage() {
  const { data: tenants, isLoading, error } = useTenants();
  const deleteTenant = useDeleteTenant();
  const navigate = useNavigate();
  const [createOpened, { open: openCreateModal, close: closeCreateModal }] = useDisclosure(false);
  const { hasRole } = useAuth();
  const canWrite = hasRole("operator");
  const canDelete = hasRole("admin");

  function confirmDelete(tenantId: string, name: string) {
    modals.openConfirmModal({
      title: "Delete tenant",
      children: <Text size="sm">Delete "{name}"? This removes all its groups and policies.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteTenant.mutate(tenantId, {
          onSuccess: () => notifications.show({ message: `Tenant "${name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );
  if (error) return <Text c="red">{String(error)}</Text>;

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Tenants</Title>
        {canWrite && (
          <Button leftSection={<IconPlus size={16} />} onClick={openCreateModal}>
            New tenant
          </Button>
        )}
      </Group>

      {tenants?.length === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            No tenants yet. Create one to start configuring DNS policy.
          </Text>
        </Card>
      )}

      {tenants && tenants.length > 0 && (
        <Table highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Created</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tenants.map((t) => (
              <Table.Tr key={t.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/tenants/${t.id}`)}>
                <Table.Td>{t.name}</Table.Td>
                <Table.Td>{new Date(t.created_at).toLocaleString()}</Table.Td>
                <Table.Td onClick={(e) => e.stopPropagation()}>
                  {canDelete && (
                    <Button
                      variant="subtle"
                      color="red"
                      size="xs"
                      leftSection={<IconTrash size={14} />}
                      onClick={() => confirmDelete(t.id, t.name)}
                    >
                      Delete
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      <Modal opened={createOpened} onClose={closeCreateModal} title="New tenant">
        <CreateTenantForm onDone={closeCreateModal} />
      </Modal>
    </Stack>
  );
}
