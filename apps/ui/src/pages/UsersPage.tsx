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
  Center,
  Group,
  Loader,
  Modal,
  PasswordInput,
  Select,
  SimpleGrid,
  Stack,
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
import { IconEdit, IconPlus, IconTrash, IconUser } from "@tabler/icons-react";
import { useState } from "react";
import { useCreateUser, useDeleteUser, useUpdateUser, useUsers, useTenants } from "../api/hooks";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type User = components["schemas"]["UserOut"];

const ROLE_OPTIONS = [
  { value: "admin",    label: "Admin — full access, manage users" },
  { value: "operator", label: "Operator — read/write, no user management" },
  { value: "viewer",   label: "Viewer — read-only" },
];

const ROLE_COLOR: Record<string, string> = {
  admin: "red",
  operator: "blue",
  viewer: "gray",
};

// ─── Add user modal ───────────────────────────────────────────────────────────

function AddUserModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const createUser = useCreateUser();
  const { data: tenants = [] } = useTenants();
  const tenantOptions = [
    { value: "", label: "Global (no tenant restriction)" },
    ...tenants.map((t) => ({ value: t.id, label: t.name })),
  ];

  const form = useForm({
    initialValues: { email: "", password: "", role: "viewer", tenant_id: "" },
    validate: {
      email: (v) => (v.trim().length < 3 ? "Email is required" : null),
      password: (v) => (v.length < 12 ? "Minimum 12 characters" : null),
      role: (v) => (!v ? "Role is required" : null),
    },
  });

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={opened} onClose={handleClose} title="Add user" size="md">
      <form
        onSubmit={form.onSubmit((values) => {
          const body = { ...values, tenant_id: values.tenant_id || null };
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          createUser.mutate(body as any, {
            onSuccess: () => {
              notifications.show({ message: `User "${values.email}" created`, color: "green" });
              handleClose();
            },
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          });
        })}
      >
        <Stack>
          <TextInput
            label="Email"
            placeholder="user@corp.local"
            required
            {...form.getInputProps("email")}
          />
          <PasswordInput
            label="Password"
            description="Minimum 12 characters"
            required
            {...form.getInputProps("password")}
          />
          <Select
            label="Role"
            data={ROLE_OPTIONS}
            required
            {...form.getInputProps("role")}
          />
          <Select
            label="Tenant scope"
            description="Scoped users only see resources within their tenant"
            data={tenantOptions}
            {...form.getInputProps("tenant_id")}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={createUser.isPending}>Create user</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Edit user modal ──────────────────────────────────────────────────────────

function EditUserModal({ user, onClose }: { user: User | null; onClose: () => void }) {
  const updateUser = useUpdateUser();
  const { data: tenants = [] } = useTenants();
  const tenantOptions = [
    { value: "", label: "Global (no tenant restriction)" },
    ...tenants.map((t) => ({ value: t.id, label: t.name })),
  ];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const form = useForm({ initialValues: { role: user?.role ?? "viewer", tenant_id: (user as any)?.tenant_id ?? "" } });

  if (!user) return null;

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={!!user} onClose={handleClose} title={`Edit user: ${user.email}`} size="sm">
      <form
        onSubmit={form.onSubmit((values) => {
          const body = { role: values.role, tenant_id: values.tenant_id || null };
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          updateUser.mutate(
            { userId: user.id, body: body as any },
            {
              onSuccess: () => {
                notifications.show({ message: `User ${user.email} updated`, color: "green" });
                handleClose();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            }
          );
        })}
      >
        <Stack>
          <TextInput label="Email" value={user.email} disabled />
          <Select label="Role" data={ROLE_OPTIONS} required {...form.getInputProps("role")} />
          <Select
            label="Tenant scope"
            description="Scoped users only see resources within their tenant"
            data={tenantOptions}
            {...form.getInputProps("tenant_id")}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={updateUser.isPending}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function UsersPage() {
  const { data: users = [], isLoading } = useUsers();
  const deleteUser = useDeleteUser();
  const { user: currentUser, hasRole } = useAuth();
  const canWrite = hasRole("admin");
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [editUser, setEditUser] = useState<User | null>(null);

  const sorted = [...users].sort((a, b) => a.email.localeCompare(b.email));

  const byRole = (r: string) => users.filter((u) => u.role === r).length;

  function confirmDelete(u: User) {
    modals.openConfirmModal({
      title: "Delete user",
      children: (
        <Text size="sm">
          Delete <strong>{u.email}</strong>? They will immediately lose access.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteUser.mutate(u.id, {
          onSuccess: () => notifications.show({ message: `User "${u.email}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  if (isLoading) return <Center h={200}><Loader /></Center>;

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Stack gap={2}>
          <Title order={2}>User management</Title>
          <Text c="dimmed" size="sm">
            Manage local accounts and role assignments. SSO/OIDC integration is on the roadmap.
          </Text>
        </Stack>
        {canWrite && (
          <Button leftSection={<IconPlus size={16} />} onClick={openAdd}>
            Add user
          </Button>
        )}
      </Group>

      {/* KPIs */}
      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        {[
          { label: "Total users", value: users.length },
          { label: "Admins", value: byRole("admin") },
          { label: "Operators", value: byRole("operator") },
          { label: "Viewers", value: byRole("viewer") },
        ].map(({ label, value }) => (
          <Stack key={label} gap={2} style={{ borderLeft: "3px solid var(--mantine-color-blue-5)", paddingLeft: 12 }}>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>{label}</Text>
            <Text size="xl" fw={700} lh={1}>{value}</Text>
          </Stack>
        ))}
      </SimpleGrid>

      <Table striped highlightOnHover withTableBorder withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Email</Table.Th>
            <Table.Th w={130}>Role</Table.Th>
            <Table.Th w={160}>Tenant scope</Table.Th>
            <Table.Th w={110} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {sorted.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={4}>
                <Text c="dimmed" ta="center" py="md">No users found</Text>
              </Table.Td>
            </Table.Tr>
          )}
          {sorted.map((u) => {
            const isSelf = u.id === currentUser?.id;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const tenantId = (u as any).tenant_id as string | null | undefined;
            return (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Group gap={8} wrap="nowrap">
                    <IconUser size={14} style={{ color: "var(--mantine-color-dimmed)" }} />
                    <Text size="sm" fw={isSelf ? 600 : undefined}>
                      {u.email}
                    </Text>
                    {isSelf && (
                      <Badge size="xs" variant="outline" color="blue">you</Badge>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Badge color={ROLE_COLOR[u.role] ?? "gray"} variant="light" size="sm">
                    {u.role}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  {tenantId ? (
                    <Text size="xs" c="dimmed" style={{ fontFamily: "monospace" }}>{tenantId}</Text>
                  ) : (
                    <Text size="xs" c="dimmed">Global</Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    <Tooltip label="Edit user">
                      <ActionIcon size="sm" variant="subtle" onClick={() => setEditUser(u)}>
                        <IconEdit size={14} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label={isSelf ? "Cannot delete your own account" : "Delete"}>
                      <ActionIcon
                        size="sm" variant="subtle" color="red"
                        disabled={isSelf}
                        onClick={() => !isSelf && confirmDelete(u)}
                      >
                        <IconTrash size={14} />
                      </ActionIcon>
                    </Tooltip>
                  </Group>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>

      <Text size="xs" c="dimmed" ta="right">{users.length} user{users.length !== 1 ? "s" : ""}</Text>

      <AddUserModal opened={addOpened} onClose={closeAdd} />
      <EditUserModal key={editUser?.id ?? "none"} user={editUser} onClose={() => setEditUser(null)} />
    </Stack>
  );
}
