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

import { Button, Group, Stack, Table, Title, Card, Text, Loader, Center, TextInput, Badge, Breadcrumbs, Anchor, Modal } from "@mantine/core";
import { useState } from "react";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPencil, IconPlus, IconTrash, IconUsers } from "@tabler/icons-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useCreateGroup, useDeleteGroup, useGroups, useRenameGroup, useTenants } from "../api/hooks";
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

function RenameGroupForm({
  tenantId,
  groupId,
  initialName,
  onDone,
}: {
  tenantId: string;
  groupId: string;
  initialName: string;
  onDone: () => void;
}) {
  const renameGroup = useRenameGroup(tenantId);
  const form = useForm({
    initialValues: { name: initialName },
    validate: {
      name: (v) => (v.trim().length < 2 ? "Name must be at least 2 characters" : null),
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        renameGroup.mutate(
          { groupId, body: { name: values.name } },
          {
            onSuccess: () => {
              notifications.show({ message: `Group renamed to "${values.name}"`, color: "green" });
              onDone();
            },
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          }
        );
      })}
    >
      <Stack>
        <TextInput label="Group name" required {...form.getInputProps("name")} />
        <Button type="submit" loading={renameGroup.isPending}>
          Save
        </Button>
      </Stack>
    </form>
  );
}

export function GroupsPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { data: tenants } = useTenants();
  const { data: groups, isLoading, error } = useGroups(tenantId);
  const deleteGroup = useDeleteGroup(tenantId);
  const navigate = useNavigate();

  const tenant = tenants?.find((t) => t.id === tenantId);
  const [createOpened, { open: openCreateModal, close: closeCreateModal }] = useDisclosure(false);
  const [editingGroup, setEditingGroup] = useState<{ id: string; name: string } | null>(null);
  const canWrite = useAuth().hasRole("operator");
  const canDelete = useAuth().hasRole("admin");

  function confirmDelete(groupId: string, name: string) {
    modals.openConfirmModal({
      title: "Delete group",
      children: <Text size="sm">Delete "{name}"? This removes its policy and block-page override.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteGroup.mutate(groupId, {
          onSuccess: () => notifications.show({ message: `Group "${name}" deleted`, color: "green" }),
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
              <Table.Th />
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
                <Table.Td onClick={(e) => e.stopPropagation()}>
                  <Group gap="xs" justify="flex-end">
                    {canWrite && (
                      <Button
                        variant="subtle"
                        size="xs"
                        leftSection={<IconPencil size={14} />}
                        onClick={() => setEditingGroup({ id: g.id, name: g.name })}
                      >
                        Rename
                      </Button>
                    )}
                    {canDelete && (
                      <Button
                        variant="subtle"
                        color="red"
                        size="xs"
                        leftSection={<IconTrash size={14} />}
                        onClick={() => confirmDelete(g.id, g.name)}
                      >
                        Delete
                      </Button>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {tenantId && editingGroup && (
        <Modal opened onClose={() => setEditingGroup(null)} title="Rename group">
          <RenameGroupForm
            tenantId={tenantId}
            groupId={editingGroup.id}
            initialName={editingGroup.name}
            onDone={() => setEditingGroup(null)}
          />
        </Modal>
      )}

      {tenantId && (
        <Modal opened={createOpened} onClose={closeCreateModal} title="New group">
          <CreateGroupForm tenantId={tenantId} onDone={closeCreateModal} />
        </Modal>
      )}
    </Stack>
  );
}
