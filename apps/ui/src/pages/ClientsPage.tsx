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
  Anchor,
  Badge,
  Breadcrumbs,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Modal,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  TagsInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconEdit, IconTrash } from "@tabler/icons-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useClients, useDeleteClient, useRegisterClient, useTenants } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import type { components } from "../api/schema";

type ClientEntry = components["schemas"]["ClientOut"];

function EditClientForm({ tenantId, client, onDone }: { tenantId: string; client: ClientEntry; onDone: () => void }) {
  const registerClient = useRegisterClient(tenantId);
  const form = useForm({
    initialValues: {
      hostname: client.hostname ?? "",
      owner: client.owner ?? "",
      device_type: client.device_type ?? "",
      tags: client.tags ?? [],
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        registerClient.mutate(
          {
            ip: client.ip,
            body: {
              hostname: values.hostname.trim() || null,
              owner: values.owner.trim() || null,
              device_type: values.device_type.trim() || null,
              tags: values.tags,
            },
          },
          {
            onSuccess: () => {
              notifications.show({ message: `Client ${client.ip} registered`, color: "green" });
              onDone();
            },
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          }
        );
      })}
    >
      <Stack>
        <TextInput label="IP" value={client.ip} disabled />
        <TextInput label="Hostname" placeholder="fabio-laptop.corp.local" {...form.getInputProps("hostname")} />
        <TextInput label="Owner" placeholder="fabio@company.com" {...form.getInputProps("owner")} />
        <Select
          label="Device type"
          data={["laptop", "desktop", "server", "mobile", "iot"]}
          clearable
          {...form.getInputProps("device_type")}
        />
        <TagsInput label="Tags" placeholder="contractor, unmanaged, ..." {...form.getInputProps("tags")} />
        <Button type="submit" loading={registerClient.isPending}>
          Save
        </Button>
      </Stack>
    </form>
  );
}

export function ClientsPage() {
  const { tenantId } = useParams<{ tenantId: string }>();
  const { data: tenants } = useTenants();
  const [unregisteredOnly, setUnregisteredOnly] = useState(false);
  const { data: clients, isLoading, error } = useClients(tenantId, unregisteredOnly);
  const deleteClient = useDeleteClient(tenantId);
  const [editing, setEditing] = useState<ClientEntry | null>(null);
  const [editOpened, { open: openEdit, close: closeEdit }] = useDisclosure(false);
  const canWrite = useAuth().hasRole("operator");

  const tenant = tenants?.find((t) => t.id === tenantId);

  function edit(client: ClientEntry) {
    setEditing(client);
    openEdit();
  }

  function confirmDelete(client: ClientEntry) {
    modals.openConfirmModal({
      title: "Delete client",
      children: (
        <Text size="sm">
          Delete registry entry for {client.ip}
          {client.hostname ? ` (${client.hostname})` : ""}? It will reappear as "unregistered" the next time this IP
          sends a query.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteClient.mutate(client.ip, {
          onSuccess: () => notifications.show({ message: `Client ${client.ip} deleted`, color: "green" }),
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
        <Anchor component={Link} to={`/tenants/${tenantId}`}>
          {tenant?.name ?? tenantId}
        </Anchor>
        <Text>Clients</Text>
      </Breadcrumbs>

      <Group justify="space-between">
        <Title order={2}>Clients</Title>
        <Switch
          label="Unregistered only"
          checked={unregisteredOnly}
          onChange={(e) => setUnregisteredOnly(e.currentTarget.checked)}
        />
      </Group>
      <Text c="dimmed" size="sm">
        Client IPs are auto-discovered from DNS query telemetry (design.md §20.6). Register hostname/owner/tags so
        they carry through to SIEM exports instead of showing up as bare IPs.
      </Text>

      {clients?.length === 0 && (
        <Card withBorder padding="xl">
          <Text ta="center" c="dimmed">
            {unregisteredOnly ? "No unregistered clients." : "No clients seen yet — they appear here after the first DNS query from that IP."}
          </Text>
        </Card>
      )}

      {clients && clients.length > 0 && (
        <Table highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>IP</Table.Th>
              <Table.Th>Hostname</Table.Th>
              <Table.Th>Owner</Table.Th>
              <Table.Th>Device</Table.Th>
              <Table.Th>Tags</Table.Th>
              <Table.Th>Last seen</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {clients.map((c) => (
              <Table.Tr key={c.id}>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {c.ip}
                  </Text>
                </Table.Td>
                <Table.Td>{c.hostname ?? <Text c="dimmed">—</Text>}</Table.Td>
                <Table.Td>{c.owner ?? <Text c="dimmed">—</Text>}</Table.Td>
                <Table.Td>{c.device_type ?? <Text c="dimmed">—</Text>}</Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {c.tags.map((t) => (
                      <Badge key={t} size="xs" variant="light">
                        {t}
                      </Badge>
                    ))}
                  </Group>
                </Table.Td>
                <Table.Td>{new Date(c.last_seen).toLocaleString()}</Table.Td>
                <Table.Td>
                  {c.registered_at ? (
                    <Badge size="sm" color="green">
                      registered
                    </Badge>
                  ) : (
                    <Badge size="sm" color="gray">
                      unregistered
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  {canWrite && (
                    <Group gap="xs">
                      <Button size="xs" variant="default" leftSection={<IconEdit size={14} />} onClick={() => edit(c)}>
                        Edit
                      </Button>
                      <Button size="xs" variant="subtle" color="red" leftSection={<IconTrash size={14} />} onClick={() => confirmDelete(c)}>
                        Delete
                      </Button>
                    </Group>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}

      {tenantId && editing && (
        <Modal opened={editOpened} onClose={() => { closeEdit(); setEditing(null); }} title={`Edit client ${editing.ip}`}>
          <EditClientForm tenantId={tenantId} client={editing} onDone={closeEdit} />
        </Modal>
      )}
    </Stack>
  );
}
