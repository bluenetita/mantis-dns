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

import { Badge, Button, Card, Group, NumberInput, Select, Stack, Switch, Text, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateUpstreamRoute,
  useDeleteUpstreamRoute,
  useTenants,
  useUpdateUpstreamRoute,
  useUpstreamPools,
  useUpstreamRoutes,
  type UpstreamRoute,
} from "../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../components/crud";
import { MATCH_TYPE_OPTIONS, STRATEGY_LABELS } from "./constants";

function RouteForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
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
        <Group grow>
          <Select label="Match type" data={MATCH_TYPE_OPTIONS} {...form.getInputProps("match_type")} />
          <NumberInput label="Priority" min={0} max={9999} description="Lower = evaluated first" {...form.getInputProps("priority")} />
        </Group>
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

export function RoutesTab() {
  const { data: tenants = [] } = useTenants();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const { data: routes = [], isLoading } = useUpstreamRoutes(tenantId ?? undefined);
  const { data: pools = [] } = useUpstreamPools();
  const createRoute = useCreateUpstreamRoute(tenantId ?? undefined);
  const updateRoute = useUpdateUpstreamRoute(tenantId ?? undefined);
  const deleteRoute = useDeleteUpstreamRoute(tenantId ?? undefined);
  const [editTarget, setEditTarget] = useState<UpstreamRoute | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditTarget(null); open(); };
  const openEdit = (r: UpstreamRoute) => { setEditTarget(r); open(); };

  const poolName = (id: string) => pools.find((p) => p.id === id)?.name ?? id.slice(0, 8);

  const save = (values: Partial<UpstreamRoute>) => {
    if (editTarget) {
      updateRoute.mutate(
        { id: editTarget.id, body: values },
        {
          onSuccess: () => {
            notifications.show({ message: "Route updated", color: "green" });
            close();
          },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }
      );
    } else {
      createRoute.mutate(values, {
        onSuccess: () => {
          notifications.show({ message: "Route created", color: "green" });
          close();
        },
        onError: (e) => notifications.show({ message: String(e), color: "red" }),
      });
    }
  };

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

  const columns: CrudColumn<UpstreamRoute>[] = [
    {
      key: "priority",
      header: "Priority",
      width: 60,
      render: (rt) => <Badge size="sm" variant="outline">{rt.priority}</Badge>,
    },
    {
      key: "name",
      header: "Name",
      render: (rt) => (
        <>
          <Text size="sm">{rt.name}</Text>
          {rt.tenant_id === null && <Badge size="xs" color="orange" variant="light">global</Badge>}
        </>
      ),
    },
    {
      key: "match_type",
      header: "Match",
      width: 130,
      render: (rt) => <Badge size="sm" variant="light">{rt.match_type}</Badge>,
    },
    {
      key: "match_value",
      header: "Value",
      render: (rt) => <code>{rt.match_value ?? "—"}</code>,
    },
    {
      key: "pool",
      header: "Pool",
      width: 130,
      render: (rt) => <Text size="sm">{poolName(rt.pool_id)}</Text>,
    },
    {
      key: "enabled",
      header: "On",
      width: 60,
      render: (rt) => (
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
      ),
    },
  ];

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
            <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>Add route</Button>
          </Group>

          <CrudTable
            data={routes}
            isLoading={isLoading}
            getRowKey={(rt) => rt.id}
            columns={columns}
            onEdit={openEdit}
            onDelete={confirmDelete}
            withTableBorder
            withColumnBorders
            emptyState={
              <Card withBorder padding="md" style={{ borderStyle: "dashed" }}>
                <Text c="dimmed" size="sm" ta="center">No routes for this tenant. Add one to override the default forwarding.</Text>
              </Card>
            }
          />

          <EntityModal
            opened={modalOpen}
            onClose={close}
            title={editTarget ? "Edit route" : "Add route"}
            size="md"
          >
            <RouteForm
              initial={editTarget ?? undefined}
              onSave={save}
              onCancel={close}
              saving={createRoute.isPending || updateRoute.isPending}
            />
          </EntityModal>
        </>
      )}
    </Stack>
  );
}
