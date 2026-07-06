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

import { Badge, Button, Card, Group, NumberInput, Select, Stack, Text, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateUpstreamPool,
  useDeleteUpstreamPool,
  useUpdateUpstreamPool,
  useUpstreamPools,
  useUpstreamResolvers,
  type UpstreamPool,
} from "../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../components/crud";
import { STRATEGY_LABELS } from "./constants";

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
        <Group grow>
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
        </Group>
        <TextInput label="Probe domain" {...form.getInputProps("health_check_query")} />
        <Group grow>
          <NumberInput label="Unhealthy threshold" min={1} max={10} description="Failures before ejection" {...form.getInputProps("unhealthy_threshold")} />
          <NumberInput label="Healthy threshold" min={1} max={10} description="Successes before re-admission" {...form.getInputProps("healthy_threshold")} />
          <NumberInput label="Min healthy members" min={1} description="Alert + use fallback below this" {...form.getInputProps("min_healthy_members")} />
        </Group>
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>Cancel</Button>
          <Button type="submit" loading={saving}>Save</Button>
        </Group>
      </Stack>
    </form>
  );
}

export function PoolsTab() {
  const { data: pools = [], isLoading } = useUpstreamPools();
  const { data: resolvers = [] } = useUpstreamResolvers();
  const createPool = useCreateUpstreamPool();
  const updatePool = useUpdateUpstreamPool();
  const deletePool = useDeleteUpstreamPool();
  const [editTarget, setEditTarget] = useState<UpstreamPool | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);

  const openCreate = () => { setEditTarget(null); open(); };
  const openEdit = (p: UpstreamPool) => { setEditTarget(p); open(); };

  const resolverName = (id: string) =>
    resolvers.find((r) => r.id === id)?.name ?? id.slice(0, 8);

  const save = (values: Partial<UpstreamPool>) => {
    if (editTarget) {
      updatePool.mutate(
        { id: editTarget.id, body: values },
        {
          onSuccess: () => {
            notifications.show({ message: "Pool updated", color: "green" });
            close();
          },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }
      );
    } else {
      createPool.mutate(values, {
        onSuccess: (p) => {
          notifications.show({ message: `Pool "${p.name}" created`, color: "green" });
          close();
        },
        onError: (e) => notifications.show({ message: String(e), color: "red" }),
      });
    }
  };

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

  const columns: CrudColumn<UpstreamPool>[] = [
    { key: "name", header: "Pool", render: (p) => <Text size="sm" fw={500}>{p.name}</Text> },
    {
      key: "strategy",
      header: "Strategy",
      width: 130,
      render: (p) => <Badge size="sm" variant="light">{STRATEGY_LABELS[p.strategy] ?? p.strategy}</Badge>,
    },
    {
      key: "members",
      header: "Members",
      render: (p) => (
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
      ),
    },
    {
      key: "health_check",
      header: "Health check",
      width: 90,
      render: (p) => <Text size="xs">{p.health_check_interval_s}s / {p.health_check_timeout_ms}ms</Text>,
    },
  ];

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Pools group resolvers under a load-balancing / failover strategy. Assign pools to upstream routes.
        </Text>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>Add pool</Button>
      </Group>

      <CrudTable
        data={pools}
        isLoading={isLoading}
        getRowKey={(p) => p.id}
        columns={columns}
        onEdit={openEdit}
        onDelete={confirmDelete}
        withTableBorder
        withColumnBorders
        emptyState={
          <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
            <Text c="dimmed" size="sm" ta="center">No pools. Create resolvers first, then group them into pools.</Text>
          </Card>
        }
      />

      <EntityModal
        opened={modalOpen}
        onClose={close}
        title={editTarget ? "Edit pool" : "Add pool"}
        size="lg"
      >
        <PoolForm
          initial={editTarget ?? undefined}
          onSave={save}
          onCancel={close}
          saving={createPool.isPending || updatePool.isPending}
        />
      </EntityModal>
    </Stack>
  );
}
