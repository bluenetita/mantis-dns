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
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  MultiSelect,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconBolt, IconPlus } from "@tabler/icons-react";
import { useState } from "react";
import {
  useCreateUpstreamResolver,
  useDeleteUpstreamResolver,
  useProbeUpstreamResolver,
  useUpdateUpstreamResolver,
  useUpstreamResolvers,
  type UpstreamResolver,
} from "../../api/hooks";
import { CrudTable, EntityModal, type CrudColumn } from "../../components/crud";
import { DNSSEC_OPTIONS } from "./constants";

function ResolverForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial?: Partial<UpstreamResolver>;
  onSave: (values: Partial<UpstreamResolver>) => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const form = useForm({
    initialValues: {
      name: initial?.name ?? "",
      protocol: initial?.protocol ?? "dot",
      address: initial?.address ?? "",
      port: initial?.port ?? 853,
      tls_hostname: initial?.tls_hostname ?? "",
      dnssec_validation: initial?.dnssec_validation ?? "opportunistic",
      qname_minimization: initial?.qname_minimization ?? true,
      edns_client_subnet: initial?.edns_client_subnet ?? false,
      timeout_ms: initial?.timeout_ms ?? 5000,
      max_retries: initial?.max_retries ?? 2,
      connect_timeout_ms: initial?.connect_timeout_ms ?? 3000,
      tags: initial?.tags ?? [],
      enabled: initial?.enabled ?? true,
    },
    validate: {
      name: (v) => (!v.trim() ? "Required" : null),
      address: (v) => (!v.trim() ? "Required" : null),
      port: (v) => (v < 1 || v > 65535 ? "1–65535" : null),
    },
  });

  const needsTls = ["dot", "doh"].includes(form.values.protocol);

  function submit(values: typeof form.values) {
    const out: Partial<UpstreamResolver> = {
      ...values,
      tls_hostname: needsTls && values.tls_hostname ? values.tls_hostname : undefined,
    };
    onSave(out);
  }

  return (
    <form onSubmit={form.onSubmit(submit)}>
      <Stack>
        <TextInput label="Name" placeholder="Cloudflare DoT #1" required {...form.getInputProps("name")} />
        <SimpleGrid cols={2}>
          <Select
            label="Protocol"
            data={[
              { value: "dot", label: "DNS-over-TLS (DoT)" },
              { value: "doh", label: "DNS-over-HTTPS (DoH)" },
              { value: "do53", label: "Plain DNS (do53)" },
            ]}
            {...form.getInputProps("protocol")}
          />
          <NumberInput label="Port" min={1} max={65535} {...form.getInputProps("port")} />
        </SimpleGrid>
        <SimpleGrid cols={needsTls ? 2 : 1}>
          <TextInput label="Address" placeholder="1.1.1.1" required {...form.getInputProps("address")} />
          {needsTls && (
            <TextInput
              label="TLS hostname (SNI)"
              placeholder="cloudflare-dns.com"
              description="Defaults to Address if blank"
              {...form.getInputProps("tls_hostname")}
            />
          )}
        </SimpleGrid>
        <Select label="DNSSEC validation" data={DNSSEC_OPTIONS} {...form.getInputProps("dnssec_validation")} />
        <SimpleGrid cols={3}>
          <NumberInput label="Timeout (ms)" min={100} max={30000} {...form.getInputProps("timeout_ms")} />
          <NumberInput label="Retries" min={0} max={5} {...form.getInputProps("max_retries")} />
          <NumberInput label="Connect timeout (ms)" min={100} max={15000} {...form.getInputProps("connect_timeout_ms")} />
        </SimpleGrid>
        <SimpleGrid cols={2}>
          <Checkbox label="QNAME minimization" {...form.getInputProps("qname_minimization", { type: "checkbox" })} />
          <Checkbox label="EDNS Client Subnet" {...form.getInputProps("edns_client_subnet", { type: "checkbox" })} />
        </SimpleGrid>
        <MultiSelect
          label="Tags"
          placeholder="public, internal, threat-intel…"
          data={["public", "internal", "threat-intel", "doh", "do53"]}
          searchable
          {...form.getInputProps("tags")}
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

export function ResolversTab() {
  const { data: resolvers = [], isLoading } = useUpstreamResolvers();
  const createResolver = useCreateUpstreamResolver();
  const updateResolver = useUpdateUpstreamResolver();
  const deleteResolver = useDeleteUpstreamResolver();
  const probeResolver = useProbeUpstreamResolver();
  const [editTarget, setEditTarget] = useState<UpstreamResolver | null>(null);
  const [modalOpen, { open, close }] = useDisclosure(false);
  const [probingId, setProbingId] = useState<string | null>(null);

  const openCreate = () => { setEditTarget(null); open(); };
  const openEdit = (r: UpstreamResolver) => { setEditTarget(r); open(); };

  const save = (values: Partial<UpstreamResolver>) => {
    if (editTarget) {
      updateResolver.mutate(
        { id: editTarget.id, body: values },
        {
          onSuccess: () => {
            notifications.show({ message: "Resolver updated", color: "green" });
            close();
          },
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }
      );
    } else {
      createResolver.mutate(values, {
        onSuccess: (r) => {
          notifications.show({ message: `Resolver "${r.name}" created`, color: "green" });
          close();
        },
        onError: (e) => notifications.show({ message: String(e), color: "red" }),
      });
    }
  };

  function probe(r: UpstreamResolver) {
    setProbingId(r.id);
    probeResolver.mutate(r.id, {
      onSuccess: (result) => {
        if (result.ok) {
          notifications.show({
            color: "green",
            title: `${r.name} — OK`,
            message: `${result.latency_ms?.toFixed(0)} ms · ${result.response_code}${result.dnssec_ad ? " · AD" : ""}${result.tls_subject ? ` · ${result.tls_subject}` : ""}`,
          });
        } else {
          notifications.show({
            color: "red",
            title: `${r.name} — Failed`,
            message: result.error ?? "Unknown error",
          });
        }
      },
      onError: (e) => notifications.show({ color: "red", message: String(e) }),
      onSettled: () => setProbingId(null),
    });
  }

  function confirmDelete(r: UpstreamResolver) {
    modals.openConfirmModal({
      title: "Delete resolver",
      children: <Text size="sm">Delete <strong>{r.name}</strong>? Any pools referencing it will lose this member.</Text>,
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteResolver.mutate(r.id, {
          onSuccess: () => notifications.show({ message: `Resolver "${r.name}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  const columns: CrudColumn<UpstreamResolver>[] = [
    {
      key: "name",
      header: "Name",
      render: (r) => (
        <>
          <Text size="sm" fw={500}>{r.name}</Text>
          {r.tags.length > 0 && (
            <Group gap={4} mt={2}>
              {r.tags.map((t) => (
                <Badge key={t} size="xs" variant="outline" color="gray">{t}</Badge>
              ))}
            </Group>
          )}
        </>
      ),
    },
    {
      key: "protocol",
      header: "Protocol",
      width: 100,
      render: (r) => (
        <Badge size="sm" variant="light" color={r.protocol === "dot" ? "blue" : r.protocol === "doh" ? "violet" : "gray"}>
          {r.protocol.toUpperCase()}
        </Badge>
      ),
    },
    {
      key: "address",
      header: "Address",
      render: (r) => (
        <>
          <code>{r.address}:{r.port}</code>
          {r.tls_hostname && r.tls_hostname !== r.address && (
            <Text size="xs" c="dimmed">{r.tls_hostname}</Text>
          )}
        </>
      ),
    },
    {
      key: "dnssec",
      header: "DNSSEC",
      width: 120,
      render: (r) => <Text size="xs">{r.dnssec_validation}</Text>,
    },
    {
      key: "enabled",
      header: "On",
      width: 60,
      render: (r) => (
        <Switch
          checked={r.enabled}
          size="sm"
          onChange={() =>
            updateResolver.mutate(
              { id: r.id, body: { enabled: !r.enabled } },
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
          Named upstream DNS server profiles. Group them into pools for load-balancing and failover.
        </Text>
        <Button size="xs" leftSection={<IconPlus size={14} />} onClick={openCreate}>Add resolver</Button>
      </Group>

      <CrudTable
        data={resolvers}
        isLoading={isLoading}
        getRowKey={(r) => r.id}
        columns={columns}
        onEdit={openEdit}
        onDelete={confirmDelete}
        actionsWidth={140}
        withTableBorder
        withColumnBorders
        emptyState={
          <Card withBorder padding="lg" style={{ borderStyle: "dashed" }}>
            <Text c="dimmed" size="sm" ta="center">No resolvers configured. Add one to get started.</Text>
          </Card>
        }
        renderRowActions={(r) => (
          <Tooltip label="Live probe (SOA query)">
            <Button
              size="xs" variant="default"
              leftSection={<IconBolt size={12} />}
              loading={probingId === r.id}
              onClick={() => probe(r)}
            >
              Test
            </Button>
          </Tooltip>
        )}
      />

      <EntityModal
        opened={modalOpen}
        onClose={close}
        title={editTarget ? "Edit resolver" : "Add resolver"}
        size="lg"
      >
        <ResolverForm
          initial={editTarget ?? undefined}
          onSave={save}
          onCancel={close}
          saving={createResolver.isPending || updateResolver.isPending}
        />
      </EntityModal>
    </Stack>
  );
}
