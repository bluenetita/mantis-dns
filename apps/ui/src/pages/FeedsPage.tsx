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
  Checkbox,
  CopyButton,
  Flex,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Text,
  Textarea,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCircleFilled,
  IconCopy,
  IconEdit,
  IconExternalLink,
  IconPlaylistAdd,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconTrash,
} from "@tabler/icons-react";
import { Fragment, useMemo, useState } from "react";
import { useCategories, useCreateFeed, useDeleteFeed, useFeeds, useIngestFeedNow, useUpdateFeed } from "../api/hooks";
import type { Category } from "../api/hooks";
import { categoryIcon, CATEGORY_GROUP_LABEL } from "../categoryIcons";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type Feed = components["schemas"]["FeedOut"];

// ─── helpers ────────────────────────────────────────────────────────────────

function categoryLabel(id: string, byId: Map<string, Category>): string {
  return byId.get(id)?.label ?? id.charAt(0).toUpperCase() + id.slice(1);
}

function categoryColor(id: string, byId: Map<string, Category>): string {
  return byId.get(id)?.color ?? "gray";
}

function feedStatus(f: Feed): { label: string; color: string } {
  if (!f.enabled) return { label: "Disabled", color: "gray" };
  if (f.last_domain_count === null || f.last_domain_count === undefined)
    return { label: "Pending", color: "yellow" };
  if (f.last_domain_count === 0) return { label: "Empty", color: "orange" };
  if (f.last_fetched_at) {
    const ageH = (Date.now() - new Date(f.last_fetched_at).getTime()) / 3_600_000;
    if (ageH > (f.interval_seconds / 3600) * 2) return { label: "Stale", color: "orange" };
  }
  return { label: "Active", color: "green" };
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "Just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function fmtInterval(secs: number): string {
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
}

function fmtDomains(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return n.toLocaleString();
}

// ─── KPI card ────────────────────────────────────────────────────────────────

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <Stack gap={2} style={{ borderLeft: "3px solid var(--mantine-color-blue-5)", paddingLeft: 12 }}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} style={{ letterSpacing: "0.05em" }}>
        {label}
      </Text>
      <Text size="xl" fw={700} lh={1}>
        {value}
      </Text>
      {sub && <Text size="xs" c="dimmed">{sub}</Text>}
    </Stack>
  );
}

// ─── Add Feed form ────────────────────────────────────────────────────────────

const FORMAT_OPTIONS = [
  { value: "hostfile", label: "hostfile  (0.0.0.0 domain lines)" },
  { value: "domain-list", label: "domain-list  (plain domain lines)" },
];

function AddFeedModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const createFeed = useCreateFeed();
  const form = useForm({
    initialValues: {
      id: "",
      category_id: "",
      url: "",
      format: "domain-list",
      interval_seconds: 86400,
      provider: "",
      license: "",
    },
    validate: {
      id: (v) => (v.trim().length < 2 ? "Required — must be unique" : null),
      category_id: (v) => (v.trim().length < 2 ? "Required" : null),
      url: (v) => {
        try { new URL(v); return null; } catch { return "Must be a valid URL"; }
      },
    },
  });

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={opened} onClose={handleClose} title="Add custom feed" size="lg">
      <form
        onSubmit={form.onSubmit((values) =>
          createFeed.mutate(
            { ...values, enabled: true },
            {
              onSuccess: () => {
                notifications.show({ message: `Feed "${values.id}" added`, color: "green" });
                handleClose();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            }
          )
        )}
      >
        <Stack>
          <SimpleGrid cols={2}>
            <TextInput label="Feed ID" placeholder="acme-malware-block" required {...form.getInputProps("id")} />
            <TextInput label="Category" placeholder="malware, adult, gambling …" required {...form.getInputProps("category_id")} />
          </SimpleGrid>
          <TextInput label="Source URL" placeholder="https://feeds.example.com/list.txt" required {...form.getInputProps("url")} />
          <SimpleGrid cols={2}>
            <Select label="Format" data={FORMAT_OPTIONS} {...form.getInputProps("format")} />
            <NumberInput label="Refresh interval (seconds)" min={60} {...form.getInputProps("interval_seconds")} />
          </SimpleGrid>
          <SimpleGrid cols={2}>
            <TextInput label="Provider" placeholder="Acme Threat Intel" {...form.getInputProps("provider")} />
            <TextInput label="License" placeholder="MIT, CC0, commercial …" {...form.getInputProps("license")} />
          </SimpleGrid>
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={createFeed.isPending}>Add feed</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Bulk Add Feed modal ────────────────────────────────────────────────────────

function parseBulkLines(text: string): { id: string; url: string }[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [id, url] = line.split(",").map((s) => s.trim());
      return { id: id ?? "", url: url ?? "" };
    });
}

function BulkAddFeedModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const createFeed = useCreateFeed();
  const [submitting, setSubmitting] = useState(false);
  const form = useForm({
    initialValues: {
      category_id: "",
      format: "domain-list",
      interval_seconds: 86400,
      provider: "",
      license: "",
      lines: "",
    },
    validate: {
      category_id: (v) => (v.trim().length < 2 ? "Required" : null),
      lines: (v) => {
        const entries = parseBulkLines(v);
        if (entries.length === 0) return "Enter at least one feed";
        const invalid = entries.filter((e) => !e.id || !e.url);
        if (invalid.length > 0) return `${invalid.length} line(s) missing "id,url" — one feed per line`;
        return null;
      },
    },
  });

  function handleClose() {
    form.reset();
    onClose();
  }

  async function handleSubmit(values: typeof form.values) {
    const entries = parseBulkLines(values.lines);
    setSubmitting(true);
    const results = await Promise.allSettled(
      entries.map((e) =>
        createFeed.mutateAsync({
          id: e.id,
          category_id: values.category_id,
          url: e.url,
          format: values.format,
          interval_seconds: values.interval_seconds,
          provider: values.provider,
          license: values.license,
          enabled: true,
        })
      )
    );
    setSubmitting(false);
    const ok = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.length - ok;
    notifications.show({
      message: `${ok} feed${ok === 1 ? "" : "s"} added${failed ? `, ${failed} failed (duplicate ID or bad URL?)` : ""}`,
      color: failed ? "yellow" : "green",
    });
    if (failed === 0) handleClose();
  }

  return (
    <Modal opened={opened} onClose={handleClose} title="Bulk add feeds" size="lg">
      <form onSubmit={form.onSubmit(handleSubmit)}>
        <Stack>
          <Text size="sm" c="dimmed">
            One feed per line, as <code>id,url</code>. Category, format, and schedule below apply to every line.
          </Text>
          <Textarea
            placeholder={"acme-list-1,https://example.com/list1.txt\nacme-list-2,https://example.com/list2.txt"}
            minRows={6}
            maxRows={14}
            autosize
            required
            {...form.getInputProps("lines")}
          />
          <SimpleGrid cols={2}>
            <TextInput label="Category" placeholder="malware, adult, gambling …" required {...form.getInputProps("category_id")} />
            <Select label="Format" data={FORMAT_OPTIONS} {...form.getInputProps("format")} />
          </SimpleGrid>
          <SimpleGrid cols={2}>
            <NumberInput label="Refresh interval (seconds)" min={60} {...form.getInputProps("interval_seconds")} />
            <TextInput label="Provider" placeholder="Acme Threat Intel" {...form.getInputProps("provider")} />
          </SimpleGrid>
          <TextInput label="License" placeholder="MIT, CC0, commercial …" {...form.getInputProps("license")} />
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={submitting}>Add feeds</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Edit Feed modal ──────────────────────────────────────────────────────────

function EditFeedModal({ feed, onClose }: { feed: Feed | null; onClose: () => void }) {
  const updateFeed = useUpdateFeed();
  const form = useForm({
    initialValues: {
      url: feed?.url ?? "",
      category_id: feed?.category_id ?? "",
      format: feed?.format ?? "domain-list",
      interval_seconds: feed?.interval_seconds ?? 86400,
      provider: feed?.provider ?? "",
      license: feed?.license ?? "",
    },
  });

  if (!feed) return null;

  function handleClose() {
    form.reset();
    onClose();
  }

  return (
    <Modal opened={!!feed} onClose={handleClose} title={`Edit feed: ${feed.id}`} size="lg">
      {feed.from_catalog && (
        <Text size="sm" c="dimmed" mb="sm">
          Catalog feed — URL and format are read-only. You can adjust schedule, category override, and metadata.
        </Text>
      )}
      <form
        onSubmit={form.onSubmit((values) =>
          updateFeed.mutate(
            { feedId: feed.id, body: values },
            {
              onSuccess: () => {
                notifications.show({ message: `Feed "${feed.id}" updated`, color: "green" });
                handleClose();
              },
              onError: (e) => notifications.show({ message: String(e), color: "red" }),
            }
          )
        )}
      >
        <Stack>
          <TextInput
            label="Source URL"
            disabled={feed.from_catalog}
            {...form.getInputProps("url")}
          />
          <SimpleGrid cols={2}>
            <TextInput label="Category" {...form.getInputProps("category_id")} />
            <Select
              label="Format"
              data={FORMAT_OPTIONS}
              disabled={feed.from_catalog}
              {...form.getInputProps("format")}
            />
          </SimpleGrid>
          <SimpleGrid cols={2}>
            <NumberInput label="Refresh interval (seconds)" min={60} {...form.getInputProps("interval_seconds")} />
            <TextInput label="Provider" {...form.getInputProps("provider")} />
          </SimpleGrid>
          <TextInput label="License" {...form.getInputProps("license")} />
          <Group justify="flex-end">
            <Button variant="default" onClick={handleClose}>Cancel</Button>
            <Button type="submit" loading={updateFeed.isPending}>Save changes</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function FeedsPage() {
  const { data: feeds = [], isLoading } = useFeeds();
  const { data: categoryRegistry = [] } = useCategories();
  const categoryById = useMemo(() => new Map(categoryRegistry.map((c) => [c.id, c])), [categoryRegistry]);
  const updateFeed = useUpdateFeed();
  const deleteFeed = useDeleteFeed();
  const ingestNow = useIngestFeedNow();
  const [addOpened, { open: openAdd, close: closeAdd }] = useDisclosure(false);
  const [bulkAddOpened, { open: openBulkAdd, close: closeBulkAdd }] = useDisclosure(false);
  const [editFeed, setEditFeed] = useState<Feed | null>(null);
  const [syncingId, setSyncingId] = useState<string | null>(null);
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const { hasRole } = useAuth();
  const canWrite = hasRole("operator");

  // Derived stats
  const totalDomains = feeds.reduce((s, f) => s + (f.last_domain_count ?? 0), 0);
  const activeFeeds = feeds.filter((f) => f.enabled && (f.last_domain_count ?? 0) > 0);
  const catalogFeeds = feeds.filter((f) => f.from_catalog);
  const categories = [...new Set(feeds.map((f) => f.category_id))].sort();

  // Category chips: one per category that has at least one feed, in registry
  // order (falls back to alphabetical for any custom/unregistered category).
  const categoryChips = useMemo(() => {
    const present = new Set(feeds.map((f) => f.category_id));
    const registryIds = categoryRegistry.map((c) => c.id);
    const orderedIds = [
      ...registryIds.filter((id) => present.has(id)),
      ...[...present].filter((id) => !registryIds.includes(id)).sort(),
    ];
    return orderedIds.map((id) => ({
      id,
      count: feeds.filter((f) => f.category_id === id).length,
    }));
  }, [feeds, categoryRegistry]);

  // Stable sort so toggling enabled never changes row position
  const sorted = [...feeds].sort((a, b) => a.id.localeCompare(b.id));

  // Filtered list
  const visible = sorted.filter((f) => {
    if (search) {
      const q = search.toLowerCase();
      if (!f.id.includes(q) && !(f.provider ?? "").toLowerCase().includes(q) && !f.url.toLowerCase().includes(q)) return false;
    }
    if (categoryFilter && f.category_id !== categoryFilter) return false;
    if (statusFilter === "active" && !f.enabled) return false;
    if (statusFilter === "disabled" && f.enabled) return false;
    return true;
  });

  // Group the visible rows by category, in registry order, so category is
  // the primary visual axis instead of a badge buried inside each row.
  const groupedRows = useMemo(() => {
    const registryIds = categoryRegistry.map((c) => c.id);
    const byCategory = new Map<string, Feed[]>();
    for (const f of visible) {
      const list = byCategory.get(f.category_id) ?? [];
      list.push(f);
      byCategory.set(f.category_id, list);
    }
    const orderedIds = [
      ...registryIds.filter((id) => byCategory.has(id)),
      ...[...byCategory.keys()].filter((id) => !registryIds.includes(id)).sort(),
    ];
    return orderedIds.map((id) => ({ id, feeds: byCategory.get(id)! }));
  }, [visible, categoryRegistry]);

  function toggleEnabled(feed: Feed) {
    updateFeed.mutate(
      { feedId: feed.id, body: { enabled: !feed.enabled } },
      { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
    );
  }

  function ingest(feed: Feed) {
    setSyncingId(feed.id);
    ingestNow.mutate(feed.id, {
      onSuccess: (r) =>
        notifications.show({
          message: `${feed.id}: ${r.status} · ${fmtDomains(r.domain_count)} domains${r.reason ? ` — ${r.reason}` : ""}`,
          color: r.status === "rejected" || r.status === "error" ? "yellow" : "green",
        }),
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
      onSettled: () => setSyncingId(null),
    });
  }

  function confirmDelete(feed: Feed) {
    modals.openConfirmModal({
      title: "Delete feed",
      children: (
        <Text size="sm">
          Delete <strong>{feed.id}</strong>? This stops auto-updates.
          {feed.from_catalog && " The feed will reappear on next control-plane restart since it is catalog-seeded."}
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: () =>
        deleteFeed.mutate(feed.id, {
          onSuccess: () => notifications.show({ message: `Feed "${feed.id}" deleted`, color: "green" }),
          onError: (e) => notifications.show({ message: String(e), color: "red" }),
        }),
    });
  }

  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function setGroupSelected(ids: string[], select: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (select) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  }

  async function bulkSetEnabled(enabled: boolean) {
    const ids = [...selected];
    const results = await Promise.allSettled(
      ids.map((id) => updateFeed.mutateAsync({ feedId: id, body: { enabled } }))
    );
    const ok = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.length - ok;
    notifications.show({
      message: `${ok} feed${ok === 1 ? "" : "s"} ${enabled ? "enabled" : "disabled"}${failed ? `, ${failed} failed` : ""}`,
      color: failed ? "yellow" : "green",
    });
    setSelected(new Set());
  }

  async function bulkSync() {
    const ids = [...selected].filter((id) => feeds.find((f) => f.id === id)?.enabled);
    if (ids.length === 0) {
      notifications.show({ message: "No enabled feeds selected", color: "yellow" });
      return;
    }
    setSyncingIds(new Set(ids));
    const results = await Promise.allSettled(ids.map((id) => ingestNow.mutateAsync(id)));
    setSyncingIds(new Set());
    const ok = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.length - ok;
    notifications.show({
      message: `${ok} feed${ok === 1 ? "" : "s"} synced${failed ? `, ${failed} failed` : ""}`,
      color: failed ? "yellow" : "green",
    });
  }

  function bulkDelete() {
    const ids = [...selected];
    modals.openConfirmModal({
      title: "Delete feeds",
      children: (
        <Text size="sm">
          Delete <strong>{ids.length}</strong> feed{ids.length === 1 ? "" : "s"}? This stops auto-updates for
          each. Catalog-seeded feeds reappear on next control-plane restart.
        </Text>
      ),
      labels: { confirm: `Delete ${ids.length}`, cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: async () => {
        const results = await Promise.allSettled(ids.map((id) => deleteFeed.mutateAsync(id)));
        const ok = results.filter((r) => r.status === "fulfilled").length;
        const failed = results.length - ok;
        notifications.show({
          message: `${ok} feed${ok === 1 ? "" : "s"} deleted${failed ? `, ${failed} failed` : ""}`,
          color: failed ? "yellow" : "green",
        });
        setSelected(new Set());
      },
    });
  }

  if (isLoading)
    return (
      <Flex justify="center" align="center" h={200}>
        <Loader />
      </Flex>
    );

  const colCount = canWrite ? 6 : 5;

  return (
    <Stack gap="lg">
      {/* Header */}
      <Group justify="space-between" align="flex-start">
        <Stack gap={2}>
          <Title order={2}>Threat Intelligence Feeds</Title>
          <Text c="dimmed" size="sm">
            Manage blocklist feeds. Changes take effect immediately — no restart required.
          </Text>
        </Stack>
        {canWrite && (
          <Group gap="xs">
            <Button variant="default" leftSection={<IconPlaylistAdd size={16} />} onClick={openBulkAdd}>
              Bulk add
            </Button>
            <Button leftSection={<IconPlus size={16} />} onClick={openAdd}>
              Add feed
            </Button>
          </Group>
        )}
      </Group>

      {/* KPIs */}
      <SimpleGrid cols={{ base: 2, sm: 4 }}>
        <KpiCard label="Total feeds" value={feeds.length} sub={`${catalogFeeds.length} catalog · ${feeds.length - catalogFeeds.length} custom`} />
        <KpiCard label="Active" value={activeFeeds.length} sub={`${feeds.length - activeFeeds.length} inactive`} />
        <KpiCard label="Total domains" value={totalDomains.toLocaleString()} sub="across all enabled feeds" />
        <KpiCard label="Categories" value={categories.length} sub={categories.slice(0, 3).join(", ") + (categories.length > 3 ? " …" : "")} />
      </SimpleGrid>

      {/* Filters */}
      <Group>
        <TextInput
          placeholder="Search by ID, provider, URL…"
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => setSearch(e.currentTarget.value)}
          style={{ flex: 1, maxWidth: 360 }}
        />
        <Select
          data={[
            { value: "all", label: "All statuses" },
            { value: "active", label: "Active only" },
            { value: "disabled", label: "Disabled only" },
          ]}
          value={statusFilter}
          onChange={(v) => setStatusFilter(v ?? "all")}
          style={{ width: 160 }}
        />
      </Group>

      {/* Category chips — click to filter, click again to clear */}
      <Group gap={6}>
        <Badge
          size="lg"
          radius="sm"
          variant={categoryFilter === null ? "filled" : "light"}
          color="gray"
          style={{ cursor: "pointer" }}
          onClick={() => setCategoryFilter(null)}
        >
          All ({feeds.length})
        </Badge>
        {categoryChips.map(({ id, count }) => {
          const cat = categoryById.get(id);
          const Icon = cat ? categoryIcon(cat.icon) : null;
          const active = categoryFilter === id;
          return (
            <Badge
              key={id}
              size="lg"
              radius="sm"
              variant={active ? "filled" : "light"}
              color={categoryColor(id, categoryById)}
              leftSection={Icon ? <Icon size={12} /> : undefined}
              style={{ cursor: "pointer" }}
              onClick={() => setCategoryFilter(active ? null : id)}
            >
              {categoryLabel(id, categoryById)} ({count})
            </Badge>
          );
        })}
      </Group>

      {/* Bulk action bar */}
      {canWrite && selected.size > 0 && (
        <Group
          justify="space-between"
          p="xs"
          style={{ backgroundColor: "var(--mantine-color-blue-light)", borderRadius: 8 }}
        >
          <Text size="sm" fw={600}>
            {selected.size} feed{selected.size === 1 ? "" : "s"} selected
          </Text>
          <Group gap={6}>
            <Button size="xs" variant="light" onClick={bulkSync} loading={syncingIds.size > 0} leftSection={<IconRefresh size={14} />}>
              Sync now
            </Button>
            <Button size="xs" variant="light" color="green" onClick={() => bulkSetEnabled(true)}>
              Enable
            </Button>
            <Button size="xs" variant="light" color="gray" onClick={() => bulkSetEnabled(false)}>
              Disable
            </Button>
            <Button size="xs" variant="light" color="red" onClick={bulkDelete}>
              Delete
            </Button>
            <Button size="xs" variant="subtle" onClick={() => setSelected(new Set())}>
              Clear
            </Button>
          </Group>
        </Group>
      )}

      {/* Table */}
      <Table striped highlightOnHover withTableBorder withColumnBorders>
        <Table.Thead>
          <Table.Tr>
            {canWrite && (
              <Table.Th w={32}>
                <Checkbox
                  size="xs"
                  checked={visible.length > 0 && visible.every((f) => selected.has(f.id))}
                  indeterminate={visible.some((f) => selected.has(f.id)) && !visible.every((f) => selected.has(f.id))}
                  onChange={() =>
                    setGroupSelected(
                      visible.map((f) => f.id),
                      !visible.every((f) => selected.has(f.id))
                    )
                  }
                />
              </Table.Th>
            )}
            <Table.Th>Feed</Table.Th>
            <Table.Th w={90} style={{ textAlign: "right" }}>Domains</Table.Th>
            <Table.Th w={95}>Last sync</Table.Th>
            <Table.Th w={50}>On</Table.Th>
            <Table.Th w={100} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {visible.length === 0 && (
            <Table.Tr>
              <Table.Td colSpan={colCount}>
                <Text c="dimmed" ta="center" py="md">No feeds match the current filters</Text>
              </Table.Td>
            </Table.Tr>
          )}
          {groupedRows.map(({ id: catId, feeds: catFeeds }) => {
            const cat = categoryById.get(catId);
            const Icon = categoryIcon(cat?.icon ?? "");
            const catDomains = catFeeds.reduce((s, f) => s + (f.last_domain_count ?? 0), 0);
            const catIds = catFeeds.map((f) => f.id);
            const catAllSelected = catIds.length > 0 && catIds.every((id) => selected.has(id));
            const catSomeSelected = catIds.some((id) => selected.has(id));
            return (
              <Fragment key={catId}>
                {/* Category divider row */}
                <Table.Tr style={{ backgroundColor: "var(--mantine-color-default-hover)" }}>
                  {canWrite && (
                    <Table.Td py={6}>
                      <Checkbox
                        size="xs"
                        checked={catAllSelected}
                        indeterminate={catSomeSelected && !catAllSelected}
                        onChange={() => setGroupSelected(catIds, !catAllSelected)}
                      />
                    </Table.Td>
                  )}
                  <Table.Td colSpan={colCount - (canWrite ? 1 : 0)} py={6}>
                    <Group gap={8} wrap="nowrap">
                      <ActionIcon color={categoryColor(catId, categoryById)} variant="light" size="sm" radius="sm">
                        <Icon size={13} />
                      </ActionIcon>
                      <Text size="sm" fw={700}>
                        {categoryLabel(catId, categoryById)}
                      </Text>
                      {cat && (
                        <Text size="xs" c="dimmed">
                          {CATEGORY_GROUP_LABEL[cat.group] ?? cat.group}
                        </Text>
                      )}
                      <Badge size="xs" variant="outline" color="gray">
                        {catFeeds.length} feed{catFeeds.length === 1 ? "" : "s"}
                      </Badge>
                      <Text size="xs" c="dimmed" ml="auto">
                        {catDomains.toLocaleString()} domains
                      </Text>
                    </Group>
                  </Table.Td>
                </Table.Tr>

                {catFeeds.map((f) => {
                  const { label, color } = feedStatus(f);
                  return (
                    <Table.Tr key={f.id}>
                      {canWrite && (
                        <Table.Td>
                          <Checkbox size="xs" checked={selected.has(f.id)} onChange={() => toggleSelected(f.id)} />
                        </Table.Td>
                      )}
                      {/* Feed cell */}
                      <Table.Td>
                        <Group gap={6} wrap="nowrap" align="flex-start">
                          {/* Status dot */}
                          <Tooltip label={label} position="right">
                            <IconCircleFilled
                              size={9}
                              style={{ color: `var(--mantine-color-${color}-6)`, flexShrink: 0, marginTop: 5 }}
                            />
                          </Tooltip>

                          <Stack gap={3} style={{ minWidth: 0 }}>
                            {/* Row 1: ID + copy/link */}
                            <Group gap={4} wrap="nowrap">
                              <Text size="sm" fw={600} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {f.id}
                              </Text>
                              <CopyButton value={f.url} timeout={1500}>
                                {({ copied, copy }) => (
                                  <Tooltip label={copied ? "Copied!" : f.url} multiline maw={360} position="bottom">
                                    <ActionIcon size="xs" variant="subtle" color={copied ? "teal" : "gray"} onClick={copy} style={{ flexShrink: 0 }}>
                                      {copied ? <IconCheck size={11} /> : <IconCopy size={11} />}
                                    </ActionIcon>
                                  </Tooltip>
                                )}
                              </CopyButton>
                              <ActionIcon
                                component="a" href={f.url} target="_blank" rel="noreferrer"
                                size="xs" variant="subtle" color="gray" style={{ flexShrink: 0 }}
                              >
                                <IconExternalLink size={11} />
                              </ActionIcon>
                            </Group>

                            {/* Row 2: format + catalog tag + provider + interval */}
                            <Group gap={4} wrap="wrap">
                              <Badge size="xs" variant="outline" color="gray" tt="none" style={{ flexShrink: 0 }}>
                                {f.format}
                              </Badge>
                              {f.from_catalog && (
                                <Badge size="xs" variant="dot" color="blue" style={{ flexShrink: 0 }}>catalog</Badge>
                              )}
                              {f.provider && <Text size="xs" c="dimmed" style={{ flexShrink: 0 }}>{f.provider}</Text>}
                              <Text size="xs" c="dimmed" style={{ flexShrink: 0 }}>· {fmtInterval(f.interval_seconds)}</Text>
                            </Group>
                          </Stack>
                        </Group>
                      </Table.Td>

                      {/* Domains */}
                      <Table.Td style={{ textAlign: "right" }}>
                        <Text size="sm" ff="monospace">{fmtDomains(f.last_domain_count)}</Text>
                      </Table.Td>

                      {/* Last sync */}
                      <Table.Td>
                        <Tooltip
                          label={f.last_fetched_at ? new Date(f.last_fetched_at).toLocaleString() : "Never synced"}
                          position="left"
                        >
                          <Text size="sm" c={f.last_fetched_at ? undefined : "dimmed"}>
                            {relativeTime(f.last_fetched_at)}
                          </Text>
                        </Tooltip>
                      </Table.Td>

                      {/* Toggle */}
                      <Table.Td>
                        <Switch size="sm" checked={f.enabled} disabled={!canWrite} onChange={() => toggleEnabled(f)} />
                      </Table.Td>

                      {/* Actions */}
                      <Table.Td>
                        <Group gap={2} wrap="nowrap" justify="flex-end">
                          {canWrite && (
                            <>
                              <Tooltip label="Sync now">
                                <ActionIcon size="sm" variant="subtle" onClick={() => ingest(f)} loading={syncingId === f.id || syncingIds.has(f.id)} disabled={!f.enabled}>
                                  <IconRefresh size={14} />
                                </ActionIcon>
                              </Tooltip>
                              <Tooltip label="Edit">
                                <ActionIcon size="sm" variant="subtle" onClick={() => setEditFeed(f)}>
                                  <IconEdit size={14} />
                                </ActionIcon>
                              </Tooltip>
                              <Tooltip label="Delete">
                                <ActionIcon size="sm" variant="subtle" color="red" onClick={() => confirmDelete(f)}>
                                  <IconTrash size={14} />
                                </ActionIcon>
                              </Tooltip>
                            </>
                          )}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Fragment>
            );
          })}
        </Table.Tbody>
      </Table>

      {visible.length > 0 && (
        <Text size="xs" c="dimmed" ta="right">
          {visible.length} of {feeds.length} feeds
        </Text>
      )}

      {/* Modals */}
      <AddFeedModal opened={addOpened} onClose={closeAdd} />
      <BulkAddFeedModal opened={bulkAddOpened} onClose={closeBulkAdd} />
      <EditFeedModal key={editFeed?.id ?? "none"} feed={editFeed} onClose={() => setEditFeed(null)} />
    </Stack>
  );
}
