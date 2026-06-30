import {
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  NumberInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconRefresh, IconTrash } from "@tabler/icons-react";
import { useCreateFeed, useDeleteFeed, useFeeds, useIngestFeedNow, useUpdateFeed } from "../api/hooks";
import type { components } from "../api/schema";

type Feed = components["schemas"]["FeedOut"];

function AddFeedForm({ onDone }: { onDone: () => void }) {
  const createFeed = useCreateFeed();
  const form = useForm({
    initialValues: {
      id: "",
      category_id: "",
      url: "",
      format: "hostfile",
      interval_seconds: 86400,
      license: "",
      provider: "custom",
    },
    validate: {
      id: (v) => (v.trim().length < 2 ? "Required, unique id" : null),
      category_id: (v) => (v.trim().length < 2 ? "Required" : null),
      url: (v) => {
        try {
          new URL(v);
          return null;
        } catch {
          return "Must be a valid URL";
        }
      },
    },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        createFeed.mutate(
          { ...values, enabled: true },
          {
            onSuccess: () => {
              notifications.show({ message: `Feed "${values.id}" added`, color: "green" });
              onDone();
            },
            onError: (e) => notifications.show({ message: String(e), color: "red" }),
          }
        );
      })}
    >
      <Stack>
        <TextInput label="Feed id" placeholder="my-custom-feed" required {...form.getInputProps("id")} />
        <TextInput label="Category" placeholder="adult, gambling, malware, ..." required {...form.getInputProps("category_id")} />
        <TextInput label="URL" placeholder="https://example.com/list.txt" required {...form.getInputProps("url")} />
        <Select
          label="Format"
          data={[
            { value: "hostfile", label: "hostfile — \"0.0.0.0 domain\" lines" },
            { value: "domain-list", label: "domain-list — plain domain lines" },
          ]}
          {...form.getInputProps("format")}
        />
        <NumberInput label="Refresh interval (seconds)" min={60} {...form.getInputProps("interval_seconds")} />
        <TextInput label="License" placeholder="MIT, CC0, ..." {...form.getInputProps("license")} />
        <Button type="submit" loading={createFeed.isPending}>
          Add feed
        </Button>
      </Stack>
    </form>
  );
}

export function FeedsPage() {
  const { data: feeds, isLoading } = useFeeds();
  const updateFeed = useUpdateFeed();
  const deleteFeed = useDeleteFeed();
  const ingestNow = useIngestFeedNow();

  function openAddModal() {
    const id = modals.open({
      title: "Add custom feed",
      size: "md",
      children: <AddFeedForm onDone={() => modals.close(id)} />,
    });
  }

  function toggleEnabled(feed: Feed) {
    updateFeed.mutate(
      { feedId: feed.id, body: { enabled: !feed.enabled } },
      { onError: (e) => notifications.show({ message: String(e), color: "red" }) }
    );
  }

  function ingest(feed: Feed) {
    ingestNow.mutate(feed.id, {
      onSuccess: (result) =>
        notifications.show({
          message: `${feed.id}: ${result.status} (${result.domain_count} domains)${result.reason ? ` — ${result.reason}` : ""}`,
          color: result.status === "rejected" || result.status === "error" ? "yellow" : "green",
        }),
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
    });
  }

  function confirmDelete(feed: Feed) {
    modals.openConfirmModal({
      title: "Delete feed",
      children: (
        <Text size="sm">
          Delete "{feed.id}"? This stops its auto-updates{feed.from_catalog ? " (it will reappear if the control plane restarts, since it's catalog-seeded)" : ""}.
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

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );

  const byCategory = (feeds ?? []).reduce<Record<string, Feed[]>>((acc, f) => {
    (acc[f.category_id] ??= []).push(f);
    return acc;
  }, {});

  return (
    <Stack>
      <Group justify="space-between">
        <Title order={2}>Feeds</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={openAddModal}>
          Add custom feed
        </Button>
      </Group>
      <Text c="dimmed" size="sm">
        Pre-loaded from a vetted catalog (StevenBlack, The Block List Project, URLhaus). Changes take effect
        immediately — no restart needed.
      </Text>

      {Object.entries(byCategory).map(([category, categoryFeeds]) => (
        <Card withBorder key={category}>
          <Title order={4} mb="sm" tt="capitalize">
            {category}
          </Title>
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Feed</Table.Th>
                <Table.Th>Provider</Table.Th>
                <Table.Th>Domains</Table.Th>
                <Table.Th>Interval</Table.Th>
                <Table.Th>Enabled</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {categoryFeeds.map((f) => (
                <Table.Tr key={f.id}>
                  <Table.Td>
                    <Group gap="xs">
                      {f.id}
                      {f.from_catalog && (
                        <Badge size="xs" variant="light">
                          catalog
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>{f.provider || "—"}</Table.Td>
                  <Table.Td>{f.last_domain_count ?? <Text c="dimmed">not yet ingested</Text>}</Table.Td>
                  <Table.Td>{Math.round(f.interval_seconds / 60)}m</Table.Td>
                  <Table.Td>
                    <Switch checked={f.enabled} onChange={() => toggleEnabled(f)} />
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs">
                      <Button
                        size="xs"
                        variant="default"
                        leftSection={<IconRefresh size={14} />}
                        onClick={() => ingest(f)}
                        loading={ingestNow.isPending}
                      >
                        Ingest now
                      </Button>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        leftSection={<IconTrash size={14} />}
                        onClick={() => confirmDelete(f)}
                      >
                        Delete
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Card>
      ))}
    </Stack>
  );
}
