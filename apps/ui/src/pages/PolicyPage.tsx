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
  Breadcrumbs,
  Anchor,
  Button,
  Card,
  Center,
  Code,
  Group,
  Loader,
  Paper,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconX } from "@tabler/icons-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useCategories, useCompileBundle, useTopDomains, usePolicy, useUpsertPolicy, useTestPolicy } from "../api/hooks";
import type { Category } from "../api/hooks";
import { categoryIcon, CATEGORY_GROUP_LABEL } from "../categoryIcons";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type CategoryToggle = components["schemas"]["CategoryToggleIn"];
type Override = components["schemas"]["OverrideIn"];

const CATEGORY_ACTION_OPTIONS = [
  { value: "off", label: "Off" },
  { value: "ACTION_BLOCK", label: "Block" },
  { value: "ACTION_LOG_ONLY", label: "Log only" },
  { value: "ACTION_ALLOW", label: "Allow" },
];

const GROUP_ORDER = ["security", "content", "distraction", "privacy", "network"];

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function CategoryRow({
  category,
  action,
  onChange,
}: {
  category: Category;
  action: string;
  onChange: (value: string) => void;
}) {
  const Icon = categoryIcon(category.icon);
  return (
    <Paper withBorder p="sm" radius="md">
      <Stack gap="xs">
        <Group gap="sm" wrap="nowrap" align="flex-start">
          <ThemeIcon color={category.color} variant="light" size="lg" radius="md" style={{ flexShrink: 0 }}>
            <Icon size={18} />
          </ThemeIcon>
          <div style={{ minWidth: 0, flex: 1 }}>
            <Group gap={6}>
              <Text fw={500} size="sm">
                {category.label}
              </Text>
              {!category.has_bundled_feed && (
                <Tooltip label="No pre-loaded feed — add one on the Feeds page">
                  <Badge size="xs" variant="outline" color="gray">
                    no feed
                  </Badge>
                </Tooltip>
              )}
            </Group>
            <Text size="xs" c="dimmed">
              {category.description}
            </Text>
          </div>
        </Group>
        <Select
          data={CATEGORY_ACTION_OPTIONS}
          value={action}
          onChange={(v) => v && onChange(v)}
          size="xs"
          allowDeselect={false}
          ml={44}
        />
      </Stack>
    </Paper>
  );
}

function AddOverrideForm({ onAdd }: { onAdd: (o: Override) => void }) {
  const form = useForm<{ domain: string; kind: "allow" | "deny" }>({
    initialValues: { domain: "", kind: "deny" },
    validate: { domain: (v) => (DOMAIN_RE.test(v.trim()) ? null : "Enter a valid domain, e.g. ads.example.com") },
  });

  return (
    <form
      onSubmit={form.onSubmit((values) => {
        onAdd({ domain: values.domain.trim().toLowerCase(), kind: values.kind });
        form.reset();
      })}
    >
      <Group align="flex-end">
        <TextInput placeholder="domain.example" {...form.getInputProps("domain")} style={{ flex: 1 }} />
        <Select data={["allow", "deny"]} {...form.getInputProps("kind")} w={110} />
        <Button type="submit" leftSection={<IconPlus size={14} />}>
          Add
        </Button>
      </Group>
    </form>
  );
}

export function PolicyPage() {
  const { tenantId, groupId } = useParams<{ tenantId: string; groupId: string }>();
  const { data: policy, isLoading } = usePolicy(groupId);
  const { data: categories } = useCategories();
  const upsertPolicy = useUpsertPolicy(groupId);
  const compileBundle = useCompileBundle();
  const testPolicy = useTestPolicy(groupId);
  const { data: topDomains } = useTopDomains(groupId);
  const { hasRole } = useAuth();

  const [testDomain, setTestDomain] = useState("");

  const [categoryToggles, setCategoryToggles] = useState<CategoryToggle[]>([]);
  const [overrides, setOverrides] = useState<Override[]>([]);
  const [onLoadFailure, setOnLoadFailure] = useState<"FAIL_OPEN" | "FAIL_CLOSED">("FAIL_OPEN");

  useEffect(() => {
    setCategoryToggles((policy?.category_toggles ?? []) as CategoryToggle[]);
    setOverrides((policy?.overrides ?? []) as Override[]);
    setOnLoadFailure((policy?.on_load_failure ?? "FAIL_OPEN") as "FAIL_OPEN" | "FAIL_CLOSED");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy?.id]);

  function setCategoryAction(categoryId: string, action: string) {
    setCategoryToggles((prev) => {
      const rest = prev.filter((c) => c.category_id !== categoryId);
      if (action === "off") return rest;
      return [...rest, { category_id: categoryId, action: action as CategoryToggle["action"] }];
    });
  }

  const categoriesByGroup = useMemo(() => {
    const groups = new Map<string, Category[]>();
    for (const cat of categories ?? []) {
      const list = groups.get(cat.group) ?? [];
      list.push(cat);
      groups.set(cat.group, list);
    }
    return groups;
  }, [categories]);

  function save() {
    if (!groupId) return;
    upsertPolicy.mutate(
      { on_load_failure: onLoadFailure, category_toggles: categoryToggles, overrides },
      {
        onSuccess: () => notifications.show({ message: "Policy saved", color: "green" }),
        onError: (e) => notifications.show({ message: String(e), color: "red" }),
      }
    );
  }

  function compile() {
    if (!groupId) return;
    compileBundle.mutate(groupId, {
      onSuccess: () => notifications.show({ message: "Bundle compiled and published", color: "green" }),
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
    });
  }

  if (isLoading)
    return (
      <Center h={200}>
        <Loader />
      </Center>
    );

  return (
    <Stack>
      <Breadcrumbs>
        <Anchor component={Link} to="/tenants">
          Tenants
        </Anchor>
        <Anchor component={Link} to={`/tenants/${tenantId}`}>
          Groups
        </Anchor>
        <Text>Policy</Text>
      </Breadcrumbs>

      <Title order={2}>Policy</Title>

      <Card withBorder>
        <Title order={4} mb="sm">
          Categories
        </Title>
        <Stack gap="lg">
          {GROUP_ORDER.filter((g) => categoriesByGroup.has(g)).map((group) => (
            <div key={group}>
              <Text size="xs" fw={700} tt="uppercase" c="dimmed" mb="xs">
                {CATEGORY_GROUP_LABEL[group] ?? group}
              </Text>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                {categoriesByGroup.get(group)!.map((cat) => (
                  <CategoryRow
                    key={cat.id}
                    category={cat}
                    action={categoryToggles.find((c) => c.category_id === cat.id)?.action ?? "off"}
                    onChange={(action) => setCategoryAction(cat.id, action)}
                  />
                ))}
              </SimpleGrid>
            </div>
          ))}
        </Stack>
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          Overrides
        </Title>
        <Stack gap="xs" mb="sm">
          {overrides.length === 0 && (
            <Text c="dimmed" size="sm">
              No overrides yet.
            </Text>
          )}
          {overrides.map((o) => (
            <Group key={o.domain} justify="space-between">
              <Group gap="xs">
                <Badge color={o.kind === "allow" ? "green" : "red"}>{o.kind}</Badge>
                <Text>{o.domain}</Text>
              </Group>
              <Button
                variant="subtle"
                color="gray"
                size="xs"
                leftSection={<IconX size={14} />}
                onClick={() => setOverrides((prev) => prev.filter((x) => x.domain !== o.domain))}
              >
                Remove
              </Button>
            </Group>
          ))}
        </Stack>
        <AddOverrideForm onAdd={(o) => setOverrides((prev) => [...prev.filter((x) => x.domain !== o.domain), o])} />
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          Failure policy
        </Title>
        <Select
          data={[
            { value: "FAIL_OPEN", label: "Fail open — resolve normally if bundle fails to load" },
            { value: "FAIL_CLOSED", label: "Fail closed — block all resolution" },
          ]}
          value={onLoadFailure}
          onChange={(v) => v && setOnLoadFailure(v)}
        />
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          Test a domain
        </Title>
        <Text size="sm" c="dimmed" mb="sm">
          Checks the saved policy (overrides + category feeds) without requiring a compiled bundle.
        </Text>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const d = testDomain.trim().toLowerCase().replace(/\.$/, "");
            if (d) testPolicy.mutate(d);
          }}
        >
          <Group align="flex-end">
            <TextInput
              placeholder="ads.example.com"
              value={testDomain}
              onChange={(e) => setTestDomain(e.currentTarget.value)}
              style={{ flex: 1 }}
            />
            <Button type="submit" loading={testPolicy.isPending}>
              Test
            </Button>
          </Group>
        </form>
        {testPolicy.data && (
          <Group mt="sm" gap="xs" align="center">
            <Badge
              size="lg"
              color={testPolicy.data.decision === "block" ? "red" : "green"}
            >
              {testPolicy.data.decision.toUpperCase()}
            </Badge>
            <Text size="sm" c="dimmed">
              {testPolicy.data.matched === "override_allow" && "matched allow override"}
              {testPolicy.data.matched === "override_deny" && "matched deny override"}
              {testPolicy.data.matched === "category" && (
                <>
                  category <Code>{testPolicy.data.matched_category}</Code>
                  {testPolicy.data.matched_feed_id && (
                    <> · feed <Code>{testPolicy.data.matched_feed_id}</Code></>
                  )}
                </>
              )}
              {testPolicy.data.matched === "default" && "no rule matched — default allow"}
            </Text>
          </Group>
        )}
        {testPolicy.error && (
          <Text size="sm" c="red" mt="xs">
            {String(testPolicy.error)}
          </Text>
        )}
      </Card>

      {hasRole("operator") && (
        <Group>
          <Button onClick={save} loading={upsertPolicy.isPending}>
            Save policy
          </Button>
          <Button variant="default" onClick={compile} loading={compileBundle.isPending}>
            Compile & publish bundle
          </Button>
        </Group>
      )}

      <Card withBorder>
        <Title order={4} mb="sm">
          Top domains (live telemetry)
        </Title>
        {(!topDomains || topDomains.length === 0) && (
          <Text c="dimmed" size="sm">
            No query telemetry yet for this group.
          </Text>
        )}
        {topDomains && topDomains.length > 0 && (
          <Table>
            <Table.Tbody>
              {topDomains.map((d) => (
                <Table.Tr key={`${d.qname}-${d.decision}`}>
                  <Table.Td>{d.qname}</Table.Td>
                  <Table.Td>
                    <Badge color={d.decision === "block" ? "red" : "green"}>{d.decision}</Badge>
                  </Table.Td>
                  <Table.Td>{d.count}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}
