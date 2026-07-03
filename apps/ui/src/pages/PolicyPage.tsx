import {
  Badge,
  Breadcrumbs,
  Anchor,
  Button,
  Card,
  Center,
  Checkbox,
  Code,
  Group,
  Loader,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconX } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useCompileBundle, useTopDomains, usePolicy, useUpsertPolicy, useTestPolicy } from "../api/hooks";
import type { components } from "../api/schema";
import { useAuth } from "../auth/AuthContext";

type CategoryToggle = components["schemas"]["CategoryToggleIn"];
type Override = components["schemas"]["OverrideIn"];

// Backed by services/control/aegis_control/feeds/catalog.json — adult, gambling,
// malware, ads, phishing, tracking have a pre-loaded feed. weapons/social/proxies
// have no vetted free source yet (see Feeds page); the toggle still works, the
// bloom is just empty until a feed is added.
const KNOWN_CATEGORIES = ["adult", "gambling", "weapons", "malware", "ads", "phishing", "tracking", "social", "proxies"];

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

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
  const upsertPolicy = useUpsertPolicy(groupId);
  const compileBundle = useCompileBundle();
  const testPolicy = useTestPolicy(groupId);
  const { data: topDomains } = useTopDomains(groupId);
  const { hasRole } = useAuth();

  const [testDomain, setTestDomain] = useState("");

  const [categoryToggles, setCategoryToggles] = useState<CategoryToggle[]>([]);
  const [overrides, setOverrides] = useState<Override[]>([]);
  const [onLoadFailure, setOnLoadFailure] = useState("FAIL_OPEN");

  useEffect(() => {
    setCategoryToggles(policy?.category_toggles ?? []);
    setOverrides(policy?.overrides ?? []);
    setOnLoadFailure(policy?.on_load_failure ?? "FAIL_OPEN");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy?.id]);

  function toggleCategory(categoryId: string) {
    setCategoryToggles((prev) =>
      prev.some((c) => c.category_id === categoryId)
        ? prev.filter((c) => c.category_id !== categoryId)
        : [...prev, { category_id: categoryId, action: "ACTION_BLOCK" }]
    );
  }

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
        <SimpleGrid cols={{ base: 2, sm: 3, md: 4 }}>
          {KNOWN_CATEGORIES.map((cat) => (
            <Checkbox
              key={cat}
              label={cat}
              checked={categoryToggles.some((c) => c.category_id === cat)}
              onChange={() => toggleCategory(cat)}
            />
          ))}
        </SimpleGrid>
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
