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

import { Alert, Button, Group, Modal, Select, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useGroups, usePolicy, useTenants } from "../api/hooks";
import type { components } from "../api/schema";

type PolicyOut = components["schemas"]["PolicyOut"];

export function DuplicatePolicyModal({
  opened,
  onClose,
  excludeGroupId,
  onSelect,
}: {
  opened: boolean;
  onClose: () => void;
  excludeGroupId: string | undefined;
  onSelect: (policy: PolicyOut) => void;
}) {
  const { data: tenants } = useTenants();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [groupId, setGroupId] = useState<string | null>(null);
  const { data: groups } = useGroups(tenantId ?? undefined);
  const { data: sourcePolicy, isLoading, isFetched } = usePolicy(groupId ?? undefined);

  const tenantOptions = (tenants ?? []).map((t) => ({ value: t.id, label: t.name }));
  const groupOptions = (groups ?? [])
    .filter((g) => g.id !== excludeGroupId)
    .map((g) => ({ value: g.id, label: g.name }));

  function reset() {
    setTenantId(null);
    setGroupId(null);
  }

  function handleClose() {
    reset();
    onClose();
  }

  function confirm() {
    if (!sourcePolicy) return;
    onSelect(sourcePolicy);
    reset();
    onClose();
  }

  return (
    <Modal opened={opened} onClose={handleClose} title="Duplicate policy from another group">
      <Stack>
        <Text size="sm" c="dimmed">
          Loads another group's category toggles, overrides, and failure policy into this editor.
          Nothing is saved until you click "Save policy".
        </Text>
        <Select
          label="Tenant"
          placeholder="Choose a tenant"
          data={tenantOptions}
          value={tenantId}
          onChange={(v) => {
            setTenantId(v);
            setGroupId(null);
          }}
          searchable
        />
        <Select
          label="Source group"
          placeholder="Choose a group"
          data={groupOptions}
          value={groupId}
          onChange={(v) => setGroupId(v)}
          disabled={!tenantId}
          searchable
        />
        {groupId && isLoading && (
          <Text size="sm" c="dimmed">
            Loading policy…
          </Text>
        )}
        {groupId && isFetched && !sourcePolicy && (
          <Alert color="yellow">This group has no saved policy yet.</Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={confirm} disabled={!sourcePolicy}>
            Load policy
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
