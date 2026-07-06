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

import { ActionIcon, Center, Group, Loader, Table } from "@mantine/core";
import { IconEdit, IconTrash } from "@tabler/icons-react";
import type { ReactNode } from "react";

export interface CrudColumn<T> {
  key: string;
  header: ReactNode;
  width?: number | string;
  render: (row: T) => ReactNode;
}

export interface CrudTableProps<T> {
  data: T[];
  isLoading?: boolean;
  getRowKey: (row: T, index: number) => string;
  columns: CrudColumn<T>[];
  /** Shown instead of the table when data is empty. Omit to just render an empty table body. */
  emptyState?: ReactNode;
  /** Omit onEdit/onDelete/renderRowActions all three to suppress the actions column entirely (read-only tables). */
  onEdit?: (row: T) => void;
  onDelete?: (row: T) => void;
  /** Extra per-row actions (e.g. a "Test" probe button), rendered before the edit/delete icons. */
  renderRowActions?: (row: T) => ReactNode;
  actionsWidth?: number;
  striped?: boolean;
  highlightOnHover?: boolean;
  withTableBorder?: boolean;
  withColumnBorders?: boolean;
}

export function CrudTable<T>({
  data,
  isLoading,
  getRowKey,
  columns,
  emptyState,
  onEdit,
  onDelete,
  renderRowActions,
  actionsWidth = 80,
  striped = true,
  highlightOnHover = true,
  withTableBorder = false,
  withColumnBorders = false,
}: CrudTableProps<T>) {
  if (isLoading) {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    );
  }

  if (data.length === 0 && emptyState !== undefined) {
    return <>{emptyState}</>;
  }

  const showActionsColumn = !!(onEdit || onDelete || renderRowActions);

  return (
    <Table
      striped={striped}
      highlightOnHover={highlightOnHover}
      withTableBorder={withTableBorder}
      withColumnBorders={withColumnBorders}
    >
      <Table.Thead>
        <Table.Tr>
          {columns.map((col) => (
            <Table.Th key={col.key} w={col.width}>
              {col.header}
            </Table.Th>
          ))}
          {showActionsColumn && <Table.Th w={actionsWidth} />}
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {data.map((row, index) => (
          <Table.Tr key={getRowKey(row, index)}>
            {columns.map((col) => (
              <Table.Td key={col.key}>{col.render(row)}</Table.Td>
            ))}
            {showActionsColumn && (
              <Table.Td>
                <Group gap={4} wrap="nowrap" justify="flex-end">
                  {renderRowActions?.(row)}
                  {onEdit && (
                    <ActionIcon aria-label="Edit" size="sm" variant="subtle" onClick={() => onEdit(row)}>
                      <IconEdit size={14} />
                    </ActionIcon>
                  )}
                  {onDelete && (
                    <ActionIcon aria-label="Delete" size="sm" variant="subtle" color="red" onClick={() => onDelete(row)}>
                      <IconTrash size={14} />
                    </ActionIcon>
                  )}
                </Group>
              </Table.Td>
            )}
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}
