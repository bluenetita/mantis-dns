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

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "../../test/utils";
import { CrudTable, type CrudColumn } from "./CrudTable";

interface Widget {
  id: string;
  name: string;
}

const columns: CrudColumn<Widget>[] = [
  { key: "name", header: "Name", render: (w) => w.name },
];

const rows: Widget[] = [
  { id: "1", name: "Alpha" },
  { id: "2", name: "Beta" },
];

describe("CrudTable", () => {
  it("shows a loader while isLoading", () => {
    renderWithProviders(<CrudTable data={[]} isLoading columns={columns} getRowKey={(w) => w.id} />);
    expect(document.querySelector('[class*="Loader"]')).toBeTruthy();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders the emptyState instead of the table when data is empty", () => {
    renderWithProviders(
      <CrudTable
        data={[]}
        columns={columns}
        getRowKey={(w) => w.id}
        emptyState={<div>No widgets yet</div>}
      />
    );
    expect(screen.getByText("No widgets yet")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders an empty table body when data is empty and no emptyState given", () => {
    renderWithProviders(<CrudTable data={[]} columns={columns} getRowKey={(w) => w.id} />);
    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.queryAllByRole("row")).toHaveLength(1); // header row only
  });

  it("renders one row per data item with column cells", () => {
    renderWithProviders(<CrudTable data={rows} columns={columns} getRowKey={(w) => w.id} />);
    expect(screen.getByText("Alpha")).toBeInTheDocument();
    expect(screen.getByText("Beta")).toBeInTheDocument();
  });

  it("omits the actions column entirely when onEdit/onDelete/renderRowActions are all absent (read-only mode)", () => {
    renderWithProviders(<CrudTable data={rows} columns={columns} getRowKey={(w) => w.id} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("fires onEdit with the row when the edit action is clicked", async () => {
    const user = userEvent.setup();
    const onEdit = vi.fn();
    renderWithProviders(<CrudTable data={rows} columns={columns} getRowKey={(w) => w.id} onEdit={onEdit} />);
    const editButtons = screen.getAllByRole("button", { name: "Edit" });
    await user.click(editButtons[0]);
    expect(onEdit).toHaveBeenCalledWith(rows[0]);
  });

  it("fires onDelete with the row when the delete action is clicked", async () => {
    const user = userEvent.setup();
    const onDelete = vi.fn();
    renderWithProviders(<CrudTable data={rows} columns={columns} getRowKey={(w) => w.id} onDelete={onDelete} />);
    const deleteButtons = screen.getAllByRole("button", { name: "Delete" });
    await user.click(deleteButtons[0]);
    expect(onDelete).toHaveBeenCalledWith(rows[0]);
  });

  it("renders extra per-row actions from renderRowActions", () => {
    renderWithProviders(
      <CrudTable
        data={rows}
        columns={columns}
        getRowKey={(w) => w.id}
        renderRowActions={(w) => <button>Test {w.name}</button>}
      />
    );
    expect(screen.getByRole("button", { name: "Test Alpha" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Test Beta" })).toBeInTheDocument();
  });
});
