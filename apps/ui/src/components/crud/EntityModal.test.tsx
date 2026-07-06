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
import { renderWithProviders } from "../../test/utils";
import { EntityModal } from "./EntityModal";

describe("EntityModal", () => {
  it("shows the given title and mounts the form child when opened", () => {
    renderWithProviders(
      <EntityModal opened title="Add resolver" onClose={vi.fn()}>
        <div>resolver form</div>
      </EntityModal>
    );
    expect(screen.getByText("Add resolver")).toBeInTheDocument();
    expect(screen.getByText("resolver form")).toBeInTheDocument();
  });

  it("swaps the title when the caller is in edit mode", () => {
    renderWithProviders(
      <EntityModal opened title="Edit resolver" onClose={vi.fn()}>
        <div>resolver form</div>
      </EntityModal>
    );
    expect(screen.getByText("Edit resolver")).toBeInTheDocument();
  });

  it("renders nothing when not opened", () => {
    renderWithProviders(
      <EntityModal opened={false} title="Add resolver" onClose={vi.fn()}>
        <div>resolver form</div>
      </EntityModal>
    );
    expect(screen.queryByText("Add resolver")).not.toBeInTheDocument();
    expect(screen.queryByText("resolver form")).not.toBeInTheDocument();
  });
});
