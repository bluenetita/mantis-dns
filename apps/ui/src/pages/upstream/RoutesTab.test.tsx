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
import type { MockedFunction } from "vitest";
import { renderWithProviders } from "../../test/utils";
import {
  useCreateUpstreamRoute,
  useDeleteUpstreamRoute,
  useTenants,
  useUpdateUpstreamRoute,
  useUpstreamPools,
  useUpstreamRoutes,
  type UpstreamRoute,
} from "../../api/hooks";
import { RoutesTab } from "./RoutesTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useTenants: vi.fn(),
    useUpstreamPools: vi.fn(),
    useUpstreamRoutes: vi.fn(),
    useCreateUpstreamRoute: vi.fn(),
    useUpdateUpstreamRoute: vi.fn(),
    useDeleteUpstreamRoute: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseTenants = useTenants as MockedFunction<typeof useTenants>;
const mockUseUpstreamPools = useUpstreamPools as MockedFunction<typeof useUpstreamPools>;
const mockUseUpstreamRoutes = useUpstreamRoutes as MockedFunction<typeof useUpstreamRoutes>;
const mockUseCreateUpstreamRoute = useCreateUpstreamRoute as MockedFunction<typeof useCreateUpstreamRoute>;
const mockUseUpdateUpstreamRoute = useUpdateUpstreamRoute as MockedFunction<typeof useUpdateUpstreamRoute>;
const mockUseDeleteUpstreamRoute = useDeleteUpstreamRoute as MockedFunction<typeof useDeleteUpstreamRoute>;

function makeRoute(overrides: Partial<UpstreamRoute> = {}): UpstreamRoute {
  return {
    id: "rt1",
    name: "internal-domains",
    tenant_id: "t1",
    group_id: null,
    match_type: "domain_suffix",
    match_value: ".corp.local",
    pool_id: "p1",
    nxdomain_ttl_override: null,
    require_dnssec: null,
    priority: 100,
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

beforeEach(() => {
  mockUseTenants.mockReset();
  mockUseUpstreamPools.mockReset();
  mockUseUpstreamRoutes.mockReset();
  mockUseCreateUpstreamRoute.mockReset();
  mockUseUpdateUpstreamRoute.mockReset();
  mockUseDeleteUpstreamRoute.mockReset();
  mockUseTenants.mockReturnValue({ data: [{ id: "t1", name: "Acme" }] } as never);
  mockUseUpstreamPools.mockReturnValue({ data: [] } as never);
  mockUseCreateUpstreamRoute.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseUpdateUpstreamRoute.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseDeleteUpstreamRoute.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
});

async function selectTenant(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("combobox", { name: "Tenant" }));
  await user.click(await screen.findByText("Acme"));
}

describe("RoutesTab", () => {
  it("hides the table and add button until a tenant is selected", () => {
    mockUseUpstreamRoutes.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<RoutesTab />);
    expect(screen.queryByRole("button", { name: /add route/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows the routes table after selecting a tenant", async () => {
    const user = userEvent.setup();
    mockUseUpstreamRoutes.mockReturnValue({
      data: [makeRoute({ id: "rt1", name: "internal-domains" })],
      isLoading: false,
    } as never);
    renderWithProviders(<RoutesTab />);
    await selectTenant(user);
    expect(await screen.findByText("internal-domains")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /add route/i })).toBeInTheDocument();
  });

  it("opens the add-route modal with an empty form once a tenant is selected", async () => {
    const user = userEvent.setup();
    mockUseUpstreamRoutes.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<RoutesTab />);
    await selectTenant(user);
    await user.click(screen.getByRole("button", { name: /add route/i }));
    expect(await screen.findByRole("heading", { name: "Add route" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("");
  });

  it("deletes a route after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn();
    mockUseDeleteUpstreamRoute.mockReturnValue({ mutate: deleteMutate, isPending: false } as never);
    mockUseUpstreamRoutes.mockReturnValue({ data: [makeRoute({ id: "rt1" })], isLoading: false } as never);
    renderWithProviders(<RoutesTab />);
    await selectTenant(user);

    await user.click(await screen.findByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("rt1", expect.anything());
  });
});
