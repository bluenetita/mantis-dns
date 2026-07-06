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
  useCreateUpstreamPool,
  useDeleteUpstreamPool,
  useUpdateUpstreamPool,
  useUpstreamPools,
  useUpstreamResolvers,
  type UpstreamPool,
} from "../../api/hooks";
import { PoolsTab } from "./PoolsTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useUpstreamPools: vi.fn(),
    useUpstreamResolvers: vi.fn(),
    useCreateUpstreamPool: vi.fn(),
    useUpdateUpstreamPool: vi.fn(),
    useDeleteUpstreamPool: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseUpstreamPools = useUpstreamPools as MockedFunction<typeof useUpstreamPools>;
const mockUseUpstreamResolvers = useUpstreamResolvers as MockedFunction<typeof useUpstreamResolvers>;
const mockUseCreateUpstreamPool = useCreateUpstreamPool as MockedFunction<typeof useCreateUpstreamPool>;
const mockUseUpdateUpstreamPool = useUpdateUpstreamPool as MockedFunction<typeof useUpdateUpstreamPool>;
const mockUseDeleteUpstreamPool = useDeleteUpstreamPool as MockedFunction<typeof useDeleteUpstreamPool>;

function makePool(overrides: Partial<UpstreamPool> = {}): UpstreamPool {
  return {
    id: "p1",
    name: "primary",
    strategy: "round_robin",
    health_check_interval_s: 30,
    health_check_timeout_ms: 2000,
    health_check_query: ".",
    health_check_type: "soa",
    unhealthy_threshold: 3,
    healthy_threshold: 2,
    min_healthy_members: 1,
    fallback_pool_id: null,
    members: [],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

beforeEach(() => {
  mockUseUpstreamPools.mockReset();
  mockUseUpstreamResolvers.mockReset();
  mockUseCreateUpstreamPool.mockReset();
  mockUseUpdateUpstreamPool.mockReset();
  mockUseDeleteUpstreamPool.mockReset();
  mockUseUpstreamResolvers.mockReturnValue({ data: [] } as never);
  mockUseCreateUpstreamPool.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseUpdateUpstreamPool.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseDeleteUpstreamPool.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
});

describe("PoolsTab", () => {
  it("shows the empty-state card when there are no pools", () => {
    mockUseUpstreamPools.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<PoolsTab />);
    expect(screen.getByText(/No pools\. Create resolvers first/i)).toBeInTheDocument();
  });

  it("renders a table row per pool", () => {
    mockUseUpstreamPools.mockReturnValue({
      data: [makePool({ id: "p1", name: "primary" }), makePool({ id: "p2", name: "backup" })],
      isLoading: false,
    } as never);
    renderWithProviders(<PoolsTab />);
    expect(screen.getByText("primary")).toBeInTheDocument();
    expect(screen.getByText("backup")).toBeInTheDocument();
  });

  it("opens the add-pool modal with an empty form", async () => {
    const user = userEvent.setup();
    mockUseUpstreamPools.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<PoolsTab />);
    await user.click(screen.getByRole("button", { name: /add pool/i }));
    expect(await screen.findByRole("heading", { name: "Add pool" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Pool name/)).toHaveValue("");
  });

  it("opens the edit modal prefilled with the pool's values", async () => {
    const user = userEvent.setup();
    mockUseUpstreamPools.mockReturnValue({
      data: [makePool({ id: "p1", name: "primary" })],
      isLoading: false,
    } as never);
    renderWithProviders(<PoolsTab />);
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(await screen.findByRole("heading", { name: "Edit pool" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Pool name/)).toHaveValue("primary");
  });

  it("deletes a pool after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn();
    mockUseDeleteUpstreamPool.mockReturnValue({ mutate: deleteMutate, isPending: false } as never);
    mockUseUpstreamPools.mockReturnValue({ data: [makePool({ id: "p1" })], isLoading: false } as never);
    renderWithProviders(<PoolsTab />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("p1", expect.anything());
  });
});
