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
  useCreateDhcpReservation,
  useDeleteDhcpReservation,
  useDhcpReservations,
  useUpdateDhcpReservation,
  type DhcpReservation,
} from "../../api/hooks";
import { ReservationsTab } from "./ReservationsTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useDhcpReservations: vi.fn(),
    useCreateDhcpReservation: vi.fn(),
    useUpdateDhcpReservation: vi.fn(),
    useDeleteDhcpReservation: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseDhcpReservations = useDhcpReservations as MockedFunction<typeof useDhcpReservations>;
const mockUseCreateDhcpReservation = useCreateDhcpReservation as MockedFunction<typeof useCreateDhcpReservation>;
const mockUseUpdateDhcpReservation = useUpdateDhcpReservation as MockedFunction<typeof useUpdateDhcpReservation>;
const mockUseDeleteDhcpReservation = useDeleteDhcpReservation as MockedFunction<typeof useDeleteDhcpReservation>;

const scopeOptions = [{ value: "s1", label: "office (10.8.1.0/24)" }];

function makeReservation(overrides: Partial<DhcpReservation> = {}): DhcpReservation {
  return {
    id: "r1",
    scope_id: "s1",
    tenant_id: "t1",
    mac_address: "aa:bb:cc:dd:ee:ff",
    ip_address: "10.8.1.50",
    hostname: null,
    description: null,
    client_id: null,
    next_server: null,
    boot_filename: null,
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    kea_push_error: null,
    ...overrides,
  };
}

beforeEach(() => {
  mockUseDhcpReservations.mockReset();
  mockUseCreateDhcpReservation.mockReset();
  mockUseUpdateDhcpReservation.mockReset();
  mockUseDeleteDhcpReservation.mockReset();
  mockUseCreateDhcpReservation.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseUpdateDhcpReservation.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDeleteDhcpReservation.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
});

async function selectScope(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByPlaceholderText("Select scope"));
  await user.click(await screen.findByText("office (10.8.1.0/24)"));
}

describe("ReservationsTab", () => {
  it("prompts to select a scope before showing the table", () => {
    mockUseDhcpReservations.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ReservationsTab scopeOptions={scopeOptions} />);
    expect(screen.getByText(/Select a scope to view reservations/i)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders a table row per reservation once a scope is selected", async () => {
    const user = userEvent.setup();
    mockUseDhcpReservations.mockReturnValue({
      data: [makeReservation({ id: "r1", mac_address: "aa:bb:cc:dd:ee:ff" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ReservationsTab scopeOptions={scopeOptions} />);
    await selectScope(user);
    expect(await screen.findByText("aa:bb:cc:dd:ee:ff")).toBeInTheDocument();
  });

  it("opens the add-reservation modal once a scope is selected", async () => {
    const user = userEvent.setup();
    mockUseDhcpReservations.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ReservationsTab scopeOptions={scopeOptions} />);
    await selectScope(user);
    await user.click(screen.getByRole("button", { name: /add reservation/i }));
    expect(await screen.findByRole("heading", { name: "Add reservation" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^MAC address/)).toHaveValue("");
  });

  it("deletes a reservation after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn().mockResolvedValue(undefined);
    mockUseDeleteDhcpReservation.mockReturnValue({ mutateAsync: deleteMutate, isPending: false } as never);
    mockUseDhcpReservations.mockReturnValue({ data: [makeReservation({ id: "r1" })], isLoading: false } as never);
    renderWithProviders(<ReservationsTab scopeOptions={scopeOptions} />);
    await selectScope(user);

    await user.click(await screen.findByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("r1");
  });
});
