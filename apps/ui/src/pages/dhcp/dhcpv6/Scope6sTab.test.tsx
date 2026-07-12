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
import { renderWithProviders } from "../../../test/utils";
import {
  useCreateDhcpScope6,
  useDeleteDhcpScope6,
  useDhcpPush6,
  useDhcpScopes6,
  useKeaInterfaces6,
  useUpdateDhcpScope6,
  type DhcpScope6,
} from "../../../api/hooks";
import { Scope6sTab } from "./Scope6sTab";

vi.mock("../../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../../api/hooks")>();
  return {
    ...actual,
    useDhcpScopes6: vi.fn(),
    useCreateDhcpScope6: vi.fn(),
    useUpdateDhcpScope6: vi.fn(),
    useDeleteDhcpScope6: vi.fn(),
    useDhcpPush6: vi.fn(),
    useKeaInterfaces6: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseDhcpScopes6 = useDhcpScopes6 as MockedFunction<typeof useDhcpScopes6>;
const mockUseCreateDhcpScope6 = useCreateDhcpScope6 as MockedFunction<typeof useCreateDhcpScope6>;
const mockUseUpdateDhcpScope6 = useUpdateDhcpScope6 as MockedFunction<typeof useUpdateDhcpScope6>;
const mockUseDeleteDhcpScope6 = useDeleteDhcpScope6 as MockedFunction<typeof useDeleteDhcpScope6>;
const mockUseDhcpPush6 = useDhcpPush6 as MockedFunction<typeof useDhcpPush6>;
const mockUseKeaInterfaces6 = useKeaInterfaces6 as MockedFunction<typeof useKeaInterfaces6>;

const tenantOptions = [{ value: "t1", label: "Acme" }];

function makeScope6(overrides: Partial<DhcpScope6> = {}): DhcpScope6 {
  return {
    id: "s1",
    tenant_id: "t1",
    name: "office-v6",
    description: null,
    subnet: "2001:db8::/48",
    pool_start: "2001:db8::1000",
    pool_end: "2001:db8::2000",
    pd_prefix: null,
    pd_prefix_len: null,
    dns_servers: [],
    domain_name: null,
    interface: null,
    preferred_lifetime_s: 3000,
    valid_lifetime_s: 4000,
    renew_time_s: null,
    rebind_time_s: null,
    ddns_enabled: false,
    ddns_zone_id: null,
    ddns_ttl_s: 300,
    kea_subnet_id: 1,
    last_pushed_at: null,
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    kea_push_error: null,
    ...overrides,
  };
}

beforeEach(() => {
  mockUseDhcpScopes6.mockReset();
  mockUseCreateDhcpScope6.mockReset();
  mockUseUpdateDhcpScope6.mockReset();
  mockUseDeleteDhcpScope6.mockReset();
  mockUseDhcpPush6.mockReset();
  mockUseKeaInterfaces6.mockReset();
  mockUseCreateDhcpScope6.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseUpdateDhcpScope6.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDeleteDhcpScope6.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDhcpPush6.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseKeaInterfaces6.mockReturnValue({
    data: { ok: false, interfaces: [] },
    isFetching: false,
    refetch: vi.fn(),
  } as never);
});

describe("Scope6sTab", () => {
  it("shows the empty-state message when there are no IPv6 scopes", () => {
    mockUseDhcpScopes6.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    expect(screen.getByText(/No IPv6 scopes configured/i)).toBeInTheDocument();
  });

  it("renders a table row per scope", () => {
    mockUseDhcpScopes6.mockReturnValue({
      data: [makeScope6({ id: "s1", name: "office-v6" }), makeScope6({ id: "s2", name: "guest-v6" })],
      isLoading: false,
    } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    expect(screen.getByText("office-v6")).toBeInTheDocument();
    expect(screen.getByText("guest-v6")).toBeInTheDocument();
  });

  it("opens the add-scope modal with an empty form", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes6.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    expect(await screen.findByRole("heading", { name: "Add IPv6 scope" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("");
  });

  it("shows the interface field as a dropdown of Kea's detected IPv6 interfaces", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes6.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces6.mockReturnValue({
      data: { ok: true, interfaces: [{ name: "eth2", addresses: ["2001:db8::1"], up: true }] },
      isFetching: false,
      refetch: vi.fn(),
    } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    const field = await screen.findByPlaceholderText("Select interface");
    await user.click(field);
    expect(await screen.findByText("eth2 - 2001:db8::1 - up")).toBeInTheDocument();
  });

  it("keeps the interface field as a dropdown when Kea returns an empty IPv6 interface list", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes6.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces6.mockReturnValue({
      data: { ok: true, interfaces: [] },
      isFetching: false,
      refetch: vi.fn(),
    } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    expect(await screen.findByPlaceholderText("No interfaces detected")).toBeInTheDocument();
  });

  it("refreshes Kea's detected IPv6 interfaces from the scope form", async () => {
    const user = userEvent.setup();
    const refetch = vi.fn();
    mockUseDhcpScopes6.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces6.mockReturnValue({
      data: { ok: true, interfaces: [{ name: "eth2", addresses: ["2001:db8::1"], up: true }] },
      isFetching: false,
      refetch,
    } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    await user.click(await screen.findByRole("button", { name: /refresh kea interfaces/i }));
    expect(refetch).toHaveBeenCalled();
  });

  it("deletes a scope after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn().mockResolvedValue(undefined);
    mockUseDeleteDhcpScope6.mockReturnValue({ mutateAsync: deleteMutate, isPending: false } as never);
    mockUseDhcpScopes6.mockReturnValue({ data: [makeScope6({ id: "s1" })], isLoading: false } as never);
    renderWithProviders(<Scope6sTab tenantOptions={tenantOptions} />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("s1");
  });
});
