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
  useCreateDhcpScope,
  useDeleteDhcpScope,
  useDhcpPush,
  useDhcpScopes,
  useKeaInterfaces,
  useUpdateDhcpScope,
  type DhcpScope,
} from "../../api/hooks";
import { ScopesTab } from "./ScopesTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useDhcpScopes: vi.fn(),
    useCreateDhcpScope: vi.fn(),
    useUpdateDhcpScope: vi.fn(),
    useDeleteDhcpScope: vi.fn(),
    useDhcpPush: vi.fn(),
    useKeaInterfaces: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseDhcpScopes = useDhcpScopes as MockedFunction<typeof useDhcpScopes>;
const mockUseCreateDhcpScope = useCreateDhcpScope as MockedFunction<typeof useCreateDhcpScope>;
const mockUseUpdateDhcpScope = useUpdateDhcpScope as MockedFunction<typeof useUpdateDhcpScope>;
const mockUseDeleteDhcpScope = useDeleteDhcpScope as MockedFunction<typeof useDeleteDhcpScope>;
const mockUseDhcpPush = useDhcpPush as MockedFunction<typeof useDhcpPush>;
const mockUseKeaInterfaces = useKeaInterfaces as MockedFunction<typeof useKeaInterfaces>;

const tenantOptions = [{ value: "t1", label: "Acme" }];
const zoneOptions = [{ value: "z1", label: "corp.local" }];

function makeScope(overrides: Partial<DhcpScope> = {}): DhcpScope {
  return {
    id: "s1",
    tenant_id: "t1",
    name: "office",
    description: null,
    subnet: "10.8.1.0/24",
    range_start: "10.8.1.10",
    range_end: "10.8.1.200",
    router_ip: null,
    dns_servers: [],
    ntp_server: null,
    domain_name: null,
    interface: null,
    vlan_id: null,
    lease_time_s: 86400,
    max_lease_time_s: 604800,
    renew_time_s: null,
    rebind_time_s: null,
    ddns_enabled: false,
    ddns_zone_id: null,
    ddns_ttl_s: 300,
    pxe_next_server: null,
    pxe_boot_filename: null,
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
  mockUseDhcpScopes.mockReset();
  mockUseCreateDhcpScope.mockReset();
  mockUseUpdateDhcpScope.mockReset();
  mockUseDeleteDhcpScope.mockReset();
  mockUseDhcpPush.mockReset();
  mockUseKeaInterfaces.mockReset();
  mockUseCreateDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseUpdateDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDeleteDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseKeaInterfaces.mockReturnValue({
    data: { ok: false, interfaces: [] },
    isFetching: false,
    refetch: vi.fn(),
  } as never);
  mockUseDhcpPush.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
});

describe("ScopesTab", () => {
  it("shows the empty-state message when there are no scopes", () => {
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    expect(screen.getByText(/No scopes configured/i)).toBeInTheDocument();
  });

  it("renders a table row per scope", () => {
    mockUseDhcpScopes.mockReturnValue({
      data: [makeScope({ id: "s1", name: "office" }), makeScope({ id: "s2", name: "guest" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    expect(screen.getByText("office")).toBeInTheDocument();
    expect(screen.getByText("guest")).toBeInTheDocument();
  });

  it("opens the add-scope modal with an empty form", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    expect(await screen.findByRole("heading", { name: "Add scope" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("");
  });

  it("shows the interface field as free text when Kea's interface list is unavailable", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces.mockReturnValue({
      data: { ok: false, interfaces: [] },
      isFetching: false,
      refetch: vi.fn(),
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    expect(await screen.findByRole("textbox", { name: /interface/i })).toBeInTheDocument();
  });

  it("shows the interface field as a dropdown of Kea's detected interfaces", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces.mockReturnValue({
      data: { ok: true, interfaces: [{ name: "eth1", addresses: ["10.50.0.1"], up: true }] },
      isFetching: false,
      refetch: vi.fn(),
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    const field = await screen.findByPlaceholderText("Select interface");
    await user.click(field);
    expect(await screen.findByText("eth1 - 10.50.0.1 - up")).toBeInTheDocument();
  });

  it("keeps the interface field as a dropdown when Kea returns an empty interface list", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces.mockReturnValue({
      data: { ok: true, interfaces: [] },
      isFetching: false,
      refetch: vi.fn(),
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    expect(await screen.findByPlaceholderText("No interfaces detected")).toBeInTheDocument();
  });

  it("refreshes Kea's detected interfaces from the scope form", async () => {
    const user = userEvent.setup();
    const refetch = vi.fn();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    mockUseKeaInterfaces.mockReturnValue({
      data: { ok: true, interfaces: [{ name: "eth1", addresses: ["10.50.0.1"], up: true }] },
      isFetching: false,
      refetch,
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    await user.click(await screen.findByRole("button", { name: /refresh kea interfaces/i }));
    expect(refetch).toHaveBeenCalled();
  });

  it("opens the edit modal prefilled with the scope's values", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({
      data: [makeScope({ id: "s1", name: "office", subnet: "10.8.1.0/24" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(await screen.findByRole("heading", { name: "Edit scope" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("office");
    expect(screen.getByLabelText(/^Subnet/)).toHaveValue("10.8.1.0/24");
  });

  it("deletes a scope after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn().mockResolvedValue(undefined);
    mockUseDeleteDhcpScope.mockReturnValue({ mutateAsync: deleteMutate, isPending: false } as never);
    mockUseDhcpScopes.mockReturnValue({ data: [makeScope({ id: "s1" })], isLoading: false } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("s1");
  });
});
