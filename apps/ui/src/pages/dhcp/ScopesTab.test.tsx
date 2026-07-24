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
  useDhcpInterfaces,
  useDhcpScopes,
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
    useDhcpInterfaces: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseDhcpScopes = useDhcpScopes as MockedFunction<typeof useDhcpScopes>;
const mockUseCreateDhcpScope = useCreateDhcpScope as MockedFunction<typeof useCreateDhcpScope>;
const mockUseUpdateDhcpScope = useUpdateDhcpScope as MockedFunction<typeof useUpdateDhcpScope>;
const mockUseDeleteDhcpScope = useDeleteDhcpScope as MockedFunction<typeof useDeleteDhcpScope>;
const mockUseDhcpInterfaces = useDhcpInterfaces as MockedFunction<typeof useDhcpInterfaces>;

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
    pxe_uefi_boot_filename: null,
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

beforeEach(() => {
  mockUseDhcpScopes.mockReset();
  mockUseCreateDhcpScope.mockReset();
  mockUseUpdateDhcpScope.mockReset();
  mockUseDeleteDhcpScope.mockReset();
  mockUseCreateDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseUpdateDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDeleteDhcpScope.mockReturnValue({ mutateAsync: vi.fn(), isPending: false } as never);
  mockUseDhcpInterfaces.mockReturnValue({ data: ["eth0", "eth1"], isLoading: false } as never);
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

  it("offers the fetched interfaces in the interface dropdown", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: /add scope/i }));
    const field = await screen.findByRole("combobox", { name: /^Interface/ });
    await user.click(field);
    await user.click(await screen.findByText("eth1"));
    expect(field).toHaveValue("eth1");
  });

  it("keeps a scope's existing interface selectable even if it's not in the fetched list", async () => {
    const user = userEvent.setup();
    mockUseDhcpScopes.mockReturnValue({
      data: [makeScope({ id: "s1", interface: "eth9" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ScopesTab tenantOptions={tenantOptions} zoneOptions={zoneOptions} />);
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const field = await screen.findByRole("combobox", { name: /^Interface/ });
    expect(field).toHaveValue("eth9");
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
