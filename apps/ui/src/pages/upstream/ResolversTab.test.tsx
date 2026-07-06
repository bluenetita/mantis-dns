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
  useCreateUpstreamResolver,
  useDeleteUpstreamResolver,
  useProbeUpstreamResolver,
  useUpdateUpstreamResolver,
  useUpstreamResolvers,
  type UpstreamResolver,
} from "../../api/hooks";
import { ResolversTab } from "./ResolversTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useUpstreamResolvers: vi.fn(),
    useCreateUpstreamResolver: vi.fn(),
    useUpdateUpstreamResolver: vi.fn(),
    useDeleteUpstreamResolver: vi.fn(),
    useProbeUpstreamResolver: vi.fn(),
  };
});

vi.mock("@mantine/modals", () => ({
  modals: { openConfirmModal: vi.fn((config: { onConfirm: () => void }) => config.onConfirm()) },
}));

const mockUseUpstreamResolvers = useUpstreamResolvers as MockedFunction<typeof useUpstreamResolvers>;
const mockUseCreateUpstreamResolver = useCreateUpstreamResolver as MockedFunction<typeof useCreateUpstreamResolver>;
const mockUseUpdateUpstreamResolver = useUpdateUpstreamResolver as MockedFunction<typeof useUpdateUpstreamResolver>;
const mockUseDeleteUpstreamResolver = useDeleteUpstreamResolver as MockedFunction<typeof useDeleteUpstreamResolver>;
const mockUseProbeUpstreamResolver = useProbeUpstreamResolver as MockedFunction<typeof useProbeUpstreamResolver>;

function makeResolver(overrides: Partial<UpstreamResolver> = {}): UpstreamResolver {
  return {
    id: "r1",
    name: "Cloudflare",
    protocol: "dot",
    address: "1.1.1.1",
    port: 853,
    tls_hostname: null,
    tls_pin_sha256: [],
    doh_path: "/dns-query",
    doh_method: "post",
    dnssec_validation: "opportunistic",
    qname_minimization: true,
    edns_client_subnet: false,
    timeout_ms: 5000,
    max_retries: 2,
    connect_timeout_ms: 3000,
    tags: [],
    enabled: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

beforeEach(() => {
  mockUseUpstreamResolvers.mockReset();
  mockUseCreateUpstreamResolver.mockReset();
  mockUseUpdateUpstreamResolver.mockReset();
  mockUseDeleteUpstreamResolver.mockReset();
  mockUseProbeUpstreamResolver.mockReset();
  mockUseCreateUpstreamResolver.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseUpdateUpstreamResolver.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseDeleteUpstreamResolver.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
  mockUseProbeUpstreamResolver.mockReturnValue({ mutate: vi.fn(), isPending: false } as never);
});

describe("ResolversTab", () => {
  it("shows the empty-state card when there are no resolvers", () => {
    mockUseUpstreamResolvers.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ResolversTab />);
    expect(screen.getByText(/No resolvers configured/i)).toBeInTheDocument();
  });

  it("renders a table row per resolver", () => {
    mockUseUpstreamResolvers.mockReturnValue({
      data: [makeResolver({ id: "r1", name: "Cloudflare" }), makeResolver({ id: "r2", name: "Google" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ResolversTab />);
    expect(screen.getByText("Cloudflare")).toBeInTheDocument();
    expect(screen.getByText("Google")).toBeInTheDocument();
  });

  it("opens the add-resolver modal with an empty form", async () => {
    const user = userEvent.setup();
    mockUseUpstreamResolvers.mockReturnValue({ data: [], isLoading: false } as never);
    renderWithProviders(<ResolversTab />);
    await user.click(screen.getByRole("button", { name: /add resolver/i }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Add resolver" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("");
  });

  it("opens the edit modal prefilled with the resolver's values", async () => {
    const user = userEvent.setup();
    mockUseUpstreamResolvers.mockReturnValue({
      data: [makeResolver({ id: "r1", name: "Cloudflare", address: "1.1.1.1" })],
      isLoading: false,
    } as never);
    renderWithProviders(<ResolversTab />);
    await user.click(screen.getByRole("button", { name: "Edit" }));
    expect(await screen.findByRole("heading", { name: "Edit resolver" })).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name/)).toHaveValue("Cloudflare");
    expect(screen.getByLabelText(/^Address/)).toHaveValue("1.1.1.1");
  });

  it("deletes a resolver after confirming, via modals.openConfirmModal", async () => {
    const user = userEvent.setup();
    const deleteMutate = vi.fn();
    mockUseDeleteUpstreamResolver.mockReturnValue({ mutate: deleteMutate, isPending: false } as never);
    const resolver = makeResolver({ id: "r1", name: "Cloudflare" });
    mockUseUpstreamResolvers.mockReturnValue({ data: [resolver], isLoading: false } as never);
    renderWithProviders(<ResolversTab />);

    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(deleteMutate).toHaveBeenCalledWith("r1", expect.anything());
  });
});
