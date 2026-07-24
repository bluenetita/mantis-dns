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
import type { MockedFunction } from "vitest";
import { renderWithProviders } from "../../test/utils";
import { useDhcpHealth, useDhcpStats, type DaemonHeartbeat } from "../../api/hooks";
import { StatusTab } from "./StatusTab";

vi.mock("../../api/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/hooks")>();
  return {
    ...actual,
    useDhcpStats: vi.fn(),
    useDhcpHealth: vi.fn(),
  };
});

const mockUseDhcpStats = useDhcpStats as MockedFunction<typeof useDhcpStats>;
const mockUseDhcpHealth = useDhcpHealth as MockedFunction<typeof useDhcpHealth>;

function makeInstance(overrides: Partial<DaemonHeartbeat> = {}): DaemonHeartbeat {
  return {
    instance_id: "i1",
    family: "4",
    hostname: "bn-mantis01",
    started_at: "2026-01-01T00:00:00",
    last_seen_at: "2026-01-01T00:00:00",
    stale: false,
    ...overrides,
  };
}

beforeEach(() => {
  mockUseDhcpStats.mockReturnValue({ data: [], isLoading: false } as never);
  mockUseDhcpHealth.mockReturnValue({ data: [], isLoading: false } as never);
});

describe("StatusTab", () => {
  it("shows an empty-state message when no daemon has reported in", () => {
    renderWithProviders(<StatusTab />);
    expect(screen.getByText(/No mantis-dhcp\/mantis-dhcp6 instance has reported in/)).toBeInTheDocument();
  });

  it("shows a green Online badge for a fresh heartbeat", () => {
    mockUseDhcpHealth.mockReturnValue({ data: [makeInstance({ stale: false })], isLoading: false } as never);
    renderWithProviders(<StatusTab />);
    expect(screen.getByText("Online")).toBeInTheDocument();
    expect(screen.queryByText("Not responding")).not.toBeInTheDocument();
  });

  it("shows a red Not responding badge for a stale heartbeat", () => {
    mockUseDhcpHealth.mockReturnValue({ data: [makeInstance({ stale: true })], isLoading: false } as never);
    renderWithProviders(<StatusTab />);
    expect(screen.getByText("Not responding")).toBeInTheDocument();
  });

  it("renders the hostname and family for each reporting instance", () => {
    mockUseDhcpHealth.mockReturnValue({
      data: [
        makeInstance({ instance_id: "i1", family: "4", hostname: "bn-mantis01" }),
        makeInstance({ instance_id: "i2", family: "6", hostname: null }),
      ],
      isLoading: false,
    } as never);
    renderWithProviders(<StatusTab />);
    expect(screen.getByText("DHCPv4")).toBeInTheDocument();
    expect(screen.getByText("DHCPv6")).toBeInTheDocument();
    expect(screen.getByText("bn-mantis01")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });
});
