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

import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, useSearchParams } from "react-router-dom";
import { useUrlFilters } from "./useUrlFilters";

function wrapper({ children }: { children: ReactNode }) {
  return <MemoryRouter initialEntries={["/log?qname=example.com&offset=40"]}>{children}</MemoryRouter>;
}

describe("useUrlFilters", () => {
  it("reads defaults when nothing is in the URL", () => {
    const { result } = renderHook(
      () => useUrlFilters({ decision: "", hours: "24" }),
      { wrapper: ({ children }) => <MemoryRouter>{children}</MemoryRouter> }
    );
    expect(result.current[0]).toEqual({ decision: "", hours: "24" });
  });

  it("picks up existing values from the URL on mount", () => {
    const { result } = renderHook(
      () => useUrlFilters({ qname: "", offset: "0" }),
      { wrapper }
    );
    expect(result.current[0]).toEqual({ qname: "example.com", offset: "40" });
  });

  it("writes a non-default value into the URL and omits a default one", () => {
    function useCombined() {
      const [params] = useSearchParams();
      const [filters, setFilters] = useUrlFilters({ decision: "", hours: "24" });
      return { params, filters, setFilters };
    }
    const { result } = renderHook(useCombined, { wrapper: ({ children }) => <MemoryRouter>{children}</MemoryRouter> });

    act(() => result.current.setFilters({ decision: "block", hours: "24" }));

    expect(result.current.params.get("decision")).toBe("block");
    expect(result.current.params.get("hours")).toBeNull(); // equals default, omitted
    expect(result.current.filters).toEqual({ decision: "block", hours: "24" });
  });

  it("removes a param from the URL when reset back to its default", () => {
    function useCombined() {
      const [params] = useSearchParams();
      const [filters, setFilters] = useUrlFilters({ category: "" });
      return { params, filters, setFilters };
    }
    const { result } = renderHook(useCombined, { wrapper: ({ children }) => <MemoryRouter>{children}</MemoryRouter> });

    act(() => result.current.setFilters({ category: "malware" }));
    expect(result.current.params.get("category")).toBe("malware");

    act(() => result.current.setFilters({ category: "" }));
    expect(result.current.params.get("category")).toBeNull();
  });
});
