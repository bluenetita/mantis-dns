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

import { renderHook } from "@testing-library/react";
import { confirmNavigation, isNavigationBlocked, useUnsavedChangesGuard } from "./useUnsavedChangesGuard";

describe("useUnsavedChangesGuard / confirmNavigation", () => {
  it("runs proceed() immediately when nothing is dirty", () => {
    renderHook(() => useUnsavedChangesGuard(false));
    const proceed = vi.fn();
    confirmNavigation(proceed);
    expect(proceed).toHaveBeenCalledOnce();
  });

  it("marks navigation blocked while dirty and clears it on unmount", () => {
    const { unmount } = renderHook(() => useUnsavedChangesGuard(true));
    expect(isNavigationBlocked()).toBe(true);
    unmount();
    expect(isNavigationBlocked()).toBe(false);
  });

  it("does not run proceed() synchronously while dirty (routes through the confirm modal)", () => {
    renderHook(() => useUnsavedChangesGuard(true));
    const proceed = vi.fn();
    confirmNavigation(proceed);
    expect(proceed).not.toHaveBeenCalled();
  });
});
