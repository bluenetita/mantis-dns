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

import { useEffect } from "react";
import { modals } from "@mantine/modals";

// ponytail: module-level singleton, not a React context — the app only ever
// has one "dirty" editor mounted at a time. Covers in-app nav (Shell sidebar,
// breadcrumbs) and tab close/refresh. Does NOT intercept the browser
// back/forward buttons — that needs a data router (useBlocker), which this
// app's <BrowserRouter>/<Routes> setup doesn't use. Upgrade path: migrate to
// createBrowserRouter if back-button loss becomes a real complaint.
let isBlocked = false;

export function isNavigationBlocked(): boolean {
  return isBlocked;
}

/** Registers `dirty` as the current "would lose unsaved work" state for the
 * mounted page. Call from the page that owns the editable form. */
export function useUnsavedChangesGuard(dirty: boolean) {
  useEffect(() => {
    isBlocked = dirty;
    return () => {
      isBlocked = false;
    };
  }, [dirty]);

  useEffect(() => {
    function onBeforeUnload(e: BeforeUnloadEvent) {
      if (!dirty) return;
      e.preventDefault();
      e.returnValue = "";
    }
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [dirty]);
}

/** Wrap any in-app navigation (link click, nav item click) that should be
 * confirmed when there are unsaved changes. Runs `proceed` immediately if
 * nothing is blocking. */
export function confirmNavigation(proceed: () => void) {
  if (!isBlocked) {
    proceed();
    return;
  }
  modals.openConfirmModal({
    title: "Unsaved changes",
    children: "You have unsaved policy changes. Discard them and leave this page?",
    labels: { confirm: "Discard changes", cancel: "Stay" },
    confirmProps: { color: "red" },
    onConfirm: proceed,
  });
}
