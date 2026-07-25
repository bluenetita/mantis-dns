# UX review — management UI

Scope: `apps/ui/src` (19k lines, 15 routes, Mantine 9). Read every page, shell,
auth layer, CRUD primitives and the API client. Findings are grouped by
severity, then sequenced into a plan.

Context: Epic J (sprint-plan.md §Sprint 11–13) shipped the foundation. Its own
exit criteria log WCAG AA, E2E and visual-regression as **not met**. This review
covers what is actually in the code today, not the plan's letter.

---

## P0 — Broken or misleading

### 1. Dashboard tenant filter does nothing

`DashboardPage.tsx:78,171` — `tenantFilter` is read into a `Select` and written
by `onChange`. It is passed to zero queries. Every one of the six analytics
queries fetches all tenants regardless. A user selects "Acme" and reads
whole-fleet numbers as if they were Acme's.

Either wire `tenant_id` through `rawGet` on all six calls (needs the API to
accept it) or delete the control. Deleting is one line and honest; wiring is
correct if the backend supports it. **Check the API first, then pick.**

### 2. No unsaved-changes protection on the policy editor

`PolicyPage.tsx` holds `categoryToggles`, `overrides`, `onLoadFailure` in local
state. Nothing marks the form dirty, nothing blocks navigation. Clicking the
"Tenants" breadcrumb, the back button, or a nav item silently discards every
edit. `applyDuplicatedPolicy` makes it worse — it loads a whole foreign policy
into local state and only shows a toast saying "review and click Save policy".

This is the app's highest-value screen and the easiest place to lose work.

### 3. Save is buried; publish is a separate, unexplained step

Same page. "Save policy" sits below the category grid, the overrides card, the
failure-policy card, the block-page card and the domain tester — roughly two
screens of scroll from where editing starts. Next to it, "Compile & publish
bundle" is a second button with no indication that saving alone does not reach
the filter nodes, and no signal of whether the currently saved policy has been
published or is stale.

### 4. "Test a domain" tests the saved policy, not the draft

`PolicyPage.tsx` — the tester hits `POST /groups/{id}/policy/test`, which reads
persisted state. The dimmed caption says so, but a user who toggles a category
and immediately tests gets a result for the *old* policy with no warning. Either
disable the tester while dirty or label the result "against last saved policy".

### 5. Session expiry hard-reloads and loses your place

`api/client.ts:56` — `handleUnauthorized` does `window.location.assign("/login")`.
Full page reload, no `state.from`, so after re-login you land on `/tenants`
rather than where you were, and any open form is gone. `RequireAuth` already has
the correct pattern (`Navigate` with `state: { from }`) — the client bypasses it.

### 6. ErrorBoundary is app-root only, and shows a raw stack trace

`main.tsx:49` wraps the whole tree. Any render error blanks the entire shell —
nav, header, everything — which is exactly what its own doc comment claims to
prevent ("Scoping this at the route level (see App.tsx)"; App.tsx does not use
it). It then renders `error.stack` in a `<Code block>` to an operator who cannot
act on it.

---

## P1 — Systemic gaps

### 7. Tables are not usable on anything narrow

Zero `Table.ScrollContainer` in the codebase. Zero `visibleFrom`/`hiddenFrom`
outside the `Burger`. `ZonesPage` renders 8 columns, `QueryLogPage` 8, the DHCP
tabs 6–7. On a laptop at 1280 with the 240px navbar these already crowd; on a
tablet or phone the page body scrolls horizontally. The shell is responsive; the
content is not.

### 8. Row navigation is mouse-only

7 places use `onClick` on a `Table.Tr` or a `<Text style={{cursor:"pointer"}}>`
to navigate. Zero `onKeyDown`, zero `tabIndex` in the whole app. Keyboard users
cannot open a tenant, a zone, or a group. Middle-click and ⌘-click don't open a
new tab either, because these aren't links.

`ZonesPage` gets this half-right — the row has a redundant `IconExternalLink`
action — but the primary target is still a fake link.

### 9. Filter state is invisible to the URL

Only `DhcpPage` uses `useSearchParams` (and does it well: family + tab both
survive reload and sharing). `QueryLogPage` has six filters plus an offset,
`ZonesPage` three, `FeedsPage` several — all in `useState`. Consequences: no
shareable "here's the blocked-query view I'm looking at" link, no back-button
undo of a filter, filters reset on every tab switch or accidental reload.

For an operations tool where "send me the link to what you're seeing" is a daily
act, this is a bigger loss than it looks.

### 10. Errors are stringified exceptions

57 occurrences of `String(e)` / `String(error)` in notifications and inline
error text. `client.ts` throws `new Error(\`${status}: ${detail}\`)`, so the user
sees `Error: 422: {"detail":"subnet overlaps scope 4f2a…"}` in a red toast. The
useful part is in there, wrapped in noise. There is no shared error formatter
and no mapping of 403 → "you don't have permission", 409 → "already exists".

### 11. i18n is scaffolding, not translation

`i18n.ts` loads `en` only. 79 lines of keys. 36 of 47 components have zero
`useTranslation`. Two components (`QueryLogPage`, `AuditPage`) are fully
translated, one partially, the rest hardcode English. So the dependency, the
setup, and the maintenance burden are paid in full for approximately nothing.

Decide: commit (extract everything, add a second locale, add a language switch)
or revert (delete `i18n.ts`, inline the ~40 translated strings). The current
state is the worst of both.

### 12. No sorting, no bulk actions except on one page

Zero sortable columns app-wide. A 40-zone or 200-reservation table can only be
read in server order. `FeedsPage` has select-all + bulk enable/disable/sync/
delete; nothing else does — not zones, reservations, users, clients or
resolvers. An admin cleaning up 30 stale reservations clicks 30 times.

### 13. Loading is a centered spinner that replaces the page

No `Skeleton` anywhere. Every page does `if (isLoading) return <Center><Loader/>`
— so the header, filters and nav context vanish on every refetch, and layout
jumps when data lands. With `staleTime: 10_000` and 15–30s `refetchInterval`s
this happens constantly.

### 14. Dashboard has no error state

Six `useQuery` calls in `DashboardPage.tsx`, six `isLoading` flags, zero `error`
handling. When `/analytics/summary` 500s, the KPIs show `0` and the charts show
empty. Zero blocked queries reads as "everything is fine", which is the single
most dangerous false reading a DNS filtering product can present.

---

## P2 — Consistency and polish

### 15. Four `KpiCard` implementations

`dashboard/widgets/shared.tsx:54` (exported), plus private copies in
`AnalyticsPage.tsx:52`, `FeedsPage.tsx:109`, `ZonesPage.tsx:82`. Different
padding, different `sub` treatment, one has a progress bar. Same visual role.

### 16. Three time-range controls, three refresh conventions

- Dashboard: `SegmentedControl` + `Badge "auto-refresh 30s"`, no manual refresh
- Analytics: `Button.Group` + refresh `ActionIcon` + `Text "Auto-refresh 15s"`
- Query log: `SegmentedControl`, different bucket set (`1h/6h/24h/7d/All`), no refresh indicator

Intervals themselves are scattered: 10s, 15s, 30s, 60s across `hooks.ts` and
`DashboardPage.tsx`, with no rationale attached to any of them.

### 17. Page headers differ per page

`TenantsPage` and `QueryLogPage`: bare `<Title order={2}>`. `ZonesPage`,
`UpstreamPage`, `AnalyticsPage`: title + dimmed description. `DhcpPage`: icon +
title + conditional status badge. `SettingsPage`: title + tabs. No shared
`PageHeader`, so every new page re-decides.

### 18. Duplicated formatters

`timeAgo` (`dhcp/StatusTab.tsx:21`) and `relativeTime` (`FeedsPage.tsx:87`) are
the same function. `latencyLabel`, `fmtInterval`, `fmtDomains` are page-private.
Timestamps elsewhere are raw `new Date(x).toLocaleString()`.

### 19. `UpstreamPage` tabs aren't in the URL

`defaultValue="resolvers"`, no `useSearchParams`. `DhcpPage` next door does it
right. Same for `SettingsPage`.

### 20. Login form has no autocomplete hints

Zero `autoComplete` attributes app-wide. `LoginPage` email/password should carry
`username` / `current-password` so password managers fill reliably; the password
change form in `SettingsPage.tsx:233` should carry `current-password` /
`new-password`.

### 21. Breadcrumbs say the entity type, not the entity

`PolicyPage`: `Tenants / Groups / Policy`. Three levels deep and none of them
names which tenant or which group you are in. `ClientsPage`, `GroupsPage`,
`ZoneDetailPage` follow the same shape.

### 22. Dashboard and Analytics overlap

Both render query volume over time, decision breakdown, top blocked domains and
per-group performance, at different refresh rates with different controls. Two
nav entries, one job. Either make Dashboard the customizable overview and
Analytics the drill-down (and remove the duplicated widgets from one of them),
or merge.

---

## Plan

Sequenced so each phase ships something an operator notices, and so the shared
primitives land before the pages that need them.

### Phase 1 — Stop the bleeding (P0)

| # | Change | Files |
|---|--------|-------|
| 1 | Wire or delete the dashboard tenant filter | `DashboardPage.tsx` |
| 2 | Dirty-state tracking + `useBlocker` nav guard + sticky save bar on the policy editor | `PolicyPage.tsx` |
| 3 | Publish state: show whether the saved policy is compiled, disable "Compile" when it is | `PolicyPage.tsx`, `hooks.ts` |
| 4 | Disable the domain tester while dirty, with a one-line reason | `PolicyPage.tsx` |
| 5 | 401 → in-app redirect preserving `from`, replacing `location.assign` | `api/client.ts` |
| 6 | Move `ErrorBoundary` to wrap `<Outlet/>` inside `Shell`; hide the stack behind a "Details" toggle | `Shell.tsx`, `ErrorBoundary.tsx`, `main.tsx` |

Phase 1 touches 5 files and removes every way the app currently loses work or
lies about state.

### Phase 2 — Shared primitives (kills most of P2 as a side effect)

Build once, in `src/components/`:

- `PageHeader` — icon, title, description, actions, optional status slot (#17)
- `KpiCard` — promote `dashboard/widgets/shared.tsx`, delete the three copies (#15)
- `DataTable` — wrap `CrudTable` in `Table.ScrollContainer`, add optional column sort and row-link support (#7, #8, #12)
- `useUrlFilters` — `useSearchParams`-backed filter state, one hook (#9)
- `formatError(e)` — status → human message, detail extraction (#10)
- `formatRelativeTime` / `formatDuration` — one home, delete the copies (#18)

Nothing new is invented here; each is an extraction of a pattern already written
2–4 times. `DhcpPage` is the reference implementation for URL state.

### Phase 3 — Apply the primitives

Page-by-page migration, ordered by traffic:

1. `QueryLogPage` — URL filters, scroll container, skeleton rows
2. `ZonesPage` — URL filters, real `<Link>` rows, sortable name/type/records
3. `FeedsPage` — URL filters, scroll container
4. `DhcpPage` tabs, `ClientsPage`, `UsersPage` — scroll containers, row links, bulk select on reservations and clients
5. `UpstreamPage`, `SettingsPage` — tab state into the URL
6. `DashboardPage` — error states on all six queries (#14), reconcile with Analytics (#22)

### Phase 4 — Decide the deferred questions

These are calls to make, not code to write, and they should be made explicitly
rather than by neglect:

- **i18n**: commit or revert (#11). Recommend revert unless a non-English customer is actually in the pipeline — the scaffolding costs maintenance every new string and returns nothing today.
- **Dashboard vs Analytics** (#22): merge or differentiate.
- **Refresh policy** (#16): one interval constant, one control component, documented reason.
- **WCAG AA**: Sprint 13's unmet exit criterion. Phase 2's `DataTable` and Phase 1's focus work close the largest gaps (keyboard nav, focus management); an actual audit run is still owed.

### Not doing

- No design-system rewrite. Mantine 9 is fine and the theme is three lines; the problem is inconsistent *use*, which Phase 2 fixes.
- No virtualization. Server-side pagination already covers the stated failure mode (sprint-plan.md notes this).
- No new dependencies. Everything above is Mantine, React Router, or ~20 lines.
- No Storybook / visual regression. Not until the primitives in Phase 2 are stable enough to be worth snapshotting.
