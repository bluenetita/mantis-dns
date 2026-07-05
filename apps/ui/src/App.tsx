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

import { Center, Loader } from "@mantine/core";
import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./app/Shell";
import { RequireAuth } from "./auth/RequireAuth";
import { LoginPage } from "./pages/LoginPage";

// Route-level code splitting: each admin page becomes its own chunk, loaded
// on first navigation instead of all being bundled into the initial JS
// payload. LoginPage stays eager since it's the one page unauthenticated
// visitors always hit first.
const TenantsPage = lazy(() => import("./pages/TenantsPage").then((m) => ({ default: m.TenantsPage })));
const GroupsPage = lazy(() => import("./pages/GroupsPage").then((m) => ({ default: m.GroupsPage })));
const PolicyPage = lazy(() => import("./pages/PolicyPage").then((m) => ({ default: m.PolicyPage })));
const FeedsPage = lazy(() => import("./pages/FeedsPage").then((m) => ({ default: m.FeedsPage })));
const AnalyticsPage = lazy(() => import("./pages/AnalyticsPage").then((m) => ({ default: m.AnalyticsPage })));
const AuditPage = lazy(() => import("./pages/AuditPage").then((m) => ({ default: m.AuditPage })));
const DashboardPage = lazy(() => import("./pages/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const ClientsPage = lazy(() => import("./pages/ClientsPage").then((m) => ({ default: m.ClientsPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));
const ZonesPage = lazy(() => import("./pages/ZonesPage").then((m) => ({ default: m.ZonesPage })));
const ZoneDetailPage = lazy(() => import("./pages/ZoneDetailPage").then((m) => ({ default: m.ZoneDetailPage })));
const UsersPage = lazy(() => import("./pages/UsersPage").then((m) => ({ default: m.UsersPage })));
const UpstreamPage = lazy(() => import("./pages/UpstreamPage").then((m) => ({ default: m.UpstreamPage })));
const DhcpPage = lazy(() => import("./pages/DhcpPage").then((m) => ({ default: m.DhcpPage })));
const QueryLogPage = lazy(() => import("./pages/QueryLogPage").then((m) => ({ default: m.QueryLogPage })));

function RouteFallback() {
  return (
    <Center h="60vh">
      <Loader />
    </Center>
  );
}

export default function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<RequireAuth />}>
          <Route element={<Shell />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/tenants" element={<TenantsPage />} />
            <Route path="/tenants/:tenantId" element={<GroupsPage />} />
            <Route path="/tenants/:tenantId/clients" element={<ClientsPage />} />
            <Route path="/tenants/:tenantId/groups/:groupId" element={<PolicyPage />} />
            <Route path="/feeds" element={<FeedsPage />} />
            <Route path="/zones" element={<ZonesPage />} />
            <Route path="/zones/:zoneId" element={<ZoneDetailPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/query-log" element={<QueryLogPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/upstream" element={<UpstreamPage />} />
            <Route path="/dhcp" element={<DhcpPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/tenants" replace />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}
