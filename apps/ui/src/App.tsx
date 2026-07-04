import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./app/Shell";
import { RequireAuth } from "./auth/RequireAuth";
import { LoginPage } from "./pages/LoginPage";
import { TenantsPage } from "./pages/TenantsPage";
import { GroupsPage } from "./pages/GroupsPage";
import { PolicyPage } from "./pages/PolicyPage";
import { FeedsPage } from "./pages/FeedsPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { ClientsPage } from "./pages/ClientsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { ZonesPage } from "./pages/ZonesPage";
import { ZoneDetailPage } from "./pages/ZoneDetailPage";
import { UsersPage } from "./pages/UsersPage";
import { UpstreamPage } from "./pages/UpstreamPage";
import { DhcpPage } from "./pages/DhcpPage";
import { QueryLogPage } from "./pages/QueryLogPage";

export default function App() {
  return (
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
  );
}
