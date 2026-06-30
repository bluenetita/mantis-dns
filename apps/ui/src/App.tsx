import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "./app/Shell";
import { TenantsPage } from "./pages/TenantsPage";
import { GroupsPage } from "./pages/GroupsPage";
import { PolicyPage } from "./pages/PolicyPage";
import { FeedsPage } from "./pages/FeedsPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { AuditPage } from "./pages/AuditPage";
import { SettingsPage } from "./pages/SettingsPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route path="/" element={<Navigate to="/tenants" replace />} />
        <Route path="/tenants" element={<TenantsPage />} />
        <Route path="/tenants/:tenantId" element={<GroupsPage />} />
        <Route path="/tenants/:tenantId/groups/:groupId" element={<PolicyPage />} />
        <Route path="/feeds" element={<FeedsPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/tenants" replace />} />
      </Route>
    </Routes>
  );
}
