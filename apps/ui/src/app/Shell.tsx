import { AppShell, Avatar, Burger, Group, Menu, NavLink as MantineNavLink, Text, ActionIcon, Badge, useMantineColorScheme } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconBuildingSkyscraper,
  IconRss,
  IconLayoutDashboard,
  IconHistory,
  IconSettings,
  IconSun,
  IconMoon,
  IconShieldLock,
  IconLogout,
  IconWorld,
  IconChartBar,
  IconUsers,
  IconServer,
  IconNetwork,
  IconList,
} from "@tabler/icons-react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { type Role, useAuth } from "../auth/AuthContext";

const NAV_ITEMS: { to: string; labelKey: string; icon: typeof IconRss; minRole?: Role }[] = [
  { to: "/dashboard", labelKey: "nav.dashboard", icon: IconLayoutDashboard },
  { to: "/tenants", labelKey: "nav.tenants", icon: IconBuildingSkyscraper },
  { to: "/feeds", labelKey: "nav.feeds", icon: IconRss },
  { to: "/zones", labelKey: "nav.dnsZones", icon: IconWorld },
  { to: "/analytics", labelKey: "nav.analytics", icon: IconChartBar },
  { to: "/query-log", labelKey: "nav.queryLog", icon: IconList, minRole: "operator" },
  { to: "/audit", labelKey: "nav.auditLog", icon: IconHistory, minRole: "operator" },
  { to: "/users", labelKey: "nav.users", icon: IconUsers, minRole: "admin" },
  { to: "/upstream", labelKey: "nav.dnsUpstream", icon: IconServer, minRole: "operator" },
  { to: "/dhcp", labelKey: "nav.dhcp", icon: IconNetwork, minRole: "operator" },
  { to: "/settings", labelKey: "nav.settings", icon: IconSettings },
];

export function Shell() {
  const [opened, { toggle }] = useDisclosure();
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  const location = useLocation();
  const { user, logout, hasRole } = useAuth();
  const navigate = useNavigate();
  const { t } = useTranslation();

  const visibleNavItems = NAV_ITEMS.filter((item) => !item.minRole || hasRole(item.minRole));

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="md"
    >
      {/* Skip link — keyboard users jump straight to main content */}
      <a
        href="#main-content"
        style={{
          position: "absolute",
          left: "-9999px",
          top: "auto",
          width: "1px",
          height: "1px",
          overflow: "hidden",
        }}
        onFocus={(e) => {
          e.currentTarget.style.left = "8px";
          e.currentTarget.style.top = "8px";
          e.currentTarget.style.width = "auto";
          e.currentTarget.style.height = "auto";
          e.currentTarget.style.overflow = "visible";
          e.currentTarget.style.zIndex = "9999";
          e.currentTarget.style.padding = "8px 16px";
          e.currentTarget.style.background = "var(--mantine-color-blue-6)";
          e.currentTarget.style.color = "#fff";
          e.currentTarget.style.borderRadius = "4px";
        }}
        onBlur={(e) => {
          e.currentTarget.style.left = "-9999px";
          e.currentTarget.style.top = "auto";
          e.currentTarget.style.width = "1px";
          e.currentTarget.style.height = "1px";
          e.currentTarget.style.overflow = "hidden";
        }}
      >
        Skip to main content
      </a>
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group>
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <IconShieldLock size={22} aria-hidden="true" />
            <Text fw={500}>Aegis-DNS</Text>
          </Group>
          <Group>
            <ActionIcon
              variant="default"
              onClick={() => toggleColorScheme()}
              aria-label={t("common.toggleColorScheme")}
            >
              {colorScheme === "dark" ? <IconSun size={16} /> : <IconMoon size={16} />}
            </ActionIcon>
            {user && (
              <Menu shadow="md" width={200} position="bottom-end">
                <Menu.Target>
                  <Group gap="xs" style={{ cursor: "pointer" }}>
                    <Avatar radius="xl" size={28}>
                      {user.email.slice(0, 1).toUpperCase()}
                    </Avatar>
                    <div>
                      <Text size="xs" fw={500} lh={1.1}>
                        {user.email}
                      </Text>
                      <Badge size="xs" variant="light">
                        {user.role}
                      </Badge>
                    </div>
                  </Group>
                </Menu.Target>
                <Menu.Dropdown>
                  <Menu.Item
                    color="red"
                    leftSection={<IconLogout size={14} />}
                    onClick={() => {
                      logout();
                      navigate("/login", { replace: true });
                    }}
                  >
                    {t("common.signOut")}
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            )}
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        {visibleNavItems.map((item) => (
          <MantineNavLink
            key={item.to}
            component={NavLink}
            to={item.to}
            label={t(item.labelKey)}
            leftSection={<item.icon size={18} aria-hidden="true" />}
            active={location.pathname.startsWith(item.to)}
          />
        ))}
      </AppShell.Navbar>

      <AppShell.Main id="main-content">
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
