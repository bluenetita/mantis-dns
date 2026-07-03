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
} from "@tabler/icons-react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { type Role, useAuth } from "../auth/AuthContext";

const NAV_ITEMS: { to: string; label: string; icon: typeof IconRss; minRole?: Role }[] = [
  { to: "/dashboard", label: "Dashboard", icon: IconLayoutDashboard },
  { to: "/tenants", label: "Tenants & policies", icon: IconBuildingSkyscraper },
  { to: "/feeds", label: "Feeds", icon: IconRss },
  { to: "/zones", label: "DNS Zones", icon: IconWorld },
  { to: "/analytics", label: "Analytics", icon: IconChartBar },
  { to: "/audit", label: "Audit log", icon: IconHistory, minRole: "operator" },
  { to: "/users", label: "Users", icon: IconUsers, minRole: "admin" },
  { to: "/upstream", label: "DNS Upstream", icon: IconServer, minRole: "operator" },
  { to: "/dhcp", label: "DHCP", icon: IconNetwork, minRole: "operator" },
  { to: "/settings", label: "Settings", icon: IconSettings },
];

export function Shell() {
  const [opened, { toggle }] = useDisclosure();
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  const location = useLocation();
  const { user, logout, hasRole } = useAuth();
  const navigate = useNavigate();

  const visibleNavItems = NAV_ITEMS.filter((item) => !item.minRole || hasRole(item.minRole));

  return (
    <AppShell
      header={{ height: 56 }}
      navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="md"
    >
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
              aria-label="Toggle color scheme"
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
                    Sign out
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
            label={item.label}
            leftSection={<item.icon size={18} aria-hidden="true" />}
            active={location.pathname.startsWith(item.to)}
          />
        ))}
      </AppShell.Navbar>

      <AppShell.Main>
        <Outlet />
      </AppShell.Main>
    </AppShell>
  );
}
