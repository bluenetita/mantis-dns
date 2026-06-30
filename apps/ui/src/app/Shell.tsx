import { AppShell, Burger, Group, NavLink as MantineNavLink, Text, ActionIcon, useMantineColorScheme } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconBuildingSkyscraper,
  IconRss,
  IconChartBar,
  IconHistory,
  IconSettings,
  IconSun,
  IconMoon,
  IconShieldLock,
} from "@tabler/icons-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/tenants", label: "Tenants & policies", icon: IconBuildingSkyscraper },
  { to: "/feeds", label: "Feeds", icon: IconRss },
  { to: "/analytics", label: "Analytics", icon: IconChartBar },
  { to: "/audit", label: "Audit log", icon: IconHistory },
  { to: "/settings", label: "Settings", icon: IconSettings },
];

export function Shell() {
  const [opened, { toggle }] = useDisclosure();
  const { colorScheme, toggleColorScheme } = useMantineColorScheme();
  const location = useLocation();

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
          <ActionIcon
            variant="default"
            onClick={() => toggleColorScheme()}
            aria-label="Toggle color scheme"
          >
            {colorScheme === "dark" ? <IconSun size={16} /> : <IconMoon size={16} />}
          </ActionIcon>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        {NAV_ITEMS.map((item) => (
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
