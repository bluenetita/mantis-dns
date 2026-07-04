import {
  IconActivity,
  IconAd2,
  IconAlertTriangle,
  IconBomb,
  IconCalendarPlus,
  IconCategory,
  IconCoinBitcoin,
  IconDeviceGamepad2,
  IconDeviceTv,
  IconDice,
  IconDownload,
  IconEyeCheck,
  IconEyeOff,
  IconFish,
  IconHeart,
  IconLock,
  IconMessageCircle,
  IconPill,
  IconShieldLock,
  IconSwords,
  IconVirus,
  type IconProps,
} from "@tabler/icons-react";
import type { ForwardRefExoticComponent, RefAttributes } from "react";

type TablerIcon = ForwardRefExoticComponent<IconProps & RefAttributes<SVGSVGElement>>;

const CATEGORY_ICONS: Record<string, TablerIcon> = {
  Virus: IconVirus,
  Fish: IconFish,
  Lock: IconLock,
  AlertTriangle: IconAlertTriangle,
  CoinBitcoin: IconCoinBitcoin,
  CalendarPlus: IconCalendarPlus,
  EyeOff: IconEyeOff,
  Dice: IconDice,
  Pill: IconPill,
  Download: IconDownload,
  Bomb: IconBomb,
  Swords: IconSwords,
  MessageCircle: IconMessageCircle,
  DeviceTv: IconDeviceTv,
  DeviceGamepad2: IconDeviceGamepad2,
  Heart: IconHeart,
  Ad2: IconAd2,
  EyeCheck: IconEyeCheck,
  Activity: IconActivity,
  ShieldLock: IconShieldLock,
};

export function categoryIcon(icon: string): TablerIcon {
  return CATEGORY_ICONS[icon] ?? IconCategory;
}

export const CATEGORY_GROUP_LABEL: Record<string, string> = {
  security: "Security",
  content: "Content",
  distraction: "Distraction",
  privacy: "Privacy",
  network: "Network",
};
