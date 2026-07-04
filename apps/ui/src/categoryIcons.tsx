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
