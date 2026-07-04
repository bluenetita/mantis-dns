# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Canonical content-filtering category taxonomy (design.md §18.1: "system-
defined taxonomy" — tenants/groups toggle these on/off, they don't define
new system categories). Single source of truth consumed by:
  - GET /api/v1/categories (api/routers.py) -> UI PolicyPage/FeedsPage
  - feeds/catalog.json entries reference these ids via Feed.category_id

`has_bundled_feed=False` means there's no good free, reliably-maintained
public list for that category as of writing — left for an admin to add
manually via the UI (POST /api/v1/feeds) once they have a vetted source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Group = Literal["security", "content", "distraction", "privacy", "network"]


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    description: str
    group: Group
    color: str  # Mantine color name
    icon: str  # @tabler/icons-react component name, minus the "Icon" prefix
    default_action: str  # "ACTION_BLOCK" | "ACTION_LOG_ONLY"
    has_bundled_feed: bool


CATEGORY_REGISTRY: list[Category] = [
    # ── security ─────────────────────────────────────────────────────────
    Category("malware", "Malware", "Known malware distribution and command-and-control domains.", "security", "red", "Virus", "ACTION_BLOCK", True),
    Category("phishing", "Phishing", "Sites impersonating trusted brands to steal credentials.", "security", "orange", "Fish", "ACTION_BLOCK", True),
    Category("ransomware", "Ransomware", "Domains linked to ransomware payload delivery and payment portals.", "security", "pink", "Lock", "ACTION_BLOCK", True),
    Category("scam", "Scam & Fraud", "Fraudulent schemes, fake giveaways, and tech-support scams.", "security", "grape", "AlertTriangle", "ACTION_BLOCK", True),
    Category("cryptojacking", "Cryptojacking", "Browser-based cryptocurrency mining scripts.", "security", "yellow", "CoinBitcoin", "ACTION_BLOCK", True),
    Category("newly-registered", "Newly-Registered Domains", "Domains registered in the last 30 days — a common signal in fast-flux attacks.", "security", "indigo", "CalendarPlus", "ACTION_LOG_ONLY", False),
    # ── content ──────────────────────────────────────────────────────────
    Category("adult", "Adult / Porn", "Pornography and explicit adult content.", "content", "violet", "EyeOff", "ACTION_BLOCK", True),
    Category("gambling", "Gambling", "Online casinos, betting, and gambling platforms.", "content", "cyan", "Dice", "ACTION_BLOCK", True),
    Category("drugs", "Drugs", "Illicit drug sales, marketplaces, and glorification content.", "content", "lime", "Pill", "ACTION_BLOCK", True),
    Category("piracy", "Piracy", "Torrent trackers, warez, and pirated media.", "content", "indigo", "Download", "ACTION_BLOCK", True),
    Category("weapons", "Weapons", "Firearms, ammunition, and weapon marketplaces.", "content", "gray", "Bomb", "ACTION_BLOCK", False),
    Category("hate-violence", "Hate & Violence", "Hate speech, extremism, and graphic violence.", "content", "red", "Swords", "ACTION_BLOCK", True),
    # ── distraction ──────────────────────────────────────────────────────
    Category("social", "Social Media", "Social networking and messaging platforms.", "distraction", "blue", "MessageCircle", "ACTION_LOG_ONLY", True),
    Category("streaming", "Streaming / Video", "Video streaming and entertainment sites.", "distraction", "violet", "DeviceTv", "ACTION_LOG_ONLY", True),
    Category("gaming", "Gaming", "Online games and gaming platforms.", "distraction", "green", "DeviceGamepad2", "ACTION_LOG_ONLY", True),
    Category("dating", "Dating", "Dating and relationship apps/sites.", "distraction", "pink", "Heart", "ACTION_LOG_ONLY", True),
    # ── privacy ──────────────────────────────────────────────────────────
    Category("ads", "Ads", "Advertising networks and ad-serving domains.", "privacy", "teal", "Ad2", "ACTION_BLOCK", True),
    Category("tracking", "Trackers", "Analytics and cross-site tracking domains.", "privacy", "cyan", "EyeCheck", "ACTION_BLOCK", True),
    Category("telemetry", "OS / App Telemetry", "Operating system and app telemetry endpoints.", "privacy", "gray", "Activity", "ACTION_BLOCK", False),
    # ── network ──────────────────────────────────────────────────────────
    # has_bundled_feed covers the DNS-domain side only (DoH/VPN/Tor bypass
    # domains). Tor exit-node / proxy IP lists are a different enforcement
    # mechanism (IP ACL at the filter node, not a domain feed) and are out
    # of scope for this category until that's built.
    Category("proxies", "Proxies / VPN / Tor", "Anonymizing proxies, VPN, and Tor exit-node domains.", "network", "dark", "ShieldLock", "ACTION_LOG_ONLY", True),
]

CATEGORY_BY_ID: dict[str, Category] = {c.id: c for c in CATEGORY_REGISTRY}
