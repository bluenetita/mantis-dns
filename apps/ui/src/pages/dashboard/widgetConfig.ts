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

export const WIDGET_DEFS = [
  { id: "query-volume",    label: "Query volume",          span: { base: 12, md: 8 } },
  { id: "decision",        label: "Decision breakdown",    span: { base: 12, md: 4 } },
  { id: "top-domains",     label: "Top blocked domains",   span: { base: 12, md: 6 } },
  { id: "categories",      label: "Blocks by category",    span: { base: 12, md: 6 } },
  { id: "top-clients",     label: "Top clients",           span: { base: 12 } },
  { id: "group-breakdown", label: "Group breakdown",       span: { base: 12 } },
  { id: "feed-health",     label: "Feed health",           span: { base: 12, md: 6 } },
  { id: "siem-delivery",   label: "SIEM delivery",         span: { base: 12, md: 6 } },
  { id: "recent-events",   label: "Recent block events",   span: { base: 12 } },
] as const;

export type WidgetId = typeof WIDGET_DEFS[number]["id"];

export interface WidgetConfig { id: WidgetId; visible: boolean }

export const DEFAULT_CONFIG: WidgetConfig[] = WIDGET_DEFS.map((w) => ({ id: w.id, visible: true }));

export function loadWidgetConfig(): WidgetConfig[] {
  try {
    const raw = localStorage.getItem("dashboard-widget-config");
    if (!raw) return DEFAULT_CONFIG;
    const saved: WidgetConfig[] = JSON.parse(raw);
    // Merge: keep saved order/visibility, add any new widgets at end
    const ids = new Set(saved.map((w) => w.id));
    const merged = [...saved, ...DEFAULT_CONFIG.filter((w) => !ids.has(w.id))];
    // Drop stale ids
    const valid = new Set(WIDGET_DEFS.map((w) => w.id));
    return merged.filter((w) => valid.has(w.id));
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function saveWidgetConfig(config: WidgetConfig[]) {
  localStorage.setItem("dashboard-widget-config", JSON.stringify(config));
}

export const TIME_SEGMENTS = [
  { value: "1", label: "1h" },
  { value: "6", label: "6h" },
  { value: "24", label: "24h" },
  { value: "168", label: "7d" },
  { value: "720", label: "30d" },
];
