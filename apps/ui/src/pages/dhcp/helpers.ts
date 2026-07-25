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

/** Values carried from a lease row's "Reserve" action into the Reservations form. */
export interface ReservePrefill {
  ip_address: string;
  mac_address?: string;
  duid?: string;
}

export const LEASE_STATE: Record<number, { label: string; color: string }> = {
  0: { label: "Active", color: "green" },
  1: { label: "Declined", color: "red" },
  2: { label: "Expired", color: "gray" },
};

export function fmtExpire(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Math.round((d.getTime() - Date.now()) / 1000);
  if (diff < 0) return "expired";
  if (diff < 3600) return `${Math.round(diff / 60)}m`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h`;
  return `${Math.round(diff / 86400)}d`;
}

/** Formats a duration given in seconds, e.g. 86400 -> "1d". */
export function fmtDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

/** Accepts aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, or aabbccddeeff and returns the colon form, or null if not a MAC. */
export function normalizeMac(raw: string): string | null {
  const hex = raw.replace(/[:-]/g, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex)) return null;
  return hex.match(/.{2}/g)!.join(":");
}
