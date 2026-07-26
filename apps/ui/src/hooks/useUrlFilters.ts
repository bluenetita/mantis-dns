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

import { useSearchParams } from "react-router";

/**
 * Filter/tab/pagination state that lives in the URL instead of useState, so
 * a filtered view is shareable, survives reload, and undoes with the back
 * button — the pattern DhcpPage already uses by hand for family/tab.
 *
 * Values are strings (URL search params are always strings); callers coerce
 * numbers themselves at the read site, same as DhcpPage's `hoursStr` pattern.
 * A value equal to its default is omitted from the URL to keep links clean.
 */
export function useUrlFilters<T extends Record<string, string>>(
  defaults: T
): [T, (patch: Partial<T>) => void] {
  const [searchParams, setSearchParams] = useSearchParams();

  const values = { ...defaults };
  for (const key of Object.keys(defaults)) {
    const v = searchParams.get(key);
    if (v !== null) values[key as keyof T] = v as T[keyof T];
  }

  function setFilters(patch: Partial<T>) {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const key of Object.keys(patch)) {
          const value = patch[key];
          if (value === undefined || value === defaults[key]) next.delete(key);
          else next.set(key, value);
        }
        return next;
      },
      { replace: true }
    );
  }

  return [values, setFilters];
}
