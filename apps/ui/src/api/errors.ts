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

const STATUS_PREFIX: Record<number, string> = {
  400: "Invalid request",
  401: "Session expired",
  403: "You don't have permission to do this",
  404: "Not found",
  409: "Already exists or conflicts with existing data",
  422: "Invalid input",
  429: "Too many requests — try again shortly",
  500: "Server error",
  502: "Server error",
  503: "Service unavailable",
};

/** Pulls a human message out of a FastAPI `{"detail": ...}` body (string, or
 * a Pydantic validation-error list) — the shape `client.ts` throws. */
function extractDetail(rest: string): string | null {
  try {
    const parsed = JSON.parse(rest);
    if (typeof parsed === "string") return parsed;
    const detail =
      parsed && typeof parsed === "object" && "detail" in parsed
        ? (parsed as { detail: unknown }).detail
        : parsed;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const msgs = detail
        .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : null))
        .filter((m): m is string => m !== null);
      if (msgs.length) return msgs.join("; ");
    }
    return null;
  } catch {
    return rest.trim() || null;
  }
}

/** Formats API errors (`Error("STATUS: body")`, per client.ts's `unwrap`/
 * `rawRequest`) into a message worth showing a user, instead of the raw
 * `Error: 422: {"detail":"..."}` string. */
export function formatError(e: unknown): string {
  const raw = e instanceof Error ? e.message : String(e);
  const match = raw.match(/^(\d{3}):\s*([\s\S]*)$/);
  if (!match) return raw;
  const [, statusStr, rest] = match;
  const status = Number(statusStr);
  const prefix = STATUS_PREFIX[status] ?? `Error ${status}`;
  const detail = extractDetail(rest);
  return detail && detail !== prefix ? `${prefix}: ${detail}` : prefix;
}
