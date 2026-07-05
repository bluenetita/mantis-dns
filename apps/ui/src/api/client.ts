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

import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema";

function sameOriginBase(): string {
  return typeof window === "undefined" ? "" : window.location.origin;
}

function normalizeApiBase(value: string | undefined): string {
  if (value === "") return sameOriginBase();
  if (value === undefined) return "http://localhost:8000";

  const trimmed = value.replace(/\/+$/, "");
  if (trimmed.endsWith("/api/v1")) {
    return trimmed.slice(0, -"/api/v1".length) || sameOriginBase();
  }
  return trimmed;
}

export const API_BASE = normalizeApiBase(import.meta.env.VITE_API_URL);

export function apiUrl(path: string): string {
  return new URL(`${API_BASE}${path}`, sameOriginBase()).toString();
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/** Double-submit CSRF token: set (non-httpOnly) by /auth/login alongside the
 * httpOnly session cookie the browser now carries automatically. Every
 * mutating request must echo it back as a header so the server can confirm
 * the request originated from JS running on our own origin. */
function csrfHeaders(): Record<string, string> {
  const csrf = readCookie("mantis_csrf");
  return csrf ? { "X-Mantis-CSRF-Token": csrf } : {};
}

function handleUnauthorized(status: number): void {
  if (status === 401 && !window.location.pathname.startsWith("/login")) {
    window.location.assign("/login");
  }
}

export const apiClient = createClient<paths>({ baseUrl: API_BASE, credentials: "include" });

const authMiddleware: Middleware = {
  onRequest({ request }) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      for (const [key, value] of Object.entries(csrfHeaders())) {
        request.headers.set(key, value);
      }
    }
    return request;
  },
  onResponse({ response }) {
    handleUnauthorized(response.status);
    return response;
  },
};

apiClient.use(authMiddleware);

async function rawRequest<T>(method: string, url: string, body?: unknown): Promise<T> {
  const isMutating = method !== "GET" && method !== "HEAD";
  const res = await fetch(url, {
    method,
    credentials: "include",
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(isMutating ? csrfHeaders() : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  handleUnauthorized(res.status);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** Typed fetch for endpoints not yet in the OpenAPI schema (new/extended routes). */
export async function rawGet<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  const url = new URL(apiUrl(path));
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  return rawRequest<T>("GET", url.toString());
}

/** Typed POST for endpoints not yet in the OpenAPI schema. */
export async function rawPost<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("POST", apiUrl(path), body);
}

/** PATCH for endpoints not yet in the OpenAPI schema. */
export async function rawPatch<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("PATCH", apiUrl(path), body);
}

/** PUT for endpoints not yet in the OpenAPI schema. */
export async function rawPut<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("PUT", apiUrl(path), body);
}

/** DELETE for endpoints not yet in the OpenAPI schema. */
export async function rawDelete(path: string): Promise<void> {
  await rawRequest<void>("DELETE", apiUrl(path));
}

/** Throws with a readable message on non-2xx instead of returning `{error}`. */
export function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.error !== undefined) {
    const detail =
      typeof result.error === "object" && result.error !== null && "detail" in result.error
        ? String((result.error as { detail: unknown }).detail)
        : JSON.stringify(result.error);
    throw new Error(`${result.response.status}: ${detail}`);
  }
  if (result.data === undefined) {
    if (result.response.ok) return undefined as T; // 204 No Content — valid empty response
    throw new Error(`${result.response.status}: empty response`);
  }
  return result.data;
}
