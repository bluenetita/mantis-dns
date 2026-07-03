import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/** Double-submit CSRF token: set (non-httpOnly) by /auth/login alongside the
 * httpOnly session cookie the browser now carries automatically. Every
 * mutating request must echo it back as a header so the server can confirm
 * the request originated from JS running on our own origin. */
function csrfHeaders(): Record<string, string> {
  const csrf = readCookie("aegis_csrf");
  return csrf ? { "X-Aegis-CSRF-Token": csrf } : {};
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
  const url = new URL(`${API_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  return rawRequest<T>("GET", url.toString());
}

/** Typed POST for endpoints not yet in the OpenAPI schema. */
export async function rawPost<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("POST", `${API_BASE}${path}`, body);
}

/** PATCH for endpoints not yet in the OpenAPI schema. */
export async function rawPatch<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("PATCH", `${API_BASE}${path}`, body);
}

/** PUT for endpoints not yet in the OpenAPI schema. */
export async function rawPut<T>(path: string, body: unknown): Promise<T> {
  return rawRequest<T>("PUT", `${API_BASE}${path}`, body);
}

/** DELETE for endpoints not yet in the OpenAPI schema. */
export async function rawDelete(path: string): Promise<void> {
  await rawRequest<void>("DELETE", `${API_BASE}${path}`);
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
