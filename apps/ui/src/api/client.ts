import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const TOKEN_KEY = "aegis_token";

export const apiClient = createClient<paths>({ baseUrl: API_BASE });

const authMiddleware: Middleware = {
  onRequest({ request }) {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) request.headers.set("Authorization", `Bearer ${token}`);
    return request;
  },
  onResponse({ response }) {
    if (response.status === 401 && !window.location.pathname.startsWith("/login")) {
      localStorage.removeItem(TOKEN_KEY);
      window.location.assign("/login");
    }
    return response;
  },
};

apiClient.use(authMiddleware);

/** Typed fetch for endpoints not yet in the OpenAPI schema (new/extended routes). */
export async function rawGet<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>,
): Promise<T> {
  const token = localStorage.getItem("aegis_token");
  const url = new URL(`${API_BASE}${path}`);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString(), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401 && !window.location.pathname.startsWith("/login")) {
    localStorage.removeItem("aegis_token");
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

/** Typed POST for endpoints not yet in the OpenAPI schema. */
export async function rawPost<T>(path: string, body: unknown): Promise<T> {
  const token = localStorage.getItem("aegis_token");
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && !window.location.pathname.startsWith("/login")) {
    localStorage.removeItem("aegis_token");
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

/** PATCH for endpoints not yet in the OpenAPI schema. */
export async function rawPatch<T>(path: string, body: unknown): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && !window.location.pathname.startsWith("/login")) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** PUT for endpoints not yet in the OpenAPI schema. */
export async function rawPut<T>(path: string, body: unknown): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && !window.location.pathname.startsWith("/login")) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** DELETE for endpoints not yet in the OpenAPI schema. */
export async function rawDelete(path: string): Promise<void> {
  const token = localStorage.getItem(TOKEN_KEY);
  const res = await fetch(`${API_BASE}${path}`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401 && !window.location.pathname.startsWith("/login")) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.assign("/login");
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
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
