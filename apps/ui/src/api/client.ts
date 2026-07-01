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
    throw new Error(`${result.response.status}: empty response`);
  }
  return result.data;
}
