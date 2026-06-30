import createClient from "openapi-fetch";
import type { paths } from "./schema";

const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export const apiClient = createClient<paths>({ baseUrl: API_BASE });

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
