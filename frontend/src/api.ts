/**
 * AgentShield API helpers
 * ────────────────────────
 * Single source of truth for the backend base URL.
 *
 * In dev: requests to /api/* are proxied by Vite → localhost:8000
 *   so session cookies (httpOnly, SameSite=Lax) work without CORS.
 * In production: set VITE_API_BASE_URL to your deployed backend root (no trailing slash).
 *
 * All callers should import { apiRequest, API_BASE } from "./api".
 */

function isLocalDevHost(): boolean {
  return ["5173", "5174", "5175"].includes(window.location.port);
}

function resolveDirectApiUrl(): string {
  const configured = import.meta.env.VITE_API_URL as string | undefined;
  const configuredIsLocal = Boolean(configured && /^(https?:\/\/)?(127\.0\.0\.1|localhost)(:\d+)?/i.test(configured));

  if (configured && (!import.meta.env.PROD || !configuredIsLocal)) {
    return configured;
  }

  return isLocalDevHost()
    ? `http://${window.location.hostname}:8000`
    : window.location.origin;
}

/** Base URL for direct (non-proxied) usage, e.g. WebSocket connections. */
export const API_DIRECT = resolveDirectApiUrl();

/**
 * Prefix used for all fetch calls in dev.
 * Points to /api which Vite proxies → localhost:8000.
 * In production builds VITE_API_BASE_URL should be "/" (same origin) or a full URL.
 */
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) || "/api";

/** Read the CSRF token from the cookie set by the backend. */
function getCSRFToken(): string {
  if (typeof document === "undefined") return "";
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

let cachedCSRFToken = "";

async function resolveCSRFToken(): Promise<string> {
  const cookieToken = getCSRFToken();
  if (cookieToken) {
    cachedCSRFToken = cookieToken;
    return cookieToken;
  }

  const res = await fetch(`${API_BASE}/v1/auth/csrf`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) return "";
  const payload = await res.json();
  cachedCSRFToken = typeof payload?.csrf_token === "string" ? payload.csrf_token : "";
  return cachedCSRFToken;
}

export interface ApiRequestOptions extends RequestInit {
  /** Workspace API key — sent as X-AgentShield-API-Key header. */
  apiKey?: string;
  /** Skip the CSRF token header (e.g. for GET requests). */
  skipCSRF?: boolean;
  /** Override timeout in ms. Default: 10 000. */
  timeoutMs?: number;
}

/**
 * Typed fetch wrapper.
 * - Automatically injects X-AgentShield-API-Key and X-CSRF-Token headers.
 * - Sends `credentials: "include"` so httpOnly session cookies travel with the request.
 * - Throws a descriptive Error on non-2xx responses.
 */
export async function apiRequest<T = unknown>(
  path: string,
  options: ApiRequestOptions = {}
): Promise<T> {
  const { apiKey, skipCSRF = false, timeoutMs = 10_000, ...init } = options;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  const isWriteMethod =
    init.method && !["GET", "HEAD", "OPTIONS"].includes(init.method.toUpperCase());
  const isPreSessionAuthWrite =
    isWriteMethod &&
    /^\/v1\/auth\/(signup|login|session|firebase-verify)$/.test(path);

  const extraHeaders: Record<string, string> = {};
  if (apiKey) extraHeaders["X-AgentShield-API-Key"] = apiKey;
  if (isWriteMethod && !skipCSRF && !isPreSessionAuthWrite) {
    const csrf = await resolveCSRFToken();
    if (csrf) extraHeaders["X-CSRF-Token"] = csrf;
  }

  const url = path.startsWith("http") ? path : `${API_BASE}${path}`;

  try {
    const res = await fetch(url, {
      credentials: "include", // send session + csrf cookies cross-origin via proxy
      ...init,
      signal: ctrl.signal,
      headers: {
        "Content-Type": "application/json",
        ...extraHeaders,
        ...(init.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      const bodyText = await res.text();
      try {
        const payload = bodyText ? JSON.parse(bodyText) : null;
        msg =
          payload?.error?.message ||
          payload?.error?.code ||
          payload?.detail ||
          msg;
      } catch {
        msg = bodyText || msg;
      }
      throw new Error(msg);
    }

    // 204 No Content — return empty object
    if (res.status === 204) return {} as T;
    return res.json() as Promise<T>;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out — is the backend running?");
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Convenience shorthand for JSON POST.
 */
export function apiPost<T = unknown>(
  path: string,
  body: unknown,
  options: ApiRequestOptions = {}
): Promise<T> {
  return apiRequest<T>(path, {
    method: "POST",
    body: JSON.stringify(body),
    ...options,
  });
}

/**
 * Convenience shorthand for JSON PUT.
 */
export function apiPut<T = unknown>(
  path: string,
  body: unknown,
  options: ApiRequestOptions = {}
): Promise<T> {
  return apiRequest<T>(path, {
    method: "PUT",
    body: JSON.stringify(body),
    ...options,
  });
}

/**
 * Convenience shorthand for DELETE.
 */
export function apiDelete<T = unknown>(
  path: string,
  options: ApiRequestOptions = {}
): Promise<T> {
  return apiRequest<T>(path, { method: "DELETE", ...options });
}
