/**
 * Typed fetch wrapper for the ATHAR API (SPEC §13).
 *
 * - Always `credentials: "include"`: auth is an httpOnly cookie set by the API.
 *   No token is ever read, stored or forwarded by this code.
 * - Every mutating request carries `X-Requested-With: athar` (CSRF defence,
 *   paired with SameSite=Strict on the server).
 * - Errors are RFC 7807 problem+json → thrown as `ApiError`.
 * - A 401 dispatches `athar:unauthenticated` on `window`; AuthProvider listens.
 */

import type { Problem } from "./types";

export const API_BASE = "/api/v1";
export const CSRF_HEADER = "X-Requested-With";
export const CSRF_VALUE = "athar";
export const UNAUTHENTICATED_EVENT = "athar:unauthenticated";

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * RFC 7807 problem details for display. The shape is the generated `Problem`
 * model with every field optional but `title`: a transport failure (no response
 * body at all) still has to render through the same component.
 */
export type ProblemDetails = Partial<Problem> & { title: string };

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly detail: string;

  constructor(status: number, problem: ProblemDetails) {
    super(problem.detail ?? problem.title);
    this.name = "ApiError";
    this.status = status;
    this.code = problem.code ?? `http_${status}`;
    this.title = problem.title;
    this.detail = problem.detail ?? "";
  }

  toProblem(): ProblemDetails {
    return { title: this.title, detail: this.detail, status: this.status, code: this.code };
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

export interface ApiInit extends Omit<RequestInit, "body" | "credentials"> {
  /** JSON-serialised as the request body with the right content type. */
  json?: unknown;
  /** Raw body (FormData for uploads, etc.). Ignored when `json` is given. */
  body?: BodyInit | null;
  /** Query string parameters; `undefined`/`null` values are dropped. */
  query?: Record<string, string | number | boolean | null | undefined>;
}

function isProblem(v: unknown): v is ProblemDetails {
  return typeof v === "object" && v !== null && typeof (v as { title?: unknown }).title === "string";
}

async function readProblem(res: Response): Promise<ProblemDetails> {
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("json")) {
    try {
      const body: unknown = await res.json();
      if (isProblem(body)) return body;
    } catch {
      /* fall through to the generic problem */
    }
  }
  return { title: res.statusText || `Request failed (${res.status})`, status: res.status };
}

function buildUrl(path: string, query?: ApiInit["query"]): string {
  const url = path.startsWith("/api/") ? path : `${API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;
  if (!query) return url;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `${url}?${s}` : url;
}

/**
 * `api<T>("/findings", { query: { severity: "Critical" } })`
 * `api<UserOut>("/auth/login", { method: "POST", json: { email, password } })`
 */
export async function api<T>(path: string, init: ApiInit = {}): Promise<T> {
  const { json, query, body, headers: initHeaders, ...rest } = init;
  const method = (rest.method ?? "GET").toUpperCase();
  const headers = new Headers(initHeaders);
  headers.set("Accept", "application/json, application/problem+json");
  if (MUTATING.has(method)) headers.set(CSRF_HEADER, CSRF_VALUE);

  let finalBody: BodyInit | null | undefined = body;
  if (json !== undefined) {
    headers.set("Content-Type", "application/json");
    finalBody = JSON.stringify(json);
  }

  const res = await fetch(buildUrl(path, query), {
    ...rest,
    method,
    headers,
    body: finalBody ?? null,
    credentials: "include",
  });

  if (res.status === 401) {
    if (typeof window !== "undefined") window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT));
    throw new ApiError(401, await readProblem(res));
  }
  if (!res.ok) throw new ApiError(res.status, await readProblem(res));
  if (res.status === 204 || res.headers.get("content-length") === "0") return undefined as T;

  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("json")) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

export interface FileResponse {
  blob: Blob;
  /** From Content-Disposition when the API sends one, else the fallback. */
  filename: string;
}

const FILENAME_RE = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i;

function filenameFrom(header: string | null, fallback: string): string {
  const match = header ? FILENAME_RE.exec(header) : null;
  const raw = match?.[1];
  if (!raw) return fallback;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/**
 * GET a file (the CSV / PDF / JSON exports of SPEC §16) through the same
 * credentials and problem+json error handling as `api`, so a failed export
 * surfaces as a problem rather than as a broken download.
 */
export async function apiFile(path: string, init: ApiInit = {}, fallbackName = "download"): Promise<FileResponse> {
  const { query, headers: initHeaders, ...rest } = init;
  const headers = new Headers(initHeaders);
  const res = await fetch(buildUrl(path, query), { ...rest, method: "GET", headers, credentials: "include" });

  if (res.status === 401 && typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT));
  }
  if (!res.ok) throw new ApiError(res.status, await readProblem(res));

  return { blob: await res.blob(), filename: filenameFrom(res.headers.get("content-disposition"), fallbackName) };
}
