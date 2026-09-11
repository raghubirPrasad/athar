import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, CSRF_HEADER, CSRF_VALUE, isApiError, UNAUTHENTICATED_EVENT } from "./client";

function jsonResponse(body: unknown, init: ResponseInit & { contentType?: string } = {}): Response {
  const { contentType = "application/json", ...rest } = init;
  return new Response(JSON.stringify(body), {
    status: 200,
    ...rest,
    headers: { "content-type": contentType },
  });
}

function stubFetch(response: Response) {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("sends the CSRF header and cookies on a POST", async () => {
    const fetchMock = stubFetch(jsonResponse({ scan_id: 13 }));

    await api("/scan", { method: "POST", json: { month: null } });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/scan");
    expect(init.credentials).toBe("include");
    const headers = new Headers(init.headers);
    expect(headers.get(CSRF_HEADER)).toBe(CSRF_VALUE);
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(init.body).toBe(JSON.stringify({ month: null }));
  });

  it("does not send the CSRF header on a GET", async () => {
    const fetchMock = stubFetch(jsonResponse({ items: [], total: 0, limit: 50, offset: 0 }));

    await api("/identities", { query: { limit: 50, severity: undefined } });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/identities?limit=50");
    expect(new Headers(init.headers).get(CSRF_HEADER)).toBeNull();
  });

  it("turns problem+json into an ApiError with the stable code", async () => {
    stubFetch(
      jsonResponse(
        { type: "about:blank", title: "Forbidden", status: 403, detail: "Approver role required", code: "rbac.forbidden" },
        { status: 403, statusText: "Forbidden", contentType: "application/problem+json" },
      ),
    );

    const error = await api("/remediation/plan-1/approve", { method: "POST" }).catch((e: unknown) => e);

    expect(isApiError(error)).toBe(true);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(403);
    expect(apiError.code).toBe("rbac.forbidden");
    expect(apiError.title).toBe("Forbidden");
    expect(apiError.detail).toBe("Approver role required");
  });

  it("announces a 401 so the session can be dropped", async () => {
    stubFetch(
      jsonResponse(
        { title: "Unauthorized", status: 401, code: "auth.missing_session" },
        { status: 401, contentType: "application/problem+json" },
      ),
    );
    const listener = vi.fn();
    window.addEventListener(UNAUTHENTICATED_EVENT, listener);

    await expect(api("/auth/me")).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);

    window.removeEventListener(UNAUTHENTICATED_EVENT, listener);
  });

  it("still produces a renderable problem when the body is not problem+json", async () => {
    stubFetch(new Response("gateway down", { status: 502, statusText: "Bad Gateway" }));

    const error = (await api("/estate/summary").catch((e: unknown) => e)) as ApiError;

    expect(error.status).toBe(502);
    expect(error.title).toBe("Bad Gateway");
    expect(error.code).toBe("http_502");
  });
});
