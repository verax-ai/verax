import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  accessToken,
  authorizedFetch,
  beginSession,
  rememberToken,
  sessionIssueError,
} from "../src/session.ts";

function prmResponse(issuer = "http://127.0.0.1:8790"): Response {
  return new Response(
    JSON.stringify({
      authorization_servers: [issuer],
      scopes_supported: ["verax:read", "verax:audit"],
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

function isPrm(input: RequestInfo | URL): boolean {
  return String(input).includes("oauth-protected-resource");
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  sessionStorage.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

beforeEach(() => {
  rememberToken(null);
  localStorage.clear();
  sessionStorage.clear();
});

describe("panel session", () => {
  it("keeps the access token in memory, not localStorage", async () => {
    rememberToken("mem-token-1");
    expect(accessToken()).toBe("mem-token-1");
    expect(localStorage.getItem("mem-token-1")).toBeNull();
    expect(localStorage.length).toBe(0);
    for (let i = 0; i < localStorage.length; i += 1) {
      expect(localStorage.key(i)).not.toMatch(/token/i);
    }
  });

  it("demo=1 does not start authorize", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "?demo=1",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    const phase = await beginSession();
    expect(phase).toBe("demo");
    expect(assign).not.toHaveBeenCalled();
    expect(accessToken()).toBeNull();
  });

  it("without a code, redirects to authorize with S256 and no token in the URL", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => (isPrm(input) ? prmResponse() : new Response("{}", { status: 404 }))),
    );
    const phase = await beginSession();
    expect(phase).toBe("redirect");
    expect(assign).toHaveBeenCalledTimes(1);
    const dest = new URL(String(assign.mock.calls[0]![0]));
    expect(dest.pathname).toBe("/authorize");
    expect(dest.searchParams.get("code_challenge_method")).toBe("S256");
    expect(dest.searchParams.get("code_challenge")).toBeTruthy();
    expect(dest.searchParams.get("response_type")).toBe("code");
    expect(dest.href).not.toMatch(/access_token/);
    expect(accessToken()).toBeNull();
  });

  it("a second beginSession shares the first boot and does not start authorize twice", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => (isPrm(input) ? prmResponse() : new Response("{}", { status: 404 }))),
    );
    const first = beginSession();
    const second = beginSession();
    expect(await first).toBe("redirect");
    expect(await second).toBe("redirect");
    expect(assign).toHaveBeenCalledTimes(1);
  });

  it("a returned state that does not match starts over instead of exchanging", async () => {
    sessionStorage.setItem("verax-pkce-verifier", "verifier-1");
    sessionStorage.setItem("verax-pkce-state", "mine");
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "?code=abc&state=theirs",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (isPrm(input)) return prmResponse();
      return new Response("{}", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const phase = await beginSession();
    expect(phase).toBe("redirect");
    expect(fetchMock.mock.calls.every((c) => isPrm(c[0] as RequestInfo | URL))).toBe(true);
    expect(assign).toHaveBeenCalledTimes(1);
    expect(accessToken()).toBeNull();
  });

  it("exchanges a code and stores the token only in memory", async () => {
    sessionStorage.setItem("verax-pkce-verifier", "verifier-1");
    sessionStorage.setItem("verax-pkce-state", "st");
    const assign = vi.fn();
    const replaceState = vi.fn();
    vi.stubGlobal("location", {
      search: "?code=abc&state=st",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    vi.stubGlobal("history", { replaceState });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      if (isPrm(input)) return prmResponse();
      return new Response(JSON.stringify({ access_token: "issued-token", token_type: "Bearer" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const phase = await beginSession();
    expect(phase).toBe("ok");
    expect(accessToken()).toBe("issued-token");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.getItem("verax-pkce-verifier")).toBeNull();
    const tokenCall = fetchMock.mock.calls.find((c) => !isPrm(c[0] as RequestInfo | URL));
    const body = String(tokenCall?.[1]?.body ?? "");
    expect(body).toMatch(/code=abc/);
    expect(body).toMatch(/code_verifier=verifier-1/);
  });

  it("reads the issuer from resource metadata before authorize", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("oauth-protected-resource")) {
        return new Response(
          JSON.stringify({
            authorization_servers: ["http://127.0.0.1:8791"],
            scopes_supported: ["verax:read", "verax:audit"],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response("{}", { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const phase = await beginSession();
    expect(phase).toBe("redirect");
    expect(fetchMock).toHaveBeenCalled();
    const dest = new URL(String(assign.mock.calls[0]![0]));
    expect(dest.origin).toBe("http://127.0.0.1:8791");
    expect(dest.pathname).toBe("/authorize");
  });

  it("PRM unreadability is a visible error, not a silent 8790 redirect", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", {
      search: "",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })));
    const phase = await beginSession();
    expect(phase).toBe("error");
    expect(assign).not.toHaveBeenCalled();
    expect(accessToken()).toBeNull();
    expect(sessionIssueError()).toMatch(/resource metadata/);
    expect(sessionIssueError()).toMatch(/8790/);
  });

  it("a token exchange the browser blocks is a visible error, not a silent loading screen", async () => {
    const assign = vi.fn();
    sessionStorage.setItem("verax-pkce-verifier", "verifier-1");
    sessionStorage.setItem("verax-pkce-state", "state-1");
    vi.stubGlobal("location", {
      search: "?code=abc&state=state-1",
      origin: "http://127.0.0.1:5173",
      pathname: "/",
      hash: "",
      assign,
    });
    vi.stubGlobal("history", { replaceState: vi.fn() });
    // What a blocked cross-origin token request looks like to the page: fetch
    // rejects. Left unhandled it threw past the caller and the panel sat on
    // "loading" with nothing on screen to say why.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (isPrm(input)) return prmResponse();
        throw new TypeError("Failed to fetch");
      }),
    );
    const phase = await beginSession();
    expect(phase).toBe("error");
    expect(accessToken()).toBeNull();
    expect(assign).not.toHaveBeenCalled();
    expect(sessionIssueError()).toMatch(/token/i);
  });

  it("authorizedFetch sends the memory token and does not read VERAX_DEV_TOKEN", async () => {
    rememberToken("mem-token-2");
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await authorizedFetch("/api/ledger");
    const headers = new Headers(fetchMock.mock.calls[0]![1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer mem-token-2");
  });
});
