import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  accessToken,
  authorizedFetch,
  beginSession,
  rememberToken,
} from "../src/session.ts";

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

  it("exchanges a code and stores the token only in memory", async () => {
    sessionStorage.setItem("verax-pkce-verifier", "verifier-1");
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
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ access_token: "issued-token", token_type: "Bearer" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const phase = await beginSession();
    expect(phase).toBe("ok");
    expect(accessToken()).toBe("issued-token");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.getItem("verax-pkce-verifier")).toBeNull();
    const body = String(fetchMock.mock.calls[0]![1]?.body ?? "");
    expect(body).toMatch(/code=abc/);
    expect(body).toMatch(/code_verifier=verifier-1/);
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
