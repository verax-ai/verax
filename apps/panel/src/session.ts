const VERIFIER_KEY = "verax-pkce-verifier";
const STATE_KEY = "verax-pkce-state";
const RETURN_KEY = "verax-return-query";
const PRM_PATH = "/.well-known/oauth-protected-resource";

let token: string | null = null;
let sessionError: string | null = null;
let boot: Promise<"ok" | "redirect" | "demo" | "error"> | null = null;

export function accessToken(): string | null {
  return token;
}

export function rememberToken(next: string | null): void {
  token = next;
  if (next === null) boot = null;
}

export function sessionIssueError(): string | null {
  return sessionError;
}

/**
 * The scopes on the token in memory, for deciding what to draw.
 *
 * Read without verifying, deliberately: a signature check here would protect
 * nothing, because the body verifies every call anyway. This answers "should
 * this button exist", never "is this allowed" - the second question is not the
 * screen's to answer.
 */
export function sessionScopes(): Set<string> {
  const out = new Set<string>();
  if (token === null) return out;
  const body = token.split(".")[1];
  if (body === undefined) return out;
  try {
    const json = atob(body.replace(/-/g, "+").replace(/_/g, "/"));
    const claims = JSON.parse(json) as { scope?: unknown };
    if (typeof claims.scope === "string") {
      for (const part of claims.scope.split(" ")) if (part !== "") out.add(part);
    }
  } catch {
    return out;
  }
  return out;
}

function fallbackIssuer(): string {
  const fromEnv = import.meta.env.VITE_VERAX_ISSUER;
  if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
    return fromEnv.replace(/\/$/, "");
  }
  return "http://127.0.0.1:8790";
}

async function issuerFromPrm(): Promise<string | null> {
  try {
    const res = await fetch(PRM_PATH);
    if (!res.ok) return null;
    const body = (await res.json()) as { authorization_servers?: unknown };
    const first = Array.isArray(body.authorization_servers) ? body.authorization_servers[0] : undefined;
    if (typeof first !== "string" || first.trim() === "") return null;
    return first.replace(/\/$/, "");
  } catch {
    return null;
  }
}

function redirectUri(): string {
  // Origin and path only: this has to match what the issuer registered, and a
  // query string would not. Which is why the panel's own address is kept here
  // instead of in the redirect, and put back when the browser returns.
  return `${window.location.origin}${window.location.pathname}`;
}

function rememberAddress(): void {
  const params = new URLSearchParams(window.location.search);
  params.delete("code");
  params.delete("state");
  const q = params.toString();
  if (q === "") sessionStorage.removeItem(RETURN_KEY);
  else sessionStorage.setItem(RETURN_KEY, q);
}

/**
 * Put the address the panel was opened at back into the bar, on the way in
 * from the issuer.
 *
 * Called before the app renders, not after the token exchange: the tab to open
 * and the seat to focus are read on the first render, so an address restored a
 * few awaits later would be correct in the bar and too late for the screen.
 * `code` and `state` are left where they are - the exchange still needs them,
 * and it strips them itself once it is done.
 */
export function restoreAddress(): boolean {
  if (typeof window === "undefined") return false;
  const params = new URLSearchParams(window.location.search);
  if (!params.has("code")) return false;
  const saved = sessionStorage.getItem(RETURN_KEY);
  sessionStorage.removeItem(RETURN_KEY);
  if (!saved) return false;
  let added = false;
  for (const [key, value] of new URLSearchParams(saved)) {
    if (params.has(key)) continue;
    params.set(key, value);
    added = true;
  }
  if (!added) return false;
  window.history.replaceState({}, "", `${window.location.pathname}?${params.toString()}${window.location.hash}`);
  return true;
}

function randomUrl(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function startAuthorize(issuer: string): Promise<void> {
  rememberAddress();
  const verifier = randomUrl();
  const state = randomUrl();
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);
  const dest = new URL(`${issuer}/authorize`);
  dest.searchParams.set("response_type", "code");
  dest.searchParams.set("client_id", "verax-panel");
  dest.searchParams.set("redirect_uri", redirectUri());
  // The panel says what it intends to do. Whether the issuer grants the
  // approve scope is the issuer's call; the panel asks, and draws no approval
  // button when the answer is no.
  dest.searchParams.set("scope", "verax:audit verax:approve");
  dest.searchParams.set("code_challenge", await s256(verifier));
  dest.searchParams.set("code_challenge_method", "S256");
  dest.searchParams.set("state", state);
  window.location.assign(dest.toString());
}

function wantDemo(): boolean {
  return new URLSearchParams(window.location.search).get("demo") === "1";
}

export async function beginSession(): Promise<"ok" | "redirect" | "demo" | "error"> {
  // Strict Mode mounts twice. A second authorize overwrites the PKCE verifier,
  // the exchange fails, and the tab loops. One boot per page load.
  if (!boot) boot = beginSessionOnce();
  return boot;
}

async function beginSessionOnce(): Promise<"ok" | "redirect" | "demo" | "error"> {
  if (wantDemo()) return "demo";
  // Harmless when main.tsx already did it: the saved address is consumed once.
  restoreAddress();
  if (token) return "ok";
  const issuer = await issuerFromPrm();
  if (!issuer) {
    const fallback = fallbackIssuer();
    sessionError = `resource metadata unreachable; last-resort issuer ${fallback}`;
    return "error";
  }
  sessionError = null;
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  if (code) {
    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    const expectedState = sessionStorage.getItem(STATE_KEY);
    sessionStorage.removeItem(VERIFIER_KEY);
    sessionStorage.removeItem(STATE_KEY);
    // A code that comes back without the state this tab sent is not ours.
    if (!verifier || !expectedState || params.get("state") !== expectedState) {
      await startAuthorize(issuer);
      return "redirect";
    }
    let res: Response;
    try {
      res = await fetch(`${issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri(),
          code_verifier: verifier,
          client_id: "verax-panel",
        }),
      });
    } catch (err) {
      // A request the browser refuses to complete - a blocked cross-origin
      // response, a closed issuer - rejects here. Retrying authorize would
      // loop, and saying nothing leaves the panel on "loading" with no reason
      // on screen for what it cannot reach.
      const why = err instanceof Error ? err.message : String(err);
      sessionError = `token exchange unreachable at ${issuer}/token: ${why}`;
      return "error";
    }
    if (!res.ok) {
      await startAuthorize(issuer);
      return "redirect";
    }
    const body = (await res.json()) as { access_token?: unknown };
    if (typeof body.access_token !== "string" || body.access_token === "") {
      await startAuthorize(issuer);
      return "redirect";
    }
    token = body.access_token;
    params.delete("code");
    params.delete("state");
    const q = params.toString();
    window.history.replaceState({}, "", `${window.location.pathname}${q ? `?${q}` : ""}${window.location.hash}`);
    return "ok";
  }
  await startAuthorize(issuer);
  return "redirect";
}

export function authorizedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return fetch(input, { ...init, headers });
}
