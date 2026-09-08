const VERIFIER_KEY = "verax-pkce-verifier";
const STATE_KEY = "verax-pkce-state";
const PRM_PATH = "/.well-known/oauth-protected-resource";

let token: string | null = null;
let sessionError: string | null = null;

export function accessToken(): string | null {
  return token;
}

export function rememberToken(next: string | null): void {
  token = next;
}

export function sessionIssueError(): string | null {
  return sessionError;
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
  return `${window.location.origin}${window.location.pathname}`;
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
  const verifier = randomUrl();
  const state = randomUrl();
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);
  const dest = new URL(`${issuer}/authorize`);
  dest.searchParams.set("response_type", "code");
  dest.searchParams.set("client_id", "verax-panel");
  dest.searchParams.set("redirect_uri", redirectUri());
  dest.searchParams.set("code_challenge", await s256(verifier));
  dest.searchParams.set("code_challenge_method", "S256");
  dest.searchParams.set("state", state);
  window.location.assign(dest.toString());
}

function wantDemo(): boolean {
  return new URLSearchParams(window.location.search).get("demo") === "1";
}

export async function beginSession(): Promise<"ok" | "redirect" | "demo" | "error"> {
  if (wantDemo()) return "demo";
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
