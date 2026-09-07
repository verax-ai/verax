const VERIFIER_KEY = "verax-pkce-verifier";
const STATE_KEY = "verax-pkce-state";

let token: string | null = null;

export function accessToken(): string | null {
  return token;
}

export function rememberToken(next: string | null): void {
  token = next;
}

function issuerOrigin(): string {
  const fromEnv = import.meta.env.VITE_VERAX_ISSUER;
  if (typeof fromEnv === "string" && fromEnv.trim() !== "") {
    return fromEnv.replace(/\/$/, "");
  }
  return "http://127.0.0.1:8790";
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

async function startAuthorize(): Promise<void> {
  const verifier = randomUrl();
  const state = randomUrl();
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);
  const dest = new URL(`${issuerOrigin()}/authorize`);
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

export async function beginSession(): Promise<"ok" | "redirect" | "demo"> {
  if (wantDemo()) return "demo";
  if (token) return "ok";
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  if (code) {
    const verifier = sessionStorage.getItem(VERIFIER_KEY);
    sessionStorage.removeItem(VERIFIER_KEY);
    sessionStorage.removeItem(STATE_KEY);
    if (!verifier) {
      await startAuthorize();
      return "redirect";
    }
    const res = await fetch(`${issuerOrigin()}/token`, {
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
    if (!res.ok) {
      await startAuthorize();
      return "redirect";
    }
    const body = (await res.json()) as { access_token?: unknown };
    if (typeof body.access_token !== "string" || body.access_token === "") {
      await startAuthorize();
      return "redirect";
    }
    token = body.access_token;
    params.delete("code");
    params.delete("state");
    const q = params.toString();
    window.history.replaceState({}, "", `${window.location.pathname}${q ? `?${q}` : ""}${window.location.hash}`);
    return "ok";
  }
  await startAuthorize();
  return "redirect";
}

export function authorizedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return fetch(input, { ...init, headers });
}
