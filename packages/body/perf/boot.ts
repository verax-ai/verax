// Shared by the scale probes: start the dev issuer and the body on loopback
// against a state directory that already holds a ledger, wait for /healthz,
// and mint a session token through the issuer's code flow. Mirrors what
// scripts/demo-box.mjs does, minus the stdio bridge. Development only.
// mintToken is the session with no passkey: it does not carry verax:audit.
// mintAuditToken enrolls a software passkey and uses that session. The
// credential is removed on stop so a later probe is not stuck at sign-in.

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, unlinkSync } from "node:fs";
import { get } from "node:http";
import { createConnection } from "node:net";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { CREDENTIALS_FILE } from "../src/operator-credentials.ts";
import { PAIRING_FILE, beginPairing } from "../src/operator-pairing.ts";
import { systemToolPath } from "../src/install.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey, registerWithSoftwarePasskey } from "../../../tests/software-passkey.ts";

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export type Booted = {
  issuerUrl: string;
  bodyUrl: string;
  bodyPid: number;
  /** Milliseconds from spawning the body until /healthz answered 200. */
  bodyStartMs: number;
  /** No passkey. Does not carry verax:audit or verax:approve. */
  mintToken: () => Promise<string>;
  /** Passkey session. Carries verax:audit and verax:approve. */
  mintAuditToken: () => Promise<string>;
  stop: () => void;
};

function portOpen(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host: "127.0.0.1" });
    sock.once("connect", () => {
      sock.end();
      resolve(true);
    });
    sock.once("error", () => resolve(false));
  });
}

function healthzUp(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = get({ host: "127.0.0.1", port, path: "/healthz", timeout: 3_000 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.once("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.once("error", () => resolve(false));
  });
}

async function waitFor(probe: () => Promise<boolean>, ms: number): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < ms) {
    if (await probe()) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** Resident set of a process in MB, read from the OS (Windows tasklist / ps). */
export function rssMb(pid: number): number | null {
  if (process.platform === "win32") {
    const out = spawnSync(systemToolPath("tasklist", "win32"), ["/FI", `PID eq ${pid}`, "/FO", "CSV", "/NH"], {
      encoding: "utf8",
    });
    const line = out.stdout.split(/\r?\n/).find((l) => l.includes(`"${pid}"`));
    if (!line) return null;
    const cols = line.split('","');
    const mem = cols[cols.length - 1]?.replace(/[^0-9]/g, "");
    return mem ? Math.round(Number(mem) / 1024) : null;
  }
  const out = spawnSync(systemToolPath("ps"), ["-o", "rss=", "-p", String(pid)], { encoding: "utf8" });
  const kb = Number(out.stdout.trim());
  return Number.isFinite(kb) && kb > 0 ? Math.round(kb / 1024) : null;
}

export async function bootBody(opts: {
  stateDir: string;
  policyFile: string;
  issuerPort: number;
  bodyPort: number;
  /** First entry is what mintToken uses; the rest are for a browser (panel). */
  redirectUris: string[];
  startTimeoutMs?: number;
  quiet?: boolean;
}): Promise<Booted> {
  const issuerUrl = `http://127.0.0.1:${opts.issuerPort}`;
  const bodyUrl = `http://127.0.0.1:${opts.bodyPort}`;
  const redirectUri = opts.redirectUris[0]!;
  const timeout = opts.startTimeoutMs ?? 120_000;
  const kids: ChildProcess[] = [];
  let stopping = false;
  let token = "";
  let enrolledAudit = false;

  // Quiet keeps the children's chatter off the console but not off the
  // record: the last lines are printed when a child dies.
  const tail: string[] = [];
  const forward = (chunk: Buffer | string) => {
    let text = String(chunk);
    if (token !== "" && text.includes(token)) text = text.split(token).join("[token]");
    for (const line of text.split(/\r?\n/)) {
      if (line === "") continue;
      tail.push(line);
      if (tail.length > 30) tail.shift();
    }
    if (!opts.quiet) process.stderr.write(text);
  };
  const stop = () => {
    if (stopping) return;
    stopping = true;
    for (const kid of kids) {
      try {
        kid.kill();
      } catch {
        // gone
      }
    }
    if (enrolledAudit) {
      for (const name of [CREDENTIALS_FILE, PAIRING_FILE]) {
        try {
          unlinkSync(join(opts.stateDir, name));
        } catch {
          // already gone
        }
      }
    }
  };
  const spawnChild = (label: string, args: string[], env: NodeJS.ProcessEnv): ChildProcess => {
    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      env: { ...env, NO_COLOR: "1", FORCE_COLOR: "0" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    child.stdout?.on("data", forward);
    child.stderr?.on("data", forward);
    child.on("exit", (code, signal) => {
      if (stopping) return;
      process.stderr.write(`boot: ${label} exited (${code ?? signal})\n`);
      if (opts.quiet && tail.length > 0) process.stderr.write(`${tail.slice(-10).join("\n")}\n`);
    });
    kids.push(child);
    return child;
  };

  const issuerEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "development",
    VERAX_STATE_DIR: opts.stateDir,
    VERAX_DEV_ISSUER_PORT: String(opts.issuerPort),
    VERAX_ISSUER: issuerUrl,
    VERAX_AUDIENCE: bodyUrl,
    VERAX_DEV_REDIRECT_URIS: opts.redirectUris.join(","),
    VERAX_DEV_SUB: "scale-operator",
    VERAX_DEV_OPERATOR_SUB: "scale-operator",
    VERAX_DEV_SCOPE: "verax:read verax:memory verax:audit verax:pay verax:approve",
    VERAX_RP_ID: "localhost",
    VERAX_RP_ORIGINS: issuerUrl,
  };
  delete issuerEnv.VERAX_DEV_TOKEN;
  spawnChild(
    "issuer",
    ["--experimental-strip-types", join(repoRoot, "scripts", "dev-issuer.mjs"), "--out", join(opts.stateDir, "dev-token")],
    issuerEnv,
  );
  if (!(await waitFor(() => portOpen(opts.issuerPort), 20_000))) {
    stop();
    throw new Error("issuer did not start");
  }

  const bodyEnv: NodeJS.ProcessEnv = {
    ...process.env,
    VERAX_STATE_DIR: opts.stateDir,
    VERAX_ISSUER: issuerUrl,
    VERAX_JWKS_URL: `${issuerUrl}/.well-known/jwks.json`,
    VERAX_AUDIENCE: bodyUrl,
    VERAX_BIND: `127.0.0.1:${opts.bodyPort}`,
    VERAX_POLICY_FILE: opts.policyFile,
  };
  delete bodyEnv.VERAX_DEV_TOKEN;
  delete bodyEnv.VERAX_INVENTORY_FILE;
  // A probe's body is killed, not closed, so its lock file outlives it and
  // names a dead pid; the next body would refuse the ledger as locked.
  const lockPath = join(opts.stateDir, "ledger.lock");
  if (existsSync(lockPath)) unlinkSync(lockPath);
  const t0 = performance.now();
  const body = spawnChild("body", ["--experimental-strip-types", join(repoRoot, "packages", "body", "src", "main.ts")], bodyEnv);
  if (!(await waitFor(() => healthzUp(opts.bodyPort), timeout))) {
    stop();
    throw new Error(`body did not answer /healthz within ${timeout} ms`);
  }
  const bodyStartMs = Math.round(performance.now() - t0);

  const mintToken = async (): Promise<string> => {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const q = new URLSearchParams({
      response_type: "code",
      client_id: "scale-probe",
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    const auth = await fetch(`${issuerUrl}/authorize?${q}`, { redirect: "manual" });
    const location = auth.headers.get("location");
    if (auth.status < 300 || auth.status >= 400 || !location) throw new Error(`authorize ${auth.status}`);
    const code = new URL(location).searchParams.get("code");
    if (!code) throw new Error("authorize gave no code");
    const tok = await fetch(`${issuerUrl}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier }),
    });
    const parsed = (await tok.json()) as { access_token?: unknown };
    if (!tok.ok || typeof parsed.access_token !== "string") throw new Error(`token ${tok.status}`);
    token = parsed.access_token;
    return token;
  };

  const mintAuditToken = async (): Promise<string> => {
    const rpID = "localhost";
    const { code } = beginPairing(opts.stateDir);
    const passkey = mintSoftwarePasskey();
    const opt = await fetch(`${issuerUrl}/enroll/options`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code }),
    });
    const options = (await opt.json()) as { challenge?: string; error?: string };
    if (!opt.ok || typeof options.challenge !== "string") throw new Error(`enroll options ${opt.status} ${options.error ?? ""}`);
    const registered = await fetch(`${issuerUrl}/enroll/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code,
        response: registerWithSoftwarePasskey(passkey, { challenge: options.challenge, rpID, origin: issuerUrl }),
      }),
    });
    if (!registered.ok) throw new Error(`enroll verify ${registered.status}`);
    enrolledAudit = true;
    const signOpt = await fetch(`${issuerUrl}/authorize/options`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const signOptions = (await signOpt.json()) as { challenge?: string; error?: string };
    if (!signOpt.ok || typeof signOptions.challenge !== "string") {
      throw new Error(`signin options ${signOpt.status} ${signOptions.error ?? ""}`);
    }
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const signed = await fetch(`${issuerUrl}/authorize/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        response: assertWithSoftwarePasskey(passkey, { challenge: signOptions.challenge, rpID, origin: issuerUrl }),
        response_type: "code",
        client_id: "scale-probe",
        redirect_uri: redirectUri,
        code_challenge: challenge,
        code_challenge_method: "S256",
        state: "scale",
      }),
    });
    const signedBody = (await signed.json()) as { location?: string; error?: string };
    if (!signed.ok || typeof signedBody.location !== "string") {
      throw new Error(`signin verify ${signed.status} ${signedBody.error ?? ""}`);
    }
    const authCode = new URL(signedBody.location).searchParams.get("code");
    if (!authCode) throw new Error("signin gave no code");
    const tok = await fetch(`${issuerUrl}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code: authCode,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    const parsed = (await tok.json()) as { access_token?: unknown };
    if (!tok.ok || typeof parsed.access_token !== "string") throw new Error(`audit token ${tok.status}`);
    token = parsed.access_token;
    return token;
  };

  return { issuerUrl, bodyUrl, bodyPid: body.pid ?? 0, bodyStartMs, mintToken, mintAuditToken, stop };
}
