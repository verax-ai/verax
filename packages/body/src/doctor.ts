import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { loadConfig, isLoopbackHost } from "./config.ts";
import { pidAlive, readLockFile } from "./unlock.ts";

export type DoctorLevel = "ok" | "warn" | "fail";

export type DoctorCheck = {
  id: string;
  level: DoctorLevel;
  detail: string;
};

const SECRET_RE = /sk-|-----BEGIN|Bearer |eyJ[A-Za-z0-9_-]{10,}\./;
const SECRET_NAME = /^(VERAX_DEV_TOKEN|.*_(TOKEN|SECRET|KEY))$/;

export function runDoctor(env: NodeJS.ProcessEnv, argv: readonly string[]): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  const issuer = Boolean(env.VERAX_ISSUER?.trim());
  const jwks = Boolean(env.VERAX_JWKS_URL?.trim());
  const audience = Boolean(env.VERAX_AUDIENCE?.trim());
  checks.push({
    id: "issuer-jwks-audience",
    level: issuer && jwks && audience ? "ok" : "fail",
    detail:
      issuer && jwks && audience
        ? "VERAX_ISSUER, VERAX_JWKS_URL, and VERAX_AUDIENCE are set"
        : "one of VERAX_ISSUER, VERAX_JWKS_URL, VERAX_AUDIENCE is missing",
  });

  const loaded = loadConfig({
    ...env,
    VERAX_STATE_DIR: env.VERAX_STATE_DIR || "placeholder",
    VERAX_POLICY_FILE: env.VERAX_POLICY_FILE || "placeholder",
  });
  if (loaded.ok) {
    const loop = isLoopbackHost(loaded.value.bindHost);
    if (loop) {
      checks.push({ id: "bind", level: "ok", detail: `bind ${loaded.value.bindHost} is loopback` });
    } else if (loaded.value.tlsTerminated) {
      checks.push({
        id: "bind",
        level: "ok",
        detail: "non-loopback bind with VERAX_TLS_TERMINATED=1",
      });
    } else {
      checks.push({
        id: "bind",
        level: "fail",
        detail: "non-loopback bind without VERAX_TLS_TERMINATED=1",
      });
    }
  } else if (loaded.reason.includes("non-loopback")) {
    checks.push({ id: "bind", level: "fail", detail: loaded.reason });
  } else {
    checks.push({ id: "bind", level: "warn", detail: "bind not judged; issuer triple incomplete" });
  }

  const stateDir = env.VERAX_STATE_DIR?.trim() ?? "";
  if (stateDir === "" || !existsSync(stateDir)) {
    checks.push({
      id: "state-dir",
      level: stateDir === "" ? "fail" : "warn",
      detail: stateDir === "" ? "VERAX_STATE_DIR is missing" : "VERAX_STATE_DIR does not exist yet",
    });
  } else if (process.platform === "win32") {
    checks.push({
      id: "state-dir",
      level: "warn",
      detail: "not checked on this platform",
    });
  } else {
    const mode = statSync(stateDir).mode & 0o777;
    checks.push({
      id: "state-dir",
      level: (mode & 0o077) === 0 ? "ok" : "fail",
      detail:
        (mode & 0o077) === 0
          ? "VERAX_STATE_DIR is owner-only"
          : `VERAX_STATE_DIR mode ${mode.toString(8)} is not 0700`,
    });
  }

  if (stateDir !== "" && existsSync(stateDir)) {
    if (existsSync(join(stateDir, "memory"))) {
      checks.push({
        id: "legacy-memory",
        level: "warn",
        detail: "legacy memory/ is present; reads do not merge it. Move records under tenants/<tenantKey>/memory/",
      });
    }
    const lockPath = join(stateDir, "ledger.lock");
    if (existsSync(lockPath)) {
      const existing = readLockFile(lockPath);
      if (!existing) {
        checks.push({ id: "ledger-lock", level: "fail", detail: "ledger.lock is unreadable" });
      } else if (existing.pid === process.pid) {
        checks.push({ id: "ledger-lock", level: "ok", detail: `ledger.lock is this process (${existing.pid})` });
      } else if (pidAlive(existing.pid)) {
        checks.push({ id: "ledger-lock", level: "warn", detail: `ledger.lock is held by live pid ${existing.pid}` });
      } else {
        checks.push({
          id: "ledger-lock",
          level: "fail",
          detail: `ledger.lock is held by dead pid ${existing.pid}; run: verax unlock ${stateDir}`,
        });
      }
    }
    checks.push(...evidenceChecks(stateDir, env));
  }

  const secretNames = Object.entries(env)
    .filter(([k, v]) => Boolean(v) && (SECRET_NAME.test(k) || SECRET_RE.test(String(v))))
    .map(([k]) => k);
  const secretInArgv = argv.some((a) => SECRET_RE.test(a));
  if (secretInArgv) {
    checks.push({
      id: "secrets-on-argv",
      level: "fail",
      detail: "process.argv matches sk-, PEM begin, Bearer, or JWT",
    });
  } else if (secretNames.length > 0) {
    checks.push({
      id: "secrets-in-env",
      level: "fail",
      detail: `named env keys look secret: ${secretNames.join(", ")}`,
    });
  } else {
    checks.push({
      id: "secrets-on-argv",
      level: "ok",
      detail: "no sk-, PEM, Bearer, or JWT pattern on argv or env",
    });
  }

  const panelPort = panelPortOf(env);
  const portSource = env.VERAX_PANEL_PORT?.trim() ? "VERAX_PANEL_PORT" : "the 5173 default, VERAX_PANEL_PORT unset";
  const redirectUris = redirectAllowList(env);
  const panelRedirect = `http://127.0.0.1:${panelPort}/`;
  // Nothing here opens a port: the number comes from the environment, so both
  // lines name where it came from and an ok cannot be read as a live check.
  if (redirectUris.some((u) => sameRedirect(u, panelRedirect))) {
    checks.push({
      id: "panel-redirect-uri",
      level: "ok",
      detail: `panel port ${panelPort} (${portSource}) is on the issuer redirect allow-list`,
    });
  } else {
    checks.push({
      id: "panel-redirect-uri",
      level: "warn",
      detail: `panel port ${panelPort} (${portSource}) is not on the issuer redirect allow-list; set VERAX_DEV_REDIRECT_URIS=${panelRedirect} or run verax desktop so it passes the panel port`,
    });
  }

  const configuredIssuer = stripSlash(env.VERAX_ISSUER?.trim() ?? "");
  const panelIssuer = stripSlash(env.VITE_VERAX_ISSUER?.trim() || "http://127.0.0.1:8790");
  if (configuredIssuer !== "" && configuredIssuer === panelIssuer) {
    checks.push({
      id: "panel-issuer",
      level: "ok",
      detail: "panel last-resort issuer matches VERAX_ISSUER",
    });
  } else if (configuredIssuer !== "") {
    checks.push({
      id: "panel-issuer",
      level: "warn",
      detail: `panel last-resort issuer ${panelIssuer} differs from VERAX_ISSUER ${configuredIssuer}; the session reads authorization_servers from resource metadata — if that document is unreachable the panel will not start`,
    });
  }

  const tokenScope = scopeFromDevToken(env.VERAX_DEV_TOKEN);
  const mintScope = env.VERAX_DEV_SCOPE?.trim() ?? "";
  const seenScope = tokenScope ?? (mintScope !== "" ? mintScope : null);
  if (seenScope !== null) {
    const parts = seenScope.split(/\s+/).filter((s) => s !== "");
    if (parts.includes("verax:audit")) {
      checks.push({
        id: "dev-token-audit",
        level: "ok",
        detail: "development token scope includes verax:audit",
      });
    } else {
      checks.push({
        id: "dev-token-audit",
        level: "warn",
        detail: "development token scope lacks verax:audit; the panel cannot read /api/ledger or /healthz counts",
      });
    }
  }

  return checks;
}

const DEFAULT_REDIRECTS = ["http://127.0.0.1:5173/", "http://127.0.0.1:4173/"];

function stripSlash(s: string): string {
  return s.replace(/\/$/, "");
}

function panelPortOf(env: NodeJS.ProcessEnv): number {
  const raw = env.VERAX_PANEL_PORT?.trim() ?? "";
  const n = Number(raw);
  if (Number.isInteger(n) && n > 0 && n < 65536) return n;
  return 5173;
}

function redirectAllowList(env: NodeJS.ProcessEnv): string[] {
  const raw = env.VERAX_DEV_REDIRECT_URIS ?? "";
  const listed = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  return listed.length > 0 ? listed : DEFAULT_REDIRECTS;
}

function sameRedirect(a: string, b: string): boolean {
  try {
    const na = new URL(a);
    const nb = new URL(b);
    const pa = na.pathname === "" ? "/" : na.pathname;
    const pb = nb.pathname === "" ? "/" : nb.pathname;
    return `${na.origin}${pa}` === `${nb.origin}${pb}`;
  } catch {
    return false;
  }
}

function scopeFromDevToken(raw: string | undefined): string | null {
  if (!raw || raw.trim() === "") return null;
  const parts = raw.trim().split(".");
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1]!, "base64url").toString("utf8");
    const payload = JSON.parse(json) as { scope?: unknown };
    return typeof payload.scope === "string" ? payload.scope : null;
  } catch {
    return null;
  }
}

export function doctorExit(checks: readonly DoctorCheck[]): number {
  return checks.some((c) => c.level === "fail") ? 1 : 0;
}

function countJsonl(path: string): { lines: number; corrupt: boolean } {
  if (!existsSync(path)) return { lines: 0, corrupt: false };
  try {
    const text = readFileSync(path, "utf8");
    let lines = 0;
    for (const line of text.split("\n")) {
      if (line === "") continue;
      lines += 1;
      try {
        JSON.parse(line);
      } catch {
        return { lines, corrupt: true };
      }
    }
    return { lines, corrupt: false };
  } catch {
    return { lines: 0, corrupt: true };
  }
}

function heartbeatMaxMs(env: NodeJS.ProcessEnv): number {
  const n = Number(env.VERAX_HEARTBEAT_MAX_MS ?? "30000");
  return Number.isFinite(n) && n > 0 ? n : 30_000;
}

function evidenceChecks(stateDir: string, env: NodeJS.ProcessEnv): DoctorCheck[] {
  const checks: DoctorCheck[] = [];
  const src = countJsonl(join(stateDir, "decisions.jsonl"));
  const hbPath = join(stateDir, "heartbeat.json");
  let hb: { atMs?: unknown; lastDecisionN?: unknown } | null = null;
  if (existsSync(hbPath)) {
    try {
      hb = JSON.parse(readFileSync(hbPath, "utf8")) as { atMs?: unknown; lastDecisionN?: unknown };
    } catch {
      hb = null;
    }
  }
  if (src.lines > 0 || hb) {
    if (!hb || typeof hb.atMs !== "number") {
      checks.push({
        id: "heartbeat",
        level: "fail",
        detail: "ledger has rows but no readable heartbeat; the evidence service looks silent",
      });
    } else if (Date.now() - hb.atMs > heartbeatMaxMs(env)) {
      checks.push({
        id: "heartbeat",
        level: "fail",
        detail: `heartbeat is silent; last pulse ${hb.atMs} lastDecisionN ${String(hb.lastDecisionN ?? "?")}`,
      });
    } else {
      checks.push({
        id: "heartbeat",
        level: "ok",
        detail: `heartbeat live; lastDecisionN ${String(hb.lastDecisionN ?? "?")}`,
      });
    }
  }
  const copy = countJsonl(join(stateDir, "evidence-copy", "decisions.jsonl"));
  if (src.lines > 0 || copy.lines > 0 || copy.corrupt) {
    if (copy.corrupt) {
      checks.push({
        id: "evidence-copy",
        level: "fail",
        detail: "evidence-copy/decisions.jsonl is corrupt",
      });
    } else if (copy.lines < src.lines) {
      checks.push({
        id: "evidence-copy",
        level: "fail",
        detail: `evidence copy is stale: ${copy.lines} lines behind source ${src.lines}`,
      });
    } else {
      checks.push({
        id: "evidence-copy",
        level: "ok",
        detail: `evidence copy has ${copy.lines} decision line(s)`,
      });
    }
  }
  return checks;
}
