import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { indexCoverage, listPieceFiles } from "@verax-ai/proxy";
import { loadConfig, isLoopbackHost } from "./config.ts";
import { parseDownstreamDocument } from "./downstream.ts";
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
  const jwksUrl = Boolean(env.VERAX_JWKS_URL?.trim());
  const jwksFileSet = Boolean(env.VERAX_JWKS_FILE?.trim());
  const jwks = jwksUrl || jwksFileSet;
  const audience = Boolean(env.VERAX_AUDIENCE?.trim());
  const tripleReady = issuer && jwks && audience;
  checks.push({
    id: "issuer-jwks-audience",
    level: tripleReady ? "ok" : "fail",
    detail: tripleReady
      ? jwksFileSet && !jwksUrl
        ? "VERAX_ISSUER, VERAX_JWKS_FILE, and VERAX_AUDIENCE are set"
        : "VERAX_ISSUER, VERAX_JWKS_URL, and VERAX_AUDIENCE are set"
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
  } else if (loaded.reason.includes("non-loopback") || loaded.reason.includes("loopback bind")) {
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

  const downstreamPath = env.VERAX_DOWNSTREAM?.trim() ?? "";
  if (downstreamPath !== "") {
    try {
      const specs = parseDownstreamDocument(readFileSync(downstreamPath, "utf8"));
      const stdio = specs.filter((s) => s.command !== undefined);
      const http = specs.filter((s) => s.url !== undefined);
      checks.push({
        id: "downstream-document",
        level: "ok",
        detail: `${specs.length} child(ren): ${stdio.length} stdio, ${http.length} http`,
      });
      for (const spec of stdio) {
        checks.push({
          id: `downstream-stdio:${spec.prefix}`,
          level: "warn",
          detail: `stdio child ${spec.prefix} runs as the same user as the body and can read the body's signing keys (keys/*.pem). An untrusted child should be reached over HTTP, ideally on a separate machine or under a separate operating-system user.`,
        });
      }
    } catch (err) {
      checks.push({
        id: "downstream-document",
        level: "fail",
        detail: err instanceof Error ? err.message : "downstream-document-unreadable",
      });
    }
  }

  checks.push(...jwksFileChecks(env, stateDir));

  return checks;
}

function jwksFileChecks(env: NodeJS.ProcessEnv, stateDir: string): DoctorCheck[] {
  const file = env.VERAX_JWKS_FILE?.trim() ?? "";
  if (file === "") return [];
  const out: DoctorCheck[] = [];
  let kid = "";
  let parses = false;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as { keys?: Array<{ kid?: unknown }> };
    const first = parsed.keys?.[0];
    if (first && typeof first.kid === "string" && first.kid !== "") {
      parses = true;
      kid = first.kid;
    }
  } catch {
    parses = false;
  }
  out.push({
    id: "jwks-file",
    level: parses ? "ok" : "fail",
    detail: parses ? `VERAX_JWKS_FILE ${file} parses kid ${kid}` : `VERAX_JWKS_FILE ${file} does not parse`,
  });
  if (stateDir === "") return out;
  const tokenPath = join(stateDir, "local-issuer", "agent.token");
  if (!existsSync(tokenPath)) return out;
  const exp = expFromToken(readFileSync(tokenPath, "utf8"));
  const weekSec = 7 * 24 * 60 * 60;
  if (exp !== null && exp <= Math.floor(Date.now() / 1000) + weekSec) {
    out.push({
      id: "local-agent-token",
      level: "warn",
      detail: `${tokenPath} expires within 7 days`,
    });
  }
  return out;
}

function expFromToken(raw: string): number | null {
  const parts = raw.trim().split(".");
  if (parts.length < 2) return null;
  try {
    const json = Buffer.from(parts[1]!, "base64url").toString("utf8");
    const payload = JSON.parse(json) as { exp?: unknown };
    return typeof payload.exp === "number" ? payload.exp : null;
  } catch {
    return null;
  }
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
  let pieces: ReturnType<typeof listPieceFiles>;
  try {
    pieces = listPieceFiles(stateDir);
  } catch (err) {
    checks.push({ id: "ledger-manifest", level: "fail", detail: (err as Error).message });
    return checks;
  }
  const srcLines = pieces.reduce((s, p) => s + countJsonl(p.decisions).lines, 0);
  const decisionN = pieces.reduce((s, p) => s + (p.closed ? p.n : countJsonl(p.decisions).lines), 0);
  if (decisionN > 0) {
    const known = new Set(pieces.map((p) => p.id));
    const cov = indexCoverage(stateDir);
    if (cov === null) {
      checks.push({
        id: "ledger-index",
        level: "fail",
        detail: `index names 0 of ${decisionN} decisions; the next open rebuilds it, a running body misses the rest until then`,
      });
    } else {
      const ghost = [...cov.pieces].find((id) => !known.has(id));
      if (ghost !== undefined) {
        checks.push({
          id: "ledger-index",
          level: "fail",
          detail: `index names piece ${ghost} that the manifest does not`,
        });
      } else if (cov.refs === decisionN) {
        checks.push({
          id: "ledger-index",
          level: "ok",
          detail: `index names ${decisionN} of ${decisionN} decisions`,
        });
      } else {
        checks.push({
          id: "ledger-index",
          level: "fail",
          detail: `index names ${cov.refs} of ${decisionN} decisions; the next open rebuilds it, a running body misses the rest until then`,
        });
      }
    }
  }
  const hbPath = join(stateDir, "heartbeat.json");
  let hb: { atMs?: unknown; lastDecisionN?: unknown } | null = null;
  if (existsSync(hbPath)) {
    try {
      hb = JSON.parse(readFileSync(hbPath, "utf8")) as { atMs?: unknown; lastDecisionN?: unknown };
    } catch {
      hb = null;
    }
  }
  if (srcLines > 0 || hb) {
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
  // Each piece is mirrored on its own, so a short copy on one piece is a fail
  // even when another piece's copy still matches.
  let anything = false;
  let fail: DoctorCheck | null = null;
  let decisionLines = 0;
  let effectLines = 0;
  for (const piece of pieces) {
    const src = countJsonl(piece.decisions);
    const srcEffects = countJsonl(piece.effects);
    const copy = countJsonl(piece.copyDecisions);
    const copyEffects = countJsonl(piece.copyEffects);
    decisionLines += src.lines;
    effectLines += srcEffects.lines;
    const pieceAnything =
      src.lines > 0 ||
      srcEffects.lines > 0 ||
      copy.lines > 0 ||
      copyEffects.lines > 0 ||
      copy.corrupt ||
      copyEffects.corrupt;
    if (!pieceAnything) continue;
    anything = true;
    if (fail) continue;
    if (copy.corrupt || copyEffects.corrupt) {
      fail = {
        id: "evidence-copy",
        level: "fail",
        detail: `evidence-copy piece ${piece.id} ${copy.corrupt ? "decisions" : "effects"}.jsonl is corrupt`,
      };
    } else if (copy.lines < src.lines) {
      fail = {
        id: "evidence-copy",
        level: "fail",
        detail: `evidence copy is stale on piece ${piece.id}: ${copy.lines} lines behind source ${src.lines}`,
      };
    } else if (copyEffects.lines < srcEffects.lines) {
      fail = {
        id: "evidence-copy",
        level: "fail",
        detail: `evidence copy is stale on piece ${piece.id} effects: ${copyEffects.lines} effect line(s) behind source ${srcEffects.lines}`,
      };
    }
  }
  if (anything) {
    checks.push(
      fail ?? {
        id: "evidence-copy",
        level: "ok",
        detail: `evidence copy has ${decisionLines} decision line(s) and ${effectLines} effect line(s)`,
      },
    );
  }
  return checks;
}
