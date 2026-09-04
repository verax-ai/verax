import { existsSync, statSync } from "node:fs";
import { loadConfig, isLoopbackHost } from "./config.ts";

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

  return checks;
}

export function doctorExit(checks: readonly DoctorCheck[]): number {
  return checks.some((c) => c.level === "fail") ? 1 : 0;
}
