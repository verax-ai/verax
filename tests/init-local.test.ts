import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

function run(args: string[]): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", cli, ...args], {
    encoding: "utf8",
  });
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function payload(token: string): { scope?: string; exp?: number; iss?: string; aud?: string | string[] } {
  const body = token.split(".")[1];
  assert.ok(body, "token-shape");
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as {
    scope?: string;
    exp?: number;
    iss?: string;
    aud?: string | string[];
  };
}

describe("verax init --local", () => {
  it("writes the key, the jwks, the token, the env file and the policy", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-"));
    try {
      const r = run(["init", "--local", stateDir]);
      assert.equal(r.status, 0, r.stderr);
      for (const name of ["local-issuer/key.pem", "local-issuer/jwks.json", "local-issuer/agent.token", "verax.env", "policy.json"]) {
        assert.equal(existsSync(join(stateDir, name)), true, name);
      }
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("refuses a second run without --force and leaves the key bytes", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-force-"));
    try {
      assert.equal(run(["init", "--local", stateDir]).status, 0);
      const keyPath = join(stateDir, "local-issuer", "key.pem");
      const before = readFileSync(keyPath);
      const again = run(["init", "--local", stateDir]);
      assert.equal(again.status, 78, again.stderr);
      assert.deepEqual(readFileSync(keyPath), before);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("does not print the token", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-quiet-"));
    try {
      const r = run(["init", "--local", stateDir]);
      assert.equal(r.status, 0, r.stderr);
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      assert.ok(token.startsWith("eyJ") && token.length > 40, "token-shape");
      assert.equal(`${r.stdout}${r.stderr}`.includes(token), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("mints read and memory only", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-scope-"));
    try {
      assert.equal(run(["init", "--local", stateDir]).status, 0);
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      const scope = payload(token).scope ?? "";
      const parts = scope.split(/\s+/).filter((s) => s !== "");
      assert.ok(parts.includes("verax:read"));
      assert.ok(parts.includes("verax:memory"));
      assert.equal(parts.includes("verax:approve"), false);
      assert.equal(parts.includes("verax:audit"), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("rejects --days 91", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-days-"));
    try {
      const r = run(["init", "--local", stateDir, "--days", "91"]);
      assert.equal(r.status, 78, r.stderr);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("writes the chosen port into verax.env and the token audience", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-port-"));
    try {
      const r = run(["init", "--local", stateDir, "--port", "8797"]);
      assert.equal(r.status, 0, r.stderr);
      const env = readFileSync(join(stateDir, "verax.env"), "utf8");
      assert.match(env, /^VERAX_BIND=127\.0\.0\.1:8797$/m);
      assert.match(env, /^VERAX_AUDIENCE=http:\/\/127\.0\.0\.1:8797$/m);
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      const aud = payload(token).aud;
      const audiences = Array.isArray(aud) ? aud : [aud];
      assert.ok(audiences.includes("http://127.0.0.1:8797"));
      assert.match(r.stdout, /http:\/\/127\.0\.0\.1:8797\/mcp/);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("rejects a port outside 1024-65535", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-init-port-range-"));
    try {
      assert.equal(run(["init", "--local", stateDir, "--port", "80"]).status, 78);
      assert.equal(run(["init", "--local", stateDir, "--port", "70000"]).status, 78);
      assert.equal(existsSync(join(stateDir, "verax.env")), false);
    } finally {
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("quotes the token path when the state dir contains a space", () => {
    const parent = mkdtempSync(join(tmpdir(), "verax-init-space-"));
    const stateDir = join(parent, "state dir");
    try {
      const r = run(["init", "--local", stateDir]);
      assert.equal(r.status, 0, r.stderr);
      const tokenPath = join(stateDir, "local-issuer", "agent.token").replaceAll("\\", "/");
      const shLine = r.stdout.split(/\r?\n/).find((line) => line.includes("$(cat "));
      const psLine = r.stdout.split(/\r?\n/).find((line) => line.includes("Get-Content"));
      assert.ok(shLine, "sh-line");
      assert.ok(psLine, "ps-line");
      assert.equal(pathInsideQuotes(shLine ?? "", tokenPath), true);
      assert.equal(pathInsideQuotes(psLine ?? "", tokenPath), true);
      const envLine = r.stdout.split(/\r?\n/).find((line) => line.includes("serve --env-file"));
      const envPath = join(stateDir, "verax.env").replaceAll("\\", "/");
      assert.equal(pathInsideQuotes(envLine ?? "", envPath), true);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  });
});

function pathInsideQuotes(line: string, path: string): boolean {
  const at = line.indexOf(path);
  if (at < 1) return false;
  const before = line[at - 1];
  const after = line[at + path.length];
  return (before === "'" || before === '"') && after === before;
}
