// R1: an MCP client with a verax init --local agent token (verax:read verax:memory),
// or with no token / a forged token, speaking only HTTP. The client has no
// filesystem access to the state directory. A failure here is a finding.

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer, type Server as HttpServer } from "node:http";
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { exportJWK, generateKeyPair, importPKCS8, SignJWT } from "jose";

import { loadConfig } from "../packages/body/src/config.ts";
import { runHalt } from "../packages/body/src/halt.ts";
import { loadEnvFile } from "../packages/body/src/init-local.ts";
import { listen } from "../packages/body/src/server.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "packages", "body", "src", "cli.ts");
const echoChild = join(root, "tests", "fixtures", "downstream-echo.mjs");
const MAX_BODY_BYTES = 1024 * 1024;

type DecisionRow = {
  claims: {
    decision: string;
    ref?: string;
    subject?: string;
    reasonCode?: string;
    timestampMs?: number;
  };
  coseHex?: string;
};

type EffectRow = {
  row: { ref: string; effectClass: string; timestampMs?: number };
};

type RpcResult = { status: number; json: Record<string, unknown> | null; text: string };

function init(stateDir: string): void {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", cli, "init", "--local", stateDir], {
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
}

function envFromFile(stateDir: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const loaded = loadEnvFile(join(stateDir, "verax.env"), env);
  assert.equal(loaded.ok, true);
  return env;
}

function readDecisions(stateDir: string): DecisionRow[] {
  const path = join(stateDir, "decisions.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as DecisionRow);
}

function readEffects(stateDir: string): EffectRow[] {
  const path = join(stateDir, "effects.jsonl");
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as EffectRow);
}

function allows(rows: DecisionRow[]): DecisionRow[] {
  return rows.filter((row) => row.claims.decision === "allow");
}

function assertSignedDeny(row: DecisionRow, label: string): void {
  assert.equal(row.claims.decision, "deny", label);
  assert.equal(typeof row.coseHex, "string", label);
  assert.ok((row.coseHex ?? "").length > 0, label);
}

function textOf(json: Record<string, unknown> | null): string {
  const result = json?.result as { content?: { text?: string }[] } | undefined;
  return (result?.content ?? []).map((c) => c.text ?? "").join("");
}

async function rpc(
  url: string,
  token: string | null,
  method: string,
  params: Record<string, unknown>,
): Promise<RpcResult> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

function payloadOf(token: string): Record<string, unknown> {
  const body = token.split(".")[1];
  assert.ok(body, "token-shape");
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

type LocalKey = {
  kid: string;
  privateKey: Awaited<ReturnType<typeof importPKCS8>>;
  jwk: Record<string, unknown>;
  audience: string;
};

async function localKey(stateDir: string, audience: string): Promise<LocalKey> {
  const pem = readFileSync(join(stateDir, "local-issuer", "key.pem"), "utf8");
  const jwks = JSON.parse(readFileSync(join(stateDir, "local-issuer", "jwks.json"), "utf8")) as {
    keys: Record<string, unknown>[];
  };
  const jwk = jwks.keys[0];
  assert.ok(jwk);
  const kid = String(jwk.kid ?? "");
  assert.ok(kid !== "");
  return { kid, privateKey: await importPKCS8(pem, "ES256"), jwk, audience };
}

async function signLocal(
  key: LocalKey,
  over: {
    aud?: string;
    iss?: string;
    sub?: string;
    exp?: "past" | "future";
    omitJti?: boolean;
    kid?: string;
    scope?: string;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({ scope: over.scope ?? "verax:read verax:memory" })
    .setProtectedHeader({ alg: "ES256", kid: over.kid ?? key.kid })
    .setSubject(over.sub ?? "local-agent")
    .setIssuer(over.iss ?? "verax-local")
    .setAudience(over.aud ?? key.audience)
    .setIssuedAt(over.exp === "past" ? now - 3600 : now);
  if (over.exp === "past") jwt.setExpirationTime(now - 120);
  else jwt.setExpirationTime("1h");
  if (over.omitJti !== true) jwt.setJti(crypto.randomUUID());
  return jwt.sign(key.privateKey);
}

function spendRule(): Record<string, unknown> {
  return {
    id: "spend",
    tool: "spend",
    requires: ["verax:memory"],
    mode: "approve",
    text: "A payment is held for an operator.",
    spend: {
      maxAmountMinor: 5000,
      currency: "USD",
      payees: ["sample-merchant"],
      dailyMaxMinor: 10_000,
    },
  };
}

function writePolicy(stateDir: string, rules: unknown[], extra: Record<string, unknown> = {}): void {
  const policy = {
    version: 1,
    default: "deny",
    rules,
    ...extra,
  };
  writeFileSync(join(stateDir, "policy.json"), `${JSON.stringify(policy)}\n`);
}

const memoryRules = [
  {
    id: "memory-get",
    tool: "memory.get",
    requires: ["verax:read"],
    text: "Reading memory needs the read scope.",
  },
  {
    id: "memory-put",
    tool: "memory.put",
    requires: ["verax:memory"],
    text: "Writing memory needs the memory scope.",
  },
];

type Boot = {
  stateDir: string;
  base: string;
  mcp: string;
  token: string;
  audience: string;
  close: () => Promise<void>;
};

async function boot(opts: {
  rules?: unknown[];
  extraPolicy?: Record<string, unknown>;
  downstreamFile?: string;
} = {}): Promise<Boot> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r1-"));
  init(stateDir);
  if (opts.rules) writePolicy(stateDir, opts.rules, opts.extraPolicy);
  const env = envFromFile(stateDir);
  env.VERAX_BIND = "127.0.0.1:0";
  if (opts.downstreamFile) env.VERAX_DOWNSTREAM = opts.downstreamFile;
  const loaded = loadConfig(env);
  if (!loaded.ok) throw new Error(loaded.reason);
  const http = await listen(loaded.value);
  const port = (http.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  return {
    stateDir,
    base,
    mcp: `${base}/mcp`,
    token: readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim(),
    audience: env.VERAX_AUDIENCE ?? "",
    close: async () => {
      await new Promise<void>((resolveClose, reject) => {
        http.close((err) => (err ? reject(err) : resolveClose()));
      });
      rmSync(stateDir, { recursive: true, force: true });
    },
  };
}

function spendArgs(ref: string, amountMinor = 100): Record<string, unknown> {
  return {
    amountMinor,
    currency: "USD",
    payee: "sample-merchant",
    reference: "local-1",
    _ref: ref,
  };
}

function assertNoSpendAllow(stateDir: string, label: string): void {
  const rows = readDecisions(stateDir).filter((row) => row.claims.subject === "spend" && row.claims.decision === "allow");
  assert.deepEqual(rows, [], `${label} spend allow ${JSON.stringify(readDecisions(stateDir))}`);
  const ran = readEffects(stateDir).filter((row) => row.row.effectClass === "spend");
  assert.deepEqual(ran, [], `${label} spend effect ${JSON.stringify(readEffects(stateDir))}`);
}

function walkFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkFiles(path));
    else out.push(path);
  }
  return out;
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

describe("attack R1", () => {
  it("1 token forgery is 401 and writes no decision", { timeout: 60_000 }, async () => {
    const box = await boot();
    const evilJwks: HttpServer = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [] }));
    });
    try {
      const key = await localKey(box.stateDir, box.audience);
      const { privateKey: otherPriv, publicKey: otherPub } = await generateKeyPair("ES256", { extractable: true });
      const otherJwk = { ...(await exportJWK(otherPub)), alg: "ES256", use: "sig", kid: "evil" };
      await new Promise<void>((resolveListen, reject) => {
        evilJwks.once("error", reject);
        evilJwks.listen(0, "127.0.0.1", () => resolveListen());
      });
      const evilPort = (evilJwks.address() as { port: number }).port;
      evilJwks.removeAllListeners("request");
      evilJwks.on("request", (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ keys: [otherJwk] }));
      });
      const jku = `http://127.0.0.1:${evilPort}/jwks.json`;

      const other = await new SignJWT({ scope: "verax:read verax:memory" })
        .setProtectedHeader({ alg: "ES256", kid: key.kid })
        .setIssuer("verax-local")
        .setAudience(box.audience)
        .setSubject("local-agent")
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(otherPriv);

      const now = Math.floor(Date.now() / 1000);
      const noneClaims = {
        scope: "verax:read verax:memory",
        iss: "verax-local",
        aud: box.audience,
        sub: "local-agent",
        iat: now,
        exp: now + 600,
        jti: crypto.randomUUID(),
      };
      const none = `${b64url({ alg: "none", kid: key.kid, typ: "JWT" })}.${b64url(noneClaims)}.`;

      const x = Buffer.from(String(key.jwk.x), "base64url");
      const y = Buffer.from(String(key.jwk.y), "base64url");
      const hmacSecret = Buffer.concat([Buffer.from([0x04]), x, y]);
      const confused = await new SignJWT({ scope: "verax:read verax:memory" })
        .setProtectedHeader({ alg: "HS256", kid: key.kid })
        .setIssuer("verax-local")
        .setAudience(box.audience)
        .setSubject("local-agent")
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(hmacSecret);

      const headerAttack = async (field: "jku" | "x5u") =>
        new SignJWT({ scope: "verax:read verax:memory" })
          .setProtectedHeader({ alg: "ES256", kid: "evil", [field]: jku })
          .setIssuer("verax-local")
          .setAudience(box.audience)
          .setSubject("local-agent")
          .setJti(crypto.randomUUID())
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(otherPriv);

      const forged: { name: string; token: string }[] = [
        { name: "other-key", token: other },
        { name: "alg-none", token: none },
        { name: "hs256-confusion", token: confused },
        { name: "expired", token: await signLocal(key, { exp: "past" }) },
        { name: "wrong-aud", token: await signLocal(key, { aud: "http://127.0.0.1:1" }) },
        { name: "wrong-iss", token: await signLocal(key, { iss: "https://evil.test" }) },
        { name: "no-jti", token: await signLocal(key, { omitJti: true }) },
        { name: "jku", token: await headerAttack("jku") },
        { name: "x5u", token: await headerAttack("x5u") },
        { name: "unknown-kid", token: await signLocal(key, { kid: "not-in-file" }) },
      ];

      for (const item of forged) {
        const before = readDecisions(box.stateDir).length;
        const res = await rpc(box.mcp, item.token, "tools/list", {});
        assert.equal(res.status, 401, `${item.name} ${res.status} ${res.text}`);
        assert.equal(readDecisions(box.stateDir).length, before, `${item.name} wrote a decision`);
      }
    } finally {
      await new Promise<void>((resolveClose) => {
        evilJwks.close(() => resolveClose());
      });
      await box.close();
    }
  });

  it("2 agent token cannot approve, read the ledger, or see health counts", async () => {
    const box = await boot();
    try {
      const before = readDecisions(box.stateDir);
      const approve = await fetch(`${box.base}/api/approve`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${box.token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ ref: "r1", requestHash: "deadbeef" }),
      });
      assert.equal(approve.status, 403, await approve.text());
      const ledger = await fetch(`${box.base}/api/ledger`, {
        headers: { authorization: `Bearer ${box.token}` },
      });
      assert.equal(ledger.status, 403, await ledger.text());
      const agents = await fetch(`${box.base}/api/agents`, {
        headers: { authorization: `Bearer ${box.token}` },
      });
      assert.ok(agents.status === 403 || agents.status === 401, String(agents.status));
      const health = await fetch(`${box.base}/healthz`, {
        headers: { authorization: `Bearer ${box.token}` },
      });
      assert.equal(health.status, 200);
      assert.deepEqual(await health.json(), { ok: true });
      assert.deepEqual(readDecisions(box.stateDir), before);
    } finally {
      await box.close();
    }
  });

  it("3 a held spend is not an allow when the same _ref is sent again", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: [...memoryRules, spendRule()] });
    try {
      const first = await rpc(box.mcp, box.token, "tools/call", {
        name: "spend",
        arguments: spendArgs("r1"),
      });
      const firstText = textOf(first.json);
      assert.match(firstText, /^deferred:approval-required:/, firstText);
      assert.equal(firstText.startsWith("allowed:"), false);

      const same = await rpc(box.mcp, box.token, "tools/call", {
        name: "spend",
        arguments: spendArgs("r1"),
      });
      const sameText = textOf(same.json);
      assert.equal(sameText.startsWith("allowed:"), false, sameText);
      assert.equal(sameText.includes('"authorized":true'), false, sameText);

      const changed = await rpc(box.mcp, box.token, "tools/call", {
        name: "spend",
        arguments: spendArgs("r1", 250),
      });
      const changedText = textOf(changed.json);
      assert.equal(changedText.startsWith("allowed:"), false, changedText);
      assert.equal(changedText.includes('"authorized":true'), false, changedText);

      const forR1 = readDecisions(box.stateDir).filter(
        (row) => row.claims.ref === "r1" || row.claims.ref?.endsWith(":r1"),
      );
      assert.ok(forR1.length > 0, JSON.stringify(readDecisions(box.stateDir)));
      assert.equal(
        forR1.some((row) => row.claims.decision === "allow"),
        false,
        JSON.stringify(forR1),
      );
      assertNoSpendAllow(box.stateDir, "replay");
    } finally {
      await box.close();
    }
  });

  it("4 twenty parallel spends with one _ref allow nothing", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: [...memoryRules, spendRule()] });
    try {
      const calls = await Promise.all(
        Array.from({ length: 20 }, () =>
          rpc(box.mcp, box.token, "tools/call", { name: "spend", arguments: spendArgs("r1") }),
        ),
      );
      for (const call of calls) {
        const text = textOf(call.json);
        assert.equal(text.startsWith("allowed:"), false, text);
        assert.equal(text.includes('"authorized":true'), false, text);
      }
      assertNoSpendAllow(box.stateDir, "parallel");
      assert.equal(
        readDecisions(box.stateDir).some((row) => row.claims.decision === "allow"),
        false,
        JSON.stringify(readDecisions(box.stateDir)),
      );
    } finally {
      await box.close();
    }
  });

  it("5 tool-name tricks are not allowed", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: memoryRules });
    try {
      const names = [
        "spend ",
        "Spend",
        "spend\u200b",
        "\u0455pend",
        "memory.put/../spend",
        "x.spend",
        "",
        "n".repeat(10 * 1024),
      ];
      for (const name of names) {
        const before = readDecisions(box.stateDir).length;
        const res = await rpc(box.mcp, box.token, "tools/call", {
          name,
          arguments: spendArgs("name-trick"),
        });
        const text = textOf(res.json);
        const added = readDecisions(box.stateDir).slice(before);
        const protocolError = res.json?.error !== undefined || (res.status !== 200 && text === "");
        assert.equal(text.startsWith("allowed:"), false, `${JSON.stringify(name)} ${text}`);
        assert.equal(
          added.some((row) => row.claims.decision === "allow"),
          false,
          `${JSON.stringify(name)} ${JSON.stringify(added)}`,
        );
        if (added.length > 0) {
          for (const row of added) assertSignedDeny(row, JSON.stringify(name));
        } else {
          assert.equal(protocolError, true, `${JSON.stringify(name)} ${res.status} ${res.text}`);
        }
      }
    } finally {
      await box.close();
    }
  });

  it("6 memory ids cannot leave the tenant directory", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: memoryRules });
    try {
      const keyDir = join(box.stateDir, "keys");
      const keysBefore = existsSync(keyDir)
        ? new Map(walkFiles(keyDir).map((path) => [path, sha256File(path)]))
        : new Map<string, string>();
      const outsideBefore = new Set(walkFiles(box.stateDir).map((path) => relative(box.stateDir, path)));
      const ids = [
        "../../keys/record.private.pem",
        "..\\..\\keys\\x",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "%2e%2e%2f",
        "a\u0000b",
        `a${"b".repeat(4095)}`,
      ];
      const source = { uri: "file://t", retrievedAtMs: 1 };
      for (const id of ids) {
        for (const name of ["memory.put", "memory.get"] as const) {
          const args =
            name === "memory.put"
              ? { id, body: { note: "x" }, source, validUntilMs: Date.now() + 60_000 }
              : { id };
          const res = await rpc(box.mcp, box.token, "tools/call", { name, arguments: args });
          const text = textOf(res.json);
          const refused = text.includes("id-invalid") || text.includes("denied:");
          assert.equal(refused, true, `${name} ${JSON.stringify(id)} ${text}`);
          assert.equal(text.includes("root:"), false, text);
          assert.equal(text.includes("-----BEGIN"), false, text);
          assert.equal(text.includes("[fonts]"), false, text);
        }
      }
      const stateRoot = resolve(box.stateDir);
      for (const path of walkFiles(box.stateDir)) {
        const abs = resolve(path);
        assert.equal(abs.startsWith(stateRoot), true, abs);
        const rel = relative(box.stateDir, path).replaceAll("\\", "/");
        if (outsideBefore.has(relative(box.stateDir, path))) continue;
        const allowedNew =
          rel.startsWith("tenants/") ||
          rel.startsWith("evidence-copy/") ||
          rel.startsWith("policy-store/") ||
          rel.startsWith("in-flight/") ||
          rel === "decisions.jsonl" ||
          rel === "effects.jsonl" ||
          rel === "inputs.jsonl" ||
          rel === "approvals.jsonl" ||
          // Written by the body as it records, not by the memory id under test.
          rel === "heartbeat.json" ||
          rel === "metrics.json" ||
          rel === "witness-status.jsonl" ||
          rel === "index.jsonl" ||
          rel === "ledger-manifest.json" ||
          rel === "ledger.lock";
        assert.equal(allowedNew, true, rel);
      }
      for (const [path, hash] of keysBefore) {
        assert.equal(existsSync(path), true, path);
        assert.equal(sha256File(path), hash, path);
      }
      const rows = readDecisions(box.stateDir);
      for (const row of rows) {
        assert.ok(row.claims.decision === "allow" || row.claims.decision === "deny", JSON.stringify(row.claims));
        if (row.claims.decision === "deny") assertSignedDeny(row, row.claims.ref ?? "id");
      }
    } finally {
      await box.close();
    }
  });

  it("7 odd JSON-RPC shapes do not allow spend and the body still answers", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: [...memoryRules, spendRule()] });
    try {
      const headers = {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${box.token}`,
      };
      const put = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "memory.put",
          arguments: {
            id: "batch-1",
            body: { note: "batch" },
            source: { uri: "file://t", retrievedAtMs: 1 },
            validUntilMs: Date.now() + 60_000,
          },
        },
      };
      const spend = {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "spend", arguments: spendArgs("batch-spend") },
      };
      const batch = await fetch(box.mcp, { method: "POST", headers, body: JSON.stringify([put, spend]) });
      await batch.text();
      const note = await fetch(box.mcp, {
        method: "POST",
        headers,
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: spend.params }),
      });
      await note.text();
      const dup = await fetch(box.mcp, {
        method: "POST",
        headers,
        body: JSON.stringify([
          { ...spend, id: 7 },
          { ...put, id: 7 },
        ]),
      });
      await dup.text();
      const polluted = await fetch(box.mcp, {
        method: "POST",
        headers,
        body: '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"spend","arguments":{"amountMinor":100,"currency":"USD","payee":"sample-merchant","reference":"local-1","_ref":"proto","__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}}}',
      });
      await polluted.text();
      assert.equal(({} as { polluted?: boolean }).polluted, undefined);
      const health = await fetch(`${box.base}/healthz`);
      assert.equal(health.status, 200, await health.text());
      assertNoSpendAllow(box.stateDir, "jsonrpc");
    } finally {
      await box.close();
    }
  });

  it("8 only the exact egress host is allowed", { timeout: 60_000 }, async () => {
    // message.send documents: the host after the last '@' is lower-cased, then
    // matched against the egress list. OK.TEST therefore matches ok.test.
    // A trailing dot is not stripped, so ok.test. does not match.
    const box = await boot({
      rules: [
        ...memoryRules,
        {
          id: "message-send",
          tool: "message.send",
          requires: ["verax:memory"],
          egress: true,
          text: "Queueing a message needs the memory scope and a recipient host on the egress list.",
        },
      ],
      extraPolicy: { egress: ["ok.test"] },
    });
    try {
      const cases: { to: string; allow: boolean }[] = [
        { to: "user@ok.test", allow: true },
        { to: "user@ok.test.evil.test", allow: false },
        { to: "user@evil.test#ok.test", allow: false },
        { to: "user@ok.test@evil.test", allow: false },
        { to: "user@OK.TEST", allow: true },
        { to: "user@ok.test.", allow: false },
        { to: "user@xn--ok.test", allow: false },
        { to: "user@127.0.0.1", allow: false },
        { to: "user@[::1]", allow: false },
        { to: "user@0x7f000001", allow: false },
        { to: "user@evil.test/ok.test", allow: false },
      ];
      for (const item of cases) {
        const before = readDecisions(box.stateDir).length;
        const res = await rpc(box.mcp, box.token, "tools/call", {
          name: "message.send",
          arguments: { to: item.to, text: "hi" },
        });
        const text = textOf(res.json);
        const added = readDecisions(box.stateDir).slice(before);
        if (item.allow) {
          assert.equal((res.json?.result as { isError?: boolean } | undefined)?.isError, false, `${item.to} ${text}`);
          assert.equal(text.includes('"queued":true'), true, text);
          assert.equal(added.some((row) => row.claims.decision === "allow"), true, JSON.stringify(added));
        } else {
          assert.equal(text.startsWith("allowed:"), false, `${item.to} ${text}`);
          assert.equal(text.includes('"queued":true'), false, `${item.to} ${text}`);
          assert.ok(added.length > 0, `${item.to} wrote no decision ${res.status} ${res.text}`);
          for (const row of added) assertSignedDeny(row, item.to);
        }
      }
    } finally {
      await box.close();
    }
  });

  it("9 halt denies every later call", async () => {
    const box = await boot({ rules: memoryRules });
    try {
      assert.equal(runHalt(box.stateDir, () => undefined), 0);
      for (const name of ["memory.get", "memory.put"] as const) {
        const before = readDecisions(box.stateDir).length;
        const res = await rpc(box.mcp, box.token, "tools/call", {
          name,
          arguments:
            name === "memory.get"
              ? { id: "halt-1" }
              : {
                  id: "halt-1",
                  body: { note: "no" },
                  source: { uri: "file://t", retrievedAtMs: 1 },
                  validUntilMs: Date.now() + 60_000,
                },
        });
        const text = textOf(res.json);
        assert.match(text, /denied:halted:/, `${name} ${text}`);
        const added = readDecisions(box.stateDir).slice(before);
        assert.ok(added.length > 0, name);
        for (const row of added) {
          assertSignedDeny(row, name);
          assert.equal(row.claims.reasonCode, "halted", name);
        }
      }
    } finally {
      await box.close();
    }
  });

  it("10 another subject cannot read this tenant's memory", { timeout: 60_000 }, async () => {
    const box = await boot({ rules: memoryRules });
    try {
      const put = await rpc(box.mcp, box.token, "tools/call", {
        name: "memory.put",
        arguments: {
          id: "secret-1",
          body: { note: "tenant-secret-body" },
          source: { uri: "file://t", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 60_000,
        },
      });
      assert.equal((put.json?.result as { isError?: boolean } | undefined)?.isError, false, textOf(put.json));
      const key = await localKey(box.stateDir, box.audience);
      const other = await signLocal(key, { sub: "other-agent" });
      const before = readDecisions(box.stateDir).length;
      const got = await rpc(box.mcp, other, "tools/call", {
        name: "memory.get",
        arguments: { id: "secret-1" },
      });
      const text = textOf(got.json);
      const answered = JSON.parse(text) as { error?: string };
      assert.equal(answered.error, "not-found", text);
      assert.equal(text.includes("tenant-secret-body"), false, text);
      const added = readDecisions(box.stateDir).slice(before);
      assert.ok(added.length > 0, JSON.stringify(got));
      for (const row of added) {
        assertSignedDeny(row, "tenant");
        assert.equal(row.claims.reasonCode, "tenant-mismatch", text);
      }
    } finally {
      await box.close();
    }
  });

  it("11 a body over MAX_BODY_BYTES is 413 and writes no decision", async () => {
    const box = await boot();
    try {
      const before = readDecisions(box.stateDir).length;
      const res = await fetch(box.mcp, {
        method: "POST",
        headers: {
          authorization: `Bearer ${box.token}`,
          "content-type": "application/json",
        },
        body: "x".repeat(MAX_BODY_BYTES + 1),
      });
      assert.equal(res.status, 413, await res.text());
      assert.equal(readDecisions(box.stateDir).length, before);
    } finally {
      await box.close();
    }
  });

  it("12 a tool that throws records :threw bound to its decision", { timeout: 60_000 }, async () => {
    const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r1-throw-"));
    const downstreamFile = join(stateDir, "downstream.json");
    writeFileSync(
      downstreamFile,
      `${JSON.stringify({
        prefix: "echo",
        command: process.execPath,
        args: [echoChild],
        trust: "same-user",
      })}\n`,
    );
    const box = await boot({
      rules: [
        ...memoryRules,
        {
          id: "echo-ping",
          tool: "echo.ping",
          requires: ["verax:memory"],
          text: "A downstream probe the operator attached.",
        },
      ],
      downstreamFile,
    });
    try {
      const res = await rpc(box.mcp, box.token, "tools/call", {
        name: "echo.ping",
        arguments: { fail: true },
      });
      const effects = readEffects(box.stateDir).filter((row) => row.row.effectClass.endsWith(":threw"));
      assert.ok(effects.length > 0, `${res.status} ${res.text} ${JSON.stringify(readEffects(box.stateDir))}`);
      const decisions = readDecisions(box.stateDir);
      for (const effect of effects) {
        const decision = decisions.find((row) => row.claims.ref === effect.row.ref);
        assert.ok(decision, `unbound ${effect.row.ref}`);
        assert.equal(typeof decision.coseHex, "string");
      }
    } finally {
      await box.close();
      rmSync(stateDir, { recursive: true, force: true });
    }
  });

  it("13 the decision is on disk before the tool starts", { timeout: 60_000 }, async () => {
    const scratch = mkdtempSync(join(tmpdir(), "verax-attack-r1-clock-"));
    const childPath = join(scratch, "clock.mjs");
    const serverUrl = pathToFileURL(join(root, "node_modules", "@modelcontextprotocol", "sdk", "dist", "esm", "server", "index.js")).href;
    const stdioUrl = pathToFileURL(join(root, "node_modules", "@modelcontextprotocol", "sdk", "dist", "esm", "server", "stdio.js")).href;
    const typesUrl = pathToFileURL(join(root, "node_modules", "@modelcontextprotocol", "sdk", "dist", "esm", "types.js")).href;
    writeFileSync(
      childPath,
      [
        `import { readFileSync } from "node:fs";`,
        `import { Server } from ${JSON.stringify(serverUrl)};`,
        `import { StdioServerTransport } from ${JSON.stringify(stdioUrl)};`,
        `import { CallToolRequestSchema, ListToolsRequestSchema } from ${JSON.stringify(typesUrl)};`,
        `const server = new Server({ name: "clock", version: "0.0.0" }, { capabilities: { tools: {} } });`,
        `server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "now", description: "reads the ledger", inputSchema: { type: "object" } }] }));`,
        `server.setRequestHandler(CallToolRequestSchema, async () => {`,
        `  const startedAtMs = Date.now();`,
        `  const text = readFileSync(process.env.VERAX_CLOCK_STATE + "/decisions.jsonl", "utf8");`,
        `  const rows = text.split("\\n").filter((line) => line !== "").map((line) => JSON.parse(line));`,
        `  const allow = rows.filter((row) => row.claims && row.claims.decision === "allow" && row.claims.subject === "clock.now");`,
        `  const last = allow[allow.length - 1] ?? null;`,
        `  return { content: [{ type: "text", text: JSON.stringify({ startedAtMs, decisionOnDisk: last !== null, decisionTimestampMs: last ? last.claims.timestampMs : null, ref: last ? last.claims.ref : null }) }] };`,
        `});`,
        `await server.connect(new StdioServerTransport());`,
        "",
      ].join("\n"),
    );
    const downstreamFile = join(scratch, "downstream.json");
    writeFileSync(
      downstreamFile,
      `${JSON.stringify({
        prefix: "clock",
        command: process.execPath,
        args: [childPath],
        trust: "same-user",
        env: { VERAX_CLOCK_STATE: "" },
      })}\n`,
    );
    let box: Boot | undefined;
    try {
      const stateDir = mkdtempSync(join(tmpdir(), "verax-attack-r1-clockbody-"));
      init(stateDir);
      writePolicy(stateDir, [
        ...memoryRules,
        {
          id: "clock-now",
          tool: "clock.now",
          requires: ["verax:memory"],
          text: "A clock the operator attached.",
        },
      ]);
      const spec = JSON.parse(readFileSync(downstreamFile, "utf8")) as { env: { VERAX_CLOCK_STATE: string } };
      spec.env.VERAX_CLOCK_STATE = stateDir;
      writeFileSync(downstreamFile, `${JSON.stringify(spec)}\n`);
      const env = envFromFile(stateDir);
      env.VERAX_BIND = "127.0.0.1:0";
      env.VERAX_DOWNSTREAM = downstreamFile;
      const loaded = loadConfig(env);
      if (!loaded.ok) throw new Error(loaded.reason);
      const http = await listen(loaded.value);
      const port = (http.address() as { port: number }).port;
      const mcp = `http://127.0.0.1:${port}/mcp`;
      const token = readFileSync(join(stateDir, "local-issuer", "agent.token"), "utf8").trim();
      box = {
        stateDir,
        base: `http://127.0.0.1:${port}`,
        mcp,
        token,
        audience: env.VERAX_AUDIENCE ?? "",
        close: async () => {
          await new Promise<void>((resolveClose, reject) => {
            http.close((err) => (err ? reject(err) : resolveClose()));
          });
          rmSync(stateDir, { recursive: true, force: true });
        },
      };
      const res = await rpc(mcp, token, "tools/call", { name: "clock.now", arguments: {} });
      const text = textOf(res.json);
      const reported = JSON.parse(text) as {
        startedAtMs: number;
        decisionOnDisk: boolean;
        decisionTimestampMs: number | null;
        ref: string | null;
      };
      assert.equal(reported.decisionOnDisk, true, text);
      assert.equal(typeof reported.decisionTimestampMs, "number", text);
      assert.ok((reported.decisionTimestampMs ?? Number.POSITIVE_INFINITY) <= reported.startedAtMs, text);
      const decision = readDecisions(stateDir).find((row) => row.claims.ref === reported.ref);
      assert.ok(decision, text);
      assert.equal(decision.claims.decision, "allow");
      assert.ok((decision.claims.timestampMs ?? Number.POSITIVE_INFINITY) <= reported.startedAtMs);
      const effect = readEffects(stateDir).find((row) => row.row.ref === reported.ref);
      assert.ok(effect, JSON.stringify(readEffects(stateDir)));
      assert.equal(effect.row.effectClass, "clock.now");
    } finally {
      if (box) await box.close();
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("14 a revoked jti is 401 and writes no decision", async () => {
    const box = await boot();
    try {
      const jti = payloadOf(box.token).jti;
      assert.equal(typeof jti, "string");
      const before = readDecisions(box.stateDir).length;
      appendFileSync(join(box.stateDir, "revoked-jti.jsonl"), `${JSON.stringify({ jti })}\n`, "utf8");
      const res = await rpc(box.mcp, box.token, "tools/list", {});
      assert.equal(res.status, 401, res.text);
      assert.equal(readDecisions(box.stateDir).length, before);
    } finally {
      await box.close();
    }
  });
});
