import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { verifyLedger } from "@verax-ai/proxy";
import { runApprove } from "./approve-cli.ts";
import { listen } from "./server.ts";

const NOT_SHOWN =
  "Not shown here: data masking arrives with a downstream server such as Conarium; statement reconciliation needs a real statement (verax reconcile).";

const AUDIENCE = "http://127.0.0.1/verax-demo";
const KID = "demo";
const TOKEN_TTL_SEC = 5 * 60;
const DENY_HOST = "blocked.test";
const EGRESS_HOST = "example.com";
const SPEND = {
  amountMinor: 100,
  currency: "USD",
  payee: "sample-merchant",
  reference: "demo-1",
} as const;

export type DemoIo = {
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  stdin: NodeJS.ReadableStream;
  isTTY: boolean;
};

type PolicyDoc = {
  version: number;
  default: string;
  egress?: string[];
  rules: Array<Record<string, unknown>>;
};

function redact(text: string, token: string): string {
  if (token === "" || !text.includes(token)) return text;
  return text.split(token).join("[token]");
}

function shippedPolicyPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  let resolved: string | null = null;
  try {
    resolved = join(dirname(fileURLToPath(import.meta.resolve("@verax-ai/proxy/package.json"))), "policy", "default.json");
  } catch {
    resolved = null;
  }
  const candidates = [
    resolved,
    join(here, "..", "..", "proxy", "policy", "default.json"),
    join(here, "..", "..", "@verax-ai", "proxy", "policy", "default.json"),
  ];
  for (const path of candidates) {
    if (path && existsSync(path)) return path;
  }
  throw new Error("demo: shipped policy file not found");
}

/** Shipped default plus message.send egress and a spend rule, written under the temp dir. */
function writeDemoPolicy(stateDir: string): string {
  const shipped = JSON.parse(readFileSync(shippedPolicyPath(), "utf8")) as PolicyDoc;
  const document: PolicyDoc = {
    ...shipped,
    egress: [EGRESS_HOST],
    rules: [
      ...shipped.rules,
      {
        id: "message-send",
        tool: "message.send",
        requires: ["verax:memory"],
        egress: true,
        text: "Queueing a message needs the memory scope and a recipient host on the egress list.",
      },
      {
        id: "spend",
        tool: "spend",
        requires: ["verax:pay"],
        mode: "approve",
        text: "A payment is held for an operator.",
        spend: {
          maxAmountMinor: 5000,
          currency: "USD",
          payees: [SPEND.payee],
          dailyMaxMinor: 10_000,
        },
      },
    ],
  };
  const path = join(stateDir, "policy.json");
  writeFileSync(path, `${JSON.stringify(document, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return path;
}

function closeHttp(server: Server | null): Promise<void> {
  if (!server) return Promise.resolve();
  return new Promise((resolve) => {
    if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    server.close(() => resolve());
  });
}

async function serveJwks(jwk: Record<string, unknown>): Promise<{ server: Server; issuer: string }> {
  const server = createServer((req, res) => {
    if (req.method === "GET" && (req.url === "/.well-known/jwks.json" || req.url === "/.well-known/jwks.json/")) {
      const body = JSON.stringify({ keys: [jwk] });
      res.writeHead(200, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      });
      res.end(body);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    throw new Error("demo: jwks bind failed");
  }
  return { server, issuer: `http://127.0.0.1:${addr.port}` };
}

type DemoPrivateKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

async function mintToken(privateKey: DemoPrivateKey, issuer: string, audience: string): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope: "verax:read verax:memory verax:pay" })
    .setProtectedHeader({ alg: "ES256", kid: KID })
    .setSubject("demo-brain")
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(nowSec)
    .setExpirationTime(nowSec + TOKEN_TTL_SEC)
    .setJti(randomUUID())
    .sign(privateKey);
}

function toolText(result: unknown): string {
  const content = result && typeof result === "object" ? (result as { content?: unknown }).content : undefined;
  if (!Array.isArray(content)) return "";
  return content
    .map((part) =>
      part && typeof part === "object" && "text" in part && typeof (part as { text?: unknown }).text === "string"
        ? (part as { text: string }).text
        : "",
    )
    .filter((s) => s !== "")
    .join("\n");
}

function parseTagged(text: string, kind: "denied" | "deferred"): { code: string; ref: string } | null {
  const m = new RegExp(`^${kind}:([^:]+):(.+)$`).exec(text.trim());
  return m ? { code: m[1]!, ref: m[2]! } : null;
}

async function readAnswer(stdin: NodeJS.ReadableStream): Promise<string> {
  const ended = (stdin as NodeJS.ReadableStream & { readableEnded?: boolean }).readableEnded;
  if (ended) return "";
  return await new Promise((resolve) => {
    const done = (value: string) => {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onErr);
      resolve(value);
    };
    const onData = (chunk: Buffer | string) => {
      done(String(chunk).split(/\r?\n/)[0] ?? "");
    };
    const onEnd = () => done("");
    const onErr = () => done("");
    stdin.once("data", onData);
    stdin.once("end", onEnd);
    stdin.once("error", onErr);
    if (typeof stdin.resume === "function") stdin.resume();
  });
}

export async function runDemo(argv: string[], env: NodeJS.ProcessEnv, io: DemoIo): Promise<number> {
  if (env.NODE_ENV === "production") {
    io.stderr.write("demo refuses NODE_ENV=production\n");
    return 1;
  }

  const keep = argv.includes("--keep");
  let stateDir: string | null = null;
  let jwks: Server | null = null;
  let body: Server | null = null;
  let client: Client | null = null;
  let token = "";
  let cleaned = false;

  const writeOut = (s: string) => {
    io.stdout.write(redact(s, token));
  };
  const writeErr = (s: string) => {
    io.stderr.write(redact(s, token));
  };

  const cleanup = async () => {
    if (cleaned) return;
    cleaned = true;
    process.off("SIGINT", onStop);
    process.off("SIGTERM", onStop);
    if (client) await client.close().catch(() => undefined);
    client = null;
    await closeHttp(body);
    body = null;
    await closeHttp(jwks);
    jwks = null;
    if (stateDir && !keep) {
      try {
        rmSync(stateDir, { recursive: true, force: true });
      } catch {
        // OS temp cleanup
      }
    }
  };

  const onStop = () => {
    void cleanup();
  };
  process.once("SIGINT", onStop);
  process.once("SIGTERM", onStop);

  try {
    stateDir = mkdtempSync(join(tmpdir(), "verax-demo-"));
    const policyFile = writeDemoPolicy(stateDir);

    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(publicKey)), alg: "ES256", use: "sig", kid: KID };
    const jwksBind = await serveJwks(jwk);
    jwks = jwksBind.server;
    const issuer = jwksBind.issuer;
    const jwksUrl = `${issuer}/.well-known/jwks.json`;

    body = await listen({
      issuer,
      jwksUrl,
      audience: AUDIENCE,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile,
      tlsTerminated: false,
    });
    const addr = body.address();
    if (!addr || typeof addr === "string") throw new Error("demo: body bind failed");
    const mcpUrl = `http://127.0.0.1:${addr.port}/mcp`;

    token = await mintToken(privateKey, issuer, AUDIENCE);

    client = new Client({ name: "verax-demo", version: "0.0.0" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(mcpUrl), {
        requestInit: { headers: { authorization: `Bearer ${token}` } },
      }),
    );

    writeOut("verax demo\n");
    writeOut("\n");

    const put = await client.callTool({
      name: "memory.put",
      arguments: {
        id: "demo-note",
        body: { text: "loopback demo" },
        source: { kind: "demo" },
        validUntilMs: Date.now() + 60 * 60 * 1000,
      },
    });
    if (put.isError) throw new Error(`demo: memory.put ${toolText(put)}`);
    const got = await client.callTool({ name: "memory.get", arguments: { id: "demo-note" } });
    if (got.isError) throw new Error(`demo: memory.get ${toolText(got)}`);
    writeOut("memory.put / memory.get\n");
    writeOut("  allowed; two signed records\n");
    writeOut("\n");

    const sent = await client.callTool({
      name: "message.send",
      arguments: { to: `ops@${DENY_HOST}`, text: "demo" },
    });
    const denied = parseTagged(toolText(sent), "denied");
    if (!denied) throw new Error(`demo: message.send ${toolText(sent)}`);
    writeOut(`message.send -> ops@${DENY_HOST}\n`);
    writeOut(`  refused ${denied.code} (signed)\n`);
    writeOut(`  ref ${denied.ref}\n`);
    writeOut("\n");

    const spent = await client.callTool({
      name: "spend",
      arguments: { ...SPEND },
    });
    const held = parseTagged(toolText(spent), "deferred");
    if (!held) throw new Error(`demo: spend ${toolText(spent)}`);
    writeOut(`spend ${SPEND.amountMinor} minor ${SPEND.currency} ${SPEND.payee}\n`);
    writeOut("  held\n");

    let approved = false;
    if (io.isTTY) {
      writeOut("Approve this payment as the operator on this machine? [y/N]\n");
      const answer = await readAnswer(io.stdin);
      if (answer.trim().toLowerCase() === "y") {
        const code = await runApprove(["approve", stateDir, held.ref], (s) => writeErr(s), () => undefined);
        if (code !== 0) throw new Error("demo: approve failed");
        approved = true;
      }
    }
    if (approved) {
      writeOut("  approved; operator id bound on the record\n");
    } else if (io.isTTY) {
      writeOut("  left held\n");
    } else {
      writeOut("  no terminal to ask, so it stays held (run this in a terminal to be asked)\n");
    }
    writeOut("\n");

    const explained = await client.callTool({
      name: "audit.explain",
      arguments: { ref: denied.ref },
    });
    if (explained.isError) throw new Error(`demo: audit.explain ${toolText(explained)}`);
    let findingCode = "none";
    let trust = "unread";
    try {
      const parsed = JSON.parse(toolText(explained)) as {
        finding?: { code?: unknown };
        trustRoot?: { source?: unknown };
      };
      if (typeof parsed.finding?.code === "string") findingCode = parsed.finding.code;
      if (typeof parsed.trustRoot?.source === "string") trust = parsed.trustRoot.source;
    } catch {
      findingCode = "unparsed";
    }
    writeOut("audit.explain of the refuse\n");
    writeOut(`  finding ${findingCode}\n`);
    writeOut(`  trust-root ${trust}\n`);
    if (findingCode === "none" && trust !== "unread") {
      writeOut("  chain and signatures read back\n");
    } else {
      writeOut("  the read-back did not come out clean; see the finding above\n");
    }
    writeOut("\n");

    await client.close().catch(() => undefined);
    client = null;
    await closeHttp(body);
    body = null;
    await closeHttp(jwks);
    jwks = null;

    const counted = await verifyLedger(stateDir);
    writeOut(`records  ${counted.decisions}\n`);
    writeOut(`effects  ${counted.effects}\n`);
    if (keep) {
      writeOut(`ledger   ${stateDir}\n`);
      writeOut(`verax verify ${stateDir}\n`);
    } else {
      writeOut("ledger   removed on exit (run with --keep to keep it and check it with verax verify)\n");
    }
    writeOut("\n");
    writeOut(`${NOT_SHOWN}\n`);

    await cleanup();
    return 0;
  } catch (err) {
    const detail = err instanceof Error ? err.message : "fault";
    writeErr(`demo: ${detail}\n`);
    await cleanup();
    return 1;
  }
}
