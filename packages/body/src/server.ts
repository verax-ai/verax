import { AsyncLocalStorage } from "node:async_hooks";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { isLoopbackHost, type BodyConfig } from "./config.ts";
import {
  approvalsLogFor,
  approvePending,
  createApprovalBudgetGuard,
  explain,
  LedgerDenyUnrecorded,
  loadApprovalsFromDir,
  type LedgerCounts,
} from "@verax-ai/proxy";
import { createVerifier, readBearer, resourceMetadataUrl, wwwAuthenticate } from "./auth.ts";
import { bumpMetric, bumpUnauthenticated } from "./metrics.ts";
import { isRevokedJti } from "./revoke.ts";
import { loadOrCreateSigners } from "./keys.ts";
import { matchingInputs } from "./inputs-read.ts";
import { readPolicySnapshots } from "./policy-store.ts";
import { readHeartbeat, readWitnessPulse } from "./health-extras.ts";
import { agentsWindow } from "./agents.ts";
import { inventoryHealth, readInventoryFile } from "./inventory-file.ts";
import { createBodyServices, TOOL_NAMES } from "./wiring.ts";
import {
  openDownstream,
  parseDownstreamDocument,
  type DownstreamSession,
  type DownstreamSpec,
  type DownstreamTool,
} from "./downstream.ts";

// What a brain reads before it calls. Each description says what the tool is
// for, what it does and does not do, what the gate may answer, and what comes
// back; each parameter says its format and its bounds. The answers named here
// are the proxy's: `denied:<reason>:<ref>`, `deferred:approval-required:<ref>`
// and `allowed:<ref>` (packages/proxy/src/proxy.ts).
const ID_FORMAT =
  "1 to 128 characters of letters, digits, '.', '_' or '-', starting with a letter or digit; case-sensitive.";
const REF_FORMAT = "1 to 64 characters of letters, digits, '.', '_' or '-', starting with a letter or digit.";
const REF_PARAM = {
  type: "string",
  description:
    "Optional reference you choose for this call, " +
    REF_FORMAT +
    " Resend the same call with the same _ref after an operator approved it to receive allowed:<ref>; " +
    "a _ref reused for a different call is refused with denied:ref-reuse.",
};

export const TOOL_META = [
  {
    name: "memory.get",
    description:
      "Reads one memory item this tenant stored earlier with memory.put, by its id. " +
      "Use it to recall a fact, a setting or a note before acting on it; nothing is written. " +
      "Like every call it passes the policy gate and leaves a signed decision record; an id that belongs to another tenant is answered with a signed deny. " +
      "Returns the stored item as JSON: {id, body, source, validFromMs, validUntilMs, versionHash}. " +
      "Outside the validity window the body is withheld: {stale: true, id, validUntilMs} after it, {notYetValid: true, id, validFromMs} before it. " +
      'An unknown id answers {error: "not-found", id}.',
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        id: { type: "string", description: "The id given to memory.put: " + ID_FORMAT },
      },
      required: ["id"],
    },
  },
  {
    name: "memory.put",
    description:
      "Writes one memory item for this tenant, or replaces the item with the same id, in the body's state directory on this machine. " +
      "Use it to keep a fact for a later memory.get together with where it came from and how long it holds, so a stale fact is not served later. " +
      "The call passes the policy gate and is recorded; the record carries the item's versionHash, a SHA-256 over id, body and validity window. " +
      "Returns {ok: true, id, versionHash}. " +
      'A missing source answers {error: "source-required"}, a missing validUntilMs {error: "validUntilMs-required"}, a malformed id {error: "id-invalid"}.',
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        id: {
          type: "string",
          description:
            "Identifier to store under and read back with memory.get: " +
            ID_FORMAT +
            " An existing item with this id is replaced.",
        },
        body: {
          description:
            "The value to keep, as any JSON: object, array, string, number or boolean. Stored as given and returned as given by memory.get.",
        },
        source: {
          type: "object",
          description:
            'Where the value came from, as a JSON object of your choosing, for example {"kind": "document", "ref": "invoice-2026-09.pdf"}. Required; stored with the item so a later reader can weigh it.',
        },
        validFromMs: {
          type: "number",
          description:
            "Optional. Unix time in milliseconds from which the item may be served; before it memory.get answers notYetValid. Omit to serve it at once.",
        },
        validUntilMs: {
          type: "number",
          description:
            "Required. Unix time in milliseconds after which memory.get answers stale and withholds the body. Pick the moment the fact should no longer be trusted.",
        },
      },
      required: ["id", "body", "source", "validUntilMs"],
    },
  },
  {
    name: "audit.explain",
    description:
      "Reads one decision back from the signed ledger by its ref and explains it. " +
      "Use it to check what the body decided about an earlier call and whether the recorded effect matched, before repeating a call or reporting on it; read-only, and the lookup itself is recorded too. " +
      "Returns JSON with record (the signed decision's claims: tool, verdict, policy hash, timestamps), effect (the reconciled effect row), finding (match, mismatch or missing), witnessClass, guarantee, warnings, trustRoot (which key verified the signatures), and for a held call pair with its defer and resolution records. " +
      "A ref that does not exist, or belongs to another tenant, is answered with the same signed deny, so neither case reveals the other.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        ref: {
          type: "string",
          description:
            "The decision reference: the ref returned by an earlier call, also the tail of a denied:… or deferred:… answer; " +
            REF_FORMAT,
        },
      },
      required: ["ref"],
    },
  },
  {
    name: "message.read",
    description:
      "Reads this tenant's inbox, the messages placed for it in the body's state directory on this machine, and returns them as a JSON array in arrival order, oldest first. " +
      "Use it to see what has arrived before deciding what to answer. " +
      "Takes no arguments; read-only; the call is recorded like every other. An empty or absent inbox answers [].",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
  {
    name: "message.send",
    description:
      "Queues one message in this tenant's outbox on this machine for the delivery step the operator runs; this call opens no network connection and nothing leaves the body from it. " +
      "Use it to hand off a message, not to deliver one. " +
      "Like every call it passes the policy gate and leaves a signed decision record. " +
      "The gate reads the host after the last '@' in to and allows it only when it is on the policy's egress allow-list; otherwise the call is refused with denied:egress-blocked, or denied:egress-host-missing when no host can be read. " +
      "A policy rule in approve mode holds the call for an operator instead and answers deferred:approval-required:<ref>. " +
      "Returns {queued: true, ref}, where ref is the decision reference for audit.explain.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        to: {
          type: "string",
          description:
            "Recipient address with a host after the last '@', for example ops@example.com. The host, lower-cased, is matched against the policy's egress list.",
        },
        text: { type: "string", description: "The message body as plain text. Stored as given in the outbox row." },
        _ref: REF_PARAM,
      },
      required: ["to", "text"],
    },
  },
  {
    name: "spend",
    description:
      "Asks the body to authorize a payment and records the decision; the body never moves money, so authorized: true is a signed permission for a later payment step, not a transfer. " +
      "Use it before any payment so that amount, currency, payee and reference are checked against the policy: the one currency the policy names, a cap per call, a payee list and a daily limit. " +
      "A call outside those bounds is refused with a signed deny naming the bound: denied:spend-cap, denied:spend-payee, denied:spend-currency or denied:spend-daily. " +
      "A call within them is held for an operator on this machine and answers deferred:approval-required:<ref>; once that ref is approved (verax approve, or the panel), resending the same call with the same _ref answers allowed:<ref>, and the authorization is recorded as {authorized: true, ref, amountMinor, currency, payee, reference}. " +
      "Without a spend rule in the policy every call answers denied:spend-not-wired.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        amountMinor: {
          type: "integer",
          description:
            "Amount in the currency's minor unit as a positive integer: cents, kuruş or pence, so 1250 means 12.50. Compared against the policy's cap per call and daily limit.",
        },
        currency: {
          type: "string",
          description: "ISO 4217 code in upper case, for example USD, EUR or TRY. Must equal the currency the policy's spend rule names.",
        },
        payee: {
          type: "string",
          description: "Who is to be paid, spelled exactly as the policy's payee list spells it (a merchant or account name). A payee off the list is refused.",
        },
        reference: {
          type: "string",
          description:
            "Your own reference for this payment, such as an invoice or order id. Recorded with the authorization and used by verax reconcile to match the card statement.",
        },
        _ref: REF_PARAM,
      },
      required: ["amountMinor", "currency", "payee", "reference"],
    },
  },
];

const MAX_BODY_BYTES = 1024 * 1024;
// Node's default requestTimeout is 300s. A stalled body would otherwise stay
// authorised until that default. Headers are bounded tighter than the body.
const REQUEST_TIMEOUT_MS = 30_000;
const HEADERS_TIMEOUT_MS = 20_000;
// Unbounded GET /api/ledger stringified ~690 MB at 200k rows and threw Invalid string length (HTTP 500).
const DEFAULT_LEDGER_LIMIT = 1000;
const MAX_LEDGER_LIMIT = 5000;
const responseSlot = new AsyncLocalStorage<ServerResponse>();

/** `malformed` falls through so `Host: [` stays the existing bad-request. */
export function loopbackHostDecision(hostHeader: string | undefined, bindPort: number): "allow" | "deny" | "malformed" {
  if (hostHeader === undefined || hostHeader.trim() === "") return "deny";
  const raw = hostHeader.trim();
  if (raw.startsWith("[") && !raw.includes("]")) return "malformed";
  let name = raw;
  let port: number | undefined;
  if (raw.startsWith("[")) {
    const end = raw.indexOf("]");
    name = raw.slice(1, end);
    const rest = raw.slice(end + 1);
    if (rest === "") port = undefined;
    else if (/^:[0-9]+$/.test(rest)) port = Number(rest.slice(1));
    else return "deny";
  } else {
    const colon = raw.lastIndexOf(":");
    if (colon > 0 && /^[0-9]+$/.test(raw.slice(colon + 1))) {
      name = raw.slice(0, colon);
      port = Number(raw.slice(colon + 1));
    }
  }
  const lowered = name.toLowerCase();
  if (lowered !== "127.0.0.1" && lowered !== "localhost" && lowered !== "::1") return "deny";
  if (port === undefined) return bindPort === 80 ? "allow" : "deny";
  return port === bindPort ? "allow" : "deny";
}

function contentLengthOverLimit(req: IncomingMessage): boolean {
  const raw = req.headers["content-length"];
  if (raw === undefined) return false;
  const n = Number(Array.isArray(raw) ? raw[0] : raw);
  return Number.isFinite(n) && n > MAX_BODY_BYTES;
}

async function readJsonBody(
  req: IncomingMessage,
  max: number,
): Promise<{ ok: true; value: unknown } | { ok: false; tooLarge: true } | { ok: false; bad: true }> {
  if (contentLengthOverLimit(req)) return { ok: false, tooLarge: true };
  const chunks: Buffer[] = [];
  let seen = 0;
  try {
    for await (const chunk of req) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      seen += buf.length;
      if (seen > max) {
        return { ok: false, tooLarge: true };
      }
      chunks.push(buf);
    }
  } catch {
    return { ok: false, bad: true };
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text === "") return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, bad: true };
  }
}

/**
 * Second look at a bearer that already verified. The first look runs before
 * the body is read; this one runs after the body and before dispatch or
 * approval. `exp` is seconds since the epoch. A passed `exp` is dead even
 * inside the verifier's clock tolerance: that tolerance applied at the door,
 * and the body has since arrived. A missing `exp` is dead too.
 */
export function bearerStillLive(payload: { jti?: unknown; exp?: unknown }, stateDir: string): boolean {
  const jti = typeof payload.jti === "string" ? payload.jti : "";
  if (jti === "" || isRevokedJti(stateDir, jti)) return false;
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return false;
  return payload.exp * 1000 > Date.now();
}

function isProtectedResourcePath(pathname: string, audience: string): boolean {
  const want = new URL(resourceMetadataUrl(audience)).pathname;
  return pathname === want || pathname === "/.well-known/oauth-protected-resource";
}

function send(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    "x-content-type-options": "nosniff",
    ...headers,
  });
  res.end(text);
}

/**
 * Republishes a child's own `tools/list` entry under its prefixed name. The
 * description is the child's; the sentence added here says what changes by
 * going through the body, because the answers a caller gets back
 * (`denied:…`, `deferred:…`) are the gate's, not the child's.
 */
function downstreamMeta(tool: DownstreamTool): {
  name: string;
  description: string;
  inputSchema: unknown;
} {
  const own = typeof tool.description === "string" && tool.description !== "" ? `${tool.description} ` : "";
  return {
    name: tool.name,
    description:
      own +
      "Forwarded by this body to the downstream server that published it: the call passes the same policy gate " +
      "and leaves the same signed decision under this name, so it may be answered with denied:<reason>:<ref> or " +
      "deferred:approval-required:<ref> before the downstream server ever sees it.",
    inputSchema: tool.inputSchema ?? { type: "object" },
  };
}

async function closeAll(sessions: readonly DownstreamSession[]): Promise<void> {
  for (const session of sessions) {
    await session.close().catch(() => undefined);
  }
}

/**
 * What an operator may see about the attached children: the prefix they call
 * by, how the body reaches them, and the names it will accept.
 *
 * Deliberately not the address. A child's URL can carry its token in the path
 * — the live Conarium's does — and a command line names a path on this host.
 * Neither is needed to answer "what is standing behind this gate", so neither
 * is published. The `tests/downstream-visible` guard asserts their absence.
 */
function downstreamPublic(
  sessions: readonly DownstreamSession[],
  specs: readonly DownstreamSpec[],
): { prefix: string; transport: "stdio" | "http"; tools: string[] }[] {
  return sessions.map((session) => {
    const spec = specs.find((s) => s.prefix === session.prefix);
    return {
      prefix: session.prefix,
      transport: spec?.url !== undefined ? ("http" as const) : ("stdio" as const),
      tools: session.tools.map((t) => t.name),
    };
  });
}

/**
 * Opens every child the document names. One child that refuses to attach
 * closes the ones already open and throws: a half-attached body would serve a
 * tool list its operator never wrote.
 */
async function attachDownstream(
  file: string | null,
): Promise<{ sessions: DownstreamSession[]; specs: DownstreamSpec[] }> {
  if (file === null || file.trim() === "") return { sessions: [], specs: [] };
  const specs = parseDownstreamDocument(readFileSync(file, "utf8"));
  const sessions: DownstreamSession[] = [];
  for (const spec of specs) {
    try {
      sessions.push(await openDownstream(spec));
    } catch (err) {
      await closeAll(sessions);
      const detail = err instanceof Error ? err.message : "attach-failed";
      throw new Error(`downstream-attach-failed:${spec.prefix}:${detail}`);
    }
  }
  return { sessions, specs };
}

export async function listen(config: BodyConfig): Promise<Server> {
  const signers = loadOrCreateSigners(config.stateDir);
  // The children are attached before the door opens. A named document the body
  // cannot honour stops the start: a body that serves six tools while its
  // operator wrote seven is answering for a gate it does not have.
  const { sessions, specs: downstreamSpecs } = await attachDownstream(config.downstreamFile ?? null);
  const extraTools = sessions.flatMap((session) => session.tools);
  let services: ReturnType<typeof createBodyServices>;
  try {
    services = createBodyServices({
      stateDir: config.stateDir,
      policyFile: config.policyFile,
      recordSigner: signers.recordSigner,
      effectSigner: signers.effectSigner,
      ...(extraTools.length > 0 ? { extraTools } : {}),
    });
  } catch (err) {
    await closeAll(sessions);
    throw err;
  }
  const toolMeta = [...TOOL_META, ...extraTools.map(downstreamMeta)];
  const verify = createVerifier(config.jwksUrl, config.issuer, config.audience, config.jwksFile, config.jwksPin);

  const attachHandlers = (mcp: McpServer) => {
    mcp.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: toolMeta }));
    mcp.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const auth = extra?.authInfo;
      const scopes = new Set(auth?.scopes ?? []);
      const bag = (auth?.extra ?? {}) as Record<string, unknown>;
      const brain = typeof bag.sub === "string" ? bag.sub : (auth?.clientId ?? "unknown");
      try {
        return await services.proxy.call(
          { name: request.params.name, arguments: (request.params.arguments ?? {}) as Record<string, unknown> },
          {
            brain,
            scopes,
            ...(typeof bag.iss === "string" ? { iss: bag.iss } : {}),
            ...(typeof bag.tenant === "string" ? { tenant: bag.tenant } : {}),
            ...(typeof bag.org === "string" ? { org: bag.org } : {}),
          },
        );
      } catch (err) {
        if (err instanceof LedgerDenyUnrecorded) {
          await bumpMetric(config.stateDir, "disk_deny_unrecorded");
          const res = responseSlot.getStore();
          if (res && !res.headersSent) {
            send(res, 507, { error: "insufficient-storage" });
          }
          throw err;
        }
        throw err;
      }
    });
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      if (isLoopbackHost(config.bindHost)) {
        const hostHeader = Array.isArray(req.headers.host) ? req.headers.host[0] : req.headers.host;
        const listenPort = (server.address() as AddressInfo).port;
        const hostDecision = loopbackHostDecision(hostHeader, listenPort);
        if (hostDecision === "deny") {
          send(res, 400, { error: "host-not-allowed" });
          req.resume();
          return;
        }
      }
      if (req.headers.origin !== undefined) {
        const origin = Array.isArray(req.headers.origin) ? (req.headers.origin[0] ?? "") : req.headers.origin;
        const allowed = config.allowedOrigins ?? [];
        if (!allowed.includes(origin)) {
          send(res, 403, { error: "origin-not-allowed" });
          req.resume();
          return;
        }
      }
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
      if (req.method === "POST" && contentLengthOverLimit(req)) {
        send(res, 413, { error: "payload-too-large" });
        req.resume();
        return;
      }
      if (req.method === "GET" && url.pathname === "/healthz") {
      // Local mode reads VERAX_JWKS_FILE. Any process that can read that key
      // file can mint verax:audit, so counts are not a door here: liveness only.
      if (config.jwksFile) {
        send(res, 200, { ok: true });
        return;
      }
      const token = readBearer(req.headers.authorization);
      let canRead = false;
      if (token) {
        try {
          const verified = await verify(token);
          // Counts name how often and when the body worked. `verax:read` is a
          // brain scope, so it cannot be the key here; the operator session
          // carries `verax:audit`. A revoked or jti-less token is an
          // unauthenticated probe: liveness only.
          const jti = typeof verified.payload.jti === "string" ? verified.payload.jti : "";
          canRead =
            jti !== "" &&
            !isRevokedJti(config.stateDir, jti) &&
            verified.principal.scopes.has("verax:audit");
        } catch {
          canRead = false;
        }
      }
      if (!canRead) {
        send(res, 200, { ok: true });
        return;
      }
      // The ledger counts its own lines as it writes them; asking it is free.
      // Reading both files back to count them was one second per call on a
      // 100k-decision ledger, five times a minute for as long as a panel was open.
      // When the active piece cannot be read back, the fallback below counts
      // the merged files; it cannot tell which rows sit in the active piece,
      // so the piece fields stay out of that degraded answer.
      let counted: LedgerCounts | Omit<LedgerCounts, "activeDecisions" | "pieces"> | null =
        services.ledger.counts();
      if (!counted) {
        const decisions = await services.ledger.decisions();
        const effects = await services.ledger.effects();
        const last = decisions[decisions.length - 1];
        counted = {
          decisions: decisions.length,
          effects: effects.length,
          lastDecisionMs: last ? last.claims.timestampMs : null,
        };
      }
      send(res, 200, {
        ok: true,
        ...counted,
        lock: services.ledger.lockStatus(),
        heartbeat: readHeartbeat(config.stateDir),
        witness: readWitnessPulse(config.stateDir),
        inventory: inventoryHealth(readInventoryFile(config.inventoryFile)),
        // Always an array, empty when nothing is attached: a missing field
        // would read as "this body is too old to tell you".
        downstream: downstreamPublic(sessions, downstreamSpecs),
      });
      return;
    }
    if (req.method === "GET" && isProtectedResourcePath(url.pathname, config.audience)) {
      send(res, 200, {
        resource: config.audience,
        authorization_servers: [config.issuer],
        bearer_methods_supported: ["header"],
        scopes_supported: [
          "verax:read",
          "verax:memory",
          "verax:act",
          "verax:pay",
          "verax:audit",
          "verax:approve",
        ],
      });
      return;
    }
    const apiLedger = req.method === "GET" && url.pathname === "/api/ledger";
    const apiInventory = url.pathname === "/api/inventory";
    const contest = req.method === "POST" && url.pathname.startsWith("/api/contest/");
    const apiApprove = req.method === "POST" && url.pathname === "/api/approve";
    const apiAgents = req.method === "GET" && url.pathname === "/api/agents";
    if (url.pathname !== "/mcp" && !apiLedger && !apiInventory && !contest && !apiApprove && !apiAgents) {
      send(res, 404, { error: "not-found" });
      return;
    }
    const token = readBearer(req.headers.authorization);
    if (!token) {
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
      return;
    }
    let verified: Awaited<ReturnType<typeof verify>>;
    try {
      verified = await verify(token);
    } catch {
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
      return;
    }
    const jti = typeof verified.payload.jti === "string" ? verified.payload.jti : "";
    if (jti === "" || isRevokedJti(config.stateDir, jti)) {
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
      return;
    }
    const refuseStaleBearer = async (): Promise<boolean> => {
      if (bearerStillLive(verified.payload, config.stateDir)) return false;
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
      return true;
    };
    // Local mode: any process that can read the key file can mint
    // verax:approve or verax:audit, so those scopes are not honoured at all.
    // Nothing is written; the refusal is the whole answer.
    if (
      config.jwksFile &&
      (verified.principal.scopes.has("verax:approve") || verified.principal.scopes.has("verax:audit"))
    ) {
      send(res, 403, { error: "local-mode-operator-scope" });
      return;
    }
    try {
      if (apiApprove) {
        // Reading the ledger is not approving from it. The audit scope opens
        // every door above; this one signs a new decision and lets money go,
        // so it has a scope of its own.
        if (!verified.principal.scopes.has("verax:approve")) {
          send(res, 403, { error: "scope-missing" });
          return;
        }
        const parsed = await readJsonBody(req, MAX_BODY_BYTES);
        if (await refuseStaleBearer()) return;
        if (!parsed.ok) {
          send(res, 400, { error: "bad-body" });
          return;
        }
        const asked = (parsed.value ?? {}) as { ref?: unknown; requestHash?: unknown };
        const ref = typeof asked.ref === "string" ? asked.ref : "";
        const sawHash = typeof asked.requestHash === "string" ? asked.requestHash : "";
        if (ref === "" || sawHash === "") {
          send(res, 400, { error: "ref-and-requestHash-required" });
          return;
        }
        const waiting = loadApprovalsFromDir(config.stateDir).find((row) => row.ref === ref);
        if (!waiting) {
          send(res, 404, { error: "unknown-ref" });
          return;
        }
        // The list on a phone can be ten minutes old. An approval names the
        // request the operator was looking at, and if that is not what is
        // waiting any more, nothing is approved: "I approved what I saw" is
        // only true when something checks it.
        if (waiting.requestHash !== sawHash) {
          send(res, 409, { error: "stale", requestHash: waiting.requestHash });
          return;
        }
        const defer = services.ledger.lookupByRef(ref);
        if (!defer || defer.decision !== "defer") {
          send(res, 404, { error: "unknown-ref" });
          return;
        }
        // Who approved, on the record. The CLI writes the machine's login name,
        // which says nothing about the person holding the phone; the session's
        // own subject does.
        const approver = verified.principal.brain;
        const approvals = approvalsLogFor(services.ledger);
        const outcome = await approvePending({
          ledger: services.ledger,
          recordSigner: loadOrCreateSigners(config.stateDir).recordSigner,
          now: () => Date.now(),
          nonce: () => crypto.randomUUID(),
          ref,
          approverId: approver,
          via: "http",
          policyHash: defer.policyHash,
          approvals,
          budgetGuard: createApprovalBudgetGuard({
            policy: services.policy,
            approvals,
            now: () => Date.now(),
          }),
        });
        if (!outcome.ok) {
          const code = outcome.reason === "unknown-ref" || outcome.reason === "snapshot-missing" ? 404 : 409;
          send(res, code, {
            error: outcome.reason,
            ...(outcome.allowRef ? { allowRef: outcome.allowRef } : {}),
          });
          return;
        }
        send(res, 200, { allowRef: outcome.allowRef, approver });
        return;
      }
      if (apiLedger || apiInventory || contest || apiAgents) {
        if (await refuseStaleBearer()) return;
        // The audit doors hand out the whole ledger: every tenant's decisions, the
        // inputs documents that name their principals, and the approval snapshots
        // that carry spend arguments. `verax:read` is a brain scope, so it cannot be
        // the key here; the operator session carries `verax:audit`.
        if (!verified.principal.scopes.has("verax:audit")) {
          send(res, 403, { error: "scope-missing" });
          return;
        }
        if (apiInventory) {
          if (req.method !== "GET") {
            send(res, 405, { error: "method-not-allowed" });
            return;
          }
          send(res, 200, readInventoryFile(config.inventoryFile));
          return;
        }
        if (apiAgents) {
          // The last day unless the caller names a window; the roster's
          // agents are on the list whether or not they acted in it.
          const now = Date.now();
          const fromRaw = url.searchParams.get("from");
          const toRaw = url.searchParams.get("to");
          const from = fromRaw === null ? now - 86_400_000 : Number(fromRaw);
          const to = toRaw === null ? now : Number(toRaw);
          if (!Number.isFinite(from) || !Number.isFinite(to)) {
            send(res, 400, { error: "bad-window" });
            return;
          }
          send(
            res,
            200,
            await agentsWindow({
              ledger: services.ledger,
              stateDir: config.stateDir,
              inventoryFile: config.inventoryFile,
              fromMs: from,
              toMs: to,
            }),
          );
          return;
        }
        if (apiLedger) {
          const from = Number(url.searchParams.get("from") ?? "0");
          const to = Number(url.searchParams.get("to") ?? String(Number.MAX_SAFE_INTEGER));
          const limitRaw = url.searchParams.get("limit");
          const parsedLimit = limitRaw === null ? undefined : Number(limitRaw);
          if (
            !Number.isFinite(from) ||
            !Number.isFinite(to) ||
            (parsedLimit !== undefined && (!Number.isFinite(parsedLimit) || parsedLimit < 0))
          ) {
            send(res, 400, { error: "bad-window" });
            return;
          }
          const limit =
            parsedLimit === undefined ? DEFAULT_LEDGER_LIMIT : Math.min(MAX_LEDGER_LIMIT, Math.floor(parsedLimit));
          // The window is read from the end of the files, so a day costs a
          // day whatever the ledger's age. With a limit, the newest rows of
          // the window come back and `more` says the rest is there to ask for.
          const { rows: decisions, more, piecesTouched } = await services.ledger.decisionsWindow(from, to, limit);
          // Effects belong to the decisions returned. When the limit cut the
          // window, the oldest decision returned is where their window starts.
          const effectsFrom = more && decisions.length > 0 ? decisions[0]!.claims.timestampMs : from;
          const effects = await services.ledger.effectsWindow(effectsFrom, to);
          const hashes = [...new Set(decisions.map((d) => d.claims.policyHash))];
          send(res, 200, {
            decisions,
            effects,
            policy: { hash: services.policyHash, document: services.policyDocument },
            policies: readPolicySnapshots(config.stateDir, hashes),
            inputs: await matchingInputs(config.stateDir, decisions),
            approvals: loadApprovalsFromDir(config.stateDir),
            more,
            piecesTouched,
            limit,
          });
          return;
        }
        const ref = decodeURIComponent(url.pathname.slice("/api/contest/".length));
        const result = await explain(services.ledger, ref, await services.explainOpts());
        send(res, 200, { ...result, reAuditedAt: Date.now() });
        return;
      }
      if (req.method === "GET") {
        // Stateless: no standalone SSE. The SDK client treats 405 as "no GET stream".
        res.writeHead(405, {
          allow: "POST, DELETE",
          "content-type": "application/json",
          "x-content-type-options": "nosniff",
        });
        res.end(JSON.stringify({ error: "method-not-allowed" }));
        return;
      }
      const mcp = new McpServer({ name: "verax-body", version: "0.0.0" }, { capabilities: { tools: {} } });
      attachHandlers(mcp);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await mcp.connect(transport);
      const parsed = req.method === "POST" ? await readJsonBody(req, MAX_BODY_BYTES) : { ok: true as const, value: undefined };
      if (await refuseStaleBearer()) return;
      if (parsed.ok === false && "tooLarge" in parsed) {
        send(res, 413, { error: "payload-too-large" });
        req.destroy();
        return;
      }
      if (parsed.ok === false) {
        send(res, 400, { error: "bad-request" });
        return;
      }
      try {
        await responseSlot.run(res, async () => {
          try {
            await transport.handleRequest(
              Object.assign(req, {
                auth: {
                  token,
                  clientId: verified.principal.brain,
                  scopes: [...verified.principal.scopes],
                  extra: {
                    sub: verified.principal.brain,
                    ...(verified.principal.iss ? { iss: verified.principal.iss } : {}),
                    ...(verified.principal.tenant ? { tenant: verified.principal.tenant } : {}),
                    ...(verified.principal.org ? { org: verified.principal.org } : {}),
                  },
                },
              }),
              res,
              parsed.value,
            );
          } catch (err) {
            if (res.headersSent && res.statusCode === 507) return;
            throw err;
          }
        });
      } catch (err) {
        if (err instanceof LedgerDenyUnrecorded) {
          if (!res.headersSent) {
            await bumpMetric(config.stateDir, "disk_deny_unrecorded");
            send(res, 507, { error: "insufficient-storage" });
          }
          return;
        }
        if (res.headersSent && res.statusCode === 507) {
          return;
        }
        const detail = err instanceof Error ? err.message : "fault";
        process.stderr.write(`verax-transport: ${detail}\n`);
        if (!res.headersSent) {
            send(res, 500, { error: "transport" });
        }
      } finally {
        await transport.close();
      }
    } catch (err) {
      if (res.headersSent) return;
      const msg = err instanceof Error ? err.message : "";
      if (msg.startsWith("explain-unknown-ref:")) {
        send(res, 404, { error: "unknown-ref" });
        return;
      }
      if (err instanceof URIError) {
        send(res, 400, { error: "bad-request" });
        return;
      }
      process.stderr.write(`verax-handler: ${msg || "fault"}\n`);
      send(res, 500, { error: "fault" });
    }
    } catch (err) {
      if (res.headersSent) return;
      if (err instanceof TypeError) {
        send(res, 400, { error: "bad-request" });
        return;
      }
      process.stderr.write(`verax-handler: ${err instanceof Error ? err.message : "fault"}\n`);
      send(res, 500, { error: "fault" });
    } finally {
      // Swallow so a bad Host cannot reject the request listener.
    }
  });

  server.requestTimeout = REQUEST_TIMEOUT_MS;
  server.headersTimeout = HEADERS_TIMEOUT_MS;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.bindPort, config.bindHost, () => resolve());
  });
  server.on("close", () => {
    services.ledger.close();
    void closeAll(sessions);
  });
  return server;
}

export { TOOL_NAMES };
