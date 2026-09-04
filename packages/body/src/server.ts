import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { BodyConfig } from "./config.ts";
import { explain } from "@verax-ai/proxy";
import { createVerifier, readBearer, resourceMetadataUrl, wwwAuthenticate } from "./auth.ts";
import { bumpUnauthenticated } from "./metrics.ts";
import { loadOrCreateSigners } from "./keys.ts";
import { createBodyServices, TOOL_NAMES } from "./wiring.ts";

const TOOL_META = [
  {
    name: "memory.get",
    description: "Read a memory item. Stale items return { stale: true } without the body.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "memory.put",
    description: "Write a memory item. source and validUntilMs are required.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        id: { type: "string" },
        body: {},
        source: { type: "object" },
        validFromMs: { type: "number" },
        validUntilMs: { type: "number" },
      },
      required: ["id", "body", "source", "validUntilMs"],
    },
  },
  {
    name: "audit.explain",
    description: "Explain a decision ref against the ledger.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { ref: { type: "string" } },
      required: ["ref"],
    },
  },
  {
    name: "message.read",
    description: "Read the local inbox fixture as JSON.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
  },
];

const MAX_BODY_BYTES = 1024 * 1024;

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

export async function listen(config: BodyConfig): Promise<Server> {
  const signers = loadOrCreateSigners(config.stateDir);
  const services = createBodyServices({
    stateDir: config.stateDir,
    policyFile: config.policyFile,
    recordSigner: signers.recordSigner,
    effectSigner: signers.effectSigner,
  });
  const verify = createVerifier(config.jwksUrl, config.issuer, config.audience);

  const attachHandlers = (mcp: McpServer) => {
    mcp.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOL_META }));
    mcp.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const auth = extra?.authInfo;
      const scopes = new Set(auth?.scopes ?? []);
      const brain = typeof auth?.extra?.sub === "string" ? auth.extra.sub : (auth?.clientId ?? "unknown");
      return services.proxy.call(
        { name: request.params.name, arguments: (request.params.arguments ?? {}) as Record<string, unknown> },
        { brain, scopes },
      );
    });
  };

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
      if (req.method === "POST" && contentLengthOverLimit(req)) {
        send(res, 413, { error: "payload-too-large" });
        req.resume();
        return;
      }
      if (req.method === "GET" && url.pathname === "/healthz") {
      send(res, 200, { ok: true });
      return;
    }
    if (req.method === "GET" && isProtectedResourcePath(url.pathname, config.audience)) {
      send(res, 200, {
        resource: config.audience,
        authorization_servers: [config.issuer],
        bearer_methods_supported: ["header"],
        scopes_supported: ["verax:read", "verax:memory", "verax:act", "verax:pay"],
      });
      return;
    }
    const apiLedger = req.method === "GET" && url.pathname === "/api/ledger";
    const contest = req.method === "POST" && url.pathname.startsWith("/api/contest/");
    if (url.pathname !== "/mcp" && !apiLedger && !contest) {
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
    try {
      if (apiLedger || contest) {
        if (!verified.principal.scopes.has("verax:read")) {
          send(res, 403, { error: "scope-missing" });
          return;
        }
        if (apiLedger) {
          const from = Number(url.searchParams.get("from") ?? "0");
          const to = Number(url.searchParams.get("to") ?? String(Number.MAX_SAFE_INTEGER));
          const decisions = (await services.ledger.decisions()).filter(
            (d) => d.claims.timestampMs >= from && d.claims.timestampMs < to,
          );
          const effects = (await services.ledger.effects()).filter(
            (e) => e.row.timestampMs >= from && e.row.timestampMs < to,
          );
          send(res, 200, {
            decisions,
            effects,
            policy: { hash: services.policyHash, document: services.policyDocument },
          });
          return;
        }
        const ref = decodeURIComponent(url.pathname.slice("/api/contest/".length));
        const result = await explain(services.ledger, ref, { checkpointSigner: signers.recordSigner });
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
        await transport.handleRequest(
          Object.assign(req, {
            auth: {
              token,
              clientId: verified.principal.brain,
              scopes: [...verified.principal.scopes],
              extra: { sub: verified.principal.brain },
            },
          }),
          res,
          parsed.value,
        );
      } catch (err) {
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

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.bindPort, config.bindHost, () => resolve());
  });
  return server;
}

export { TOOL_NAMES };
