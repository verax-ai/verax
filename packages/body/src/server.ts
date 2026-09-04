import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { BodyConfig } from "./config.ts";
import { createVerifier, readBearer, wwwAuthenticate } from "./auth.ts";
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

function send(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
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
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "127.0.0.1"}`);
    if (req.method === "GET" && url.pathname === "/healthz") {
      send(res, 200, { ok: true });
      return;
    }
    if (req.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      send(res, 200, {
        resource: config.audience,
        authorization_servers: [config.issuer],
        bearer_methods_supported: ["header"],
        scopes_supported: ["verax:read", "verax:memory", "verax:act", "verax:pay"],
      });
      return;
    }
    if (url.pathname !== "/mcp") {
      send(res, 404, { error: "not-found" });
      return;
    }
    const token = readBearer(req.headers.authorization);
    if (!token) {
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
      return;
    }
    try {
      const verified = await verify(token);
      const mcp = new McpServer({ name: "verax-body", version: "0.0.0" }, { capabilities: { tools: {} } });
      attachHandlers(mcp);
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await mcp.connect(transport);
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
        );
      } catch (err) {
        const detail = err instanceof Error ? err.message : "fault";
        process.stderr.write(`verax-transport: ${detail}\n`);
        if (!res.headersSent) {
          send(res, 500, { error: "transport", detail });
        }
      } finally {
        await transport.close();
      }
    } catch {
      await bumpUnauthenticated(config.stateDir);
      send(res, 401, { error: "unauthorized" }, { "www-authenticate": wwwAuthenticate(config.audience) });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.bindPort, config.bindHost, () => resolve());
  });
  return server;
}

export { TOOL_NAMES };
