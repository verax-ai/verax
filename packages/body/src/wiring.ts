import { createProxy, FileLedger, loadPolicy, type Principal, type ToolCall, type ToolResult } from "@verax-ai/proxy";
import { readFileSync } from "node:fs";
import { persistPolicySnapshot } from "./policy-store.ts";
import { memoryGet, memoryPut } from "./tools/memory.ts";
import { auditExplain } from "./tools/audit.ts";
import { messageRead } from "./tools/message.ts";

export type ToolFn = (call: ToolCall, principal: Principal) => Promise<ToolResult>;

export const TOOL_NAMES = ["memory.get", "memory.put", "audit.explain", "message.read"] as const;

export type BodyServices = {
  proxy: ReturnType<typeof createProxy>;
  ledger: FileLedger;
  policyHash: string;
  policyDocument: unknown;
  listTools: () => readonly string[];
};

/**
 * Tool functions live in a Map that is not exported. The only way to
 * reach them at runtime is `proxy.call` -> `inner`.
 */
export function createBodyServices(opts: {
  stateDir: string;
  policyFile: string;
  recordSigner: { privateKeyPem: string; publicKeyPem: string };
  effectSigner: { privateKeyPem: string; publicKeyPem: string };
  now?: () => number;
  nonce?: () => string;
}): BodyServices {
  const ledger = new FileLedger(opts.stateDir);
  const policyText = readFileSync(opts.policyFile, "utf8");
  const policyDocument = JSON.parse(policyText) as unknown;
  const policy = loadPolicy(policyText);
  persistPolicySnapshot(opts.stateDir, policy.hash, policyDocument);
  const now = opts.now ?? (() => Date.now());
  const nonce = opts.nonce ?? (() => crypto.randomUUID());

  const registry = new Map<string, ToolFn>();
  registry.set("memory.get", (call) => memoryGet(call, opts.stateDir, now));
  registry.set("memory.put", (call) => memoryPut(call, opts.stateDir));
  registry.set("audit.explain", (call) => auditExplain(call, ledger));
  registry.set("message.read", (call) => messageRead(call, opts.stateDir));

  const inner: ToolFn = async (call) => {
    const fn = registry.get(call.name);
    if (!fn) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "unknown-tool", name: call.name }) }],
        isError: true,
      };
    }
    return fn(call, { brain: "", scopes: new Set() });
  };

  const proxy = createProxy({
    policy,
    recordSigner: opts.recordSigner,
    effectSigner: opts.effectSigner,
    ledger,
    now,
    nonce,
    inner,
  });

  return {
    proxy,
    ledger,
    policyHash: policy.hash,
    policyDocument,
    listTools: () => TOOL_NAMES,
  };
}
