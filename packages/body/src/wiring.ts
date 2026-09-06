import {
  createProxy,
  FileLedger,
  loadPolicy,
  type EffectSigner,
  type ExplainOpts,
  type Principal,
  type RecordSigner,
  type ToolCall,
  type ToolResult,
} from "@verax-ai/proxy";
import { readFileSync } from "node:fs";
import { persistPolicySnapshot } from "./policy-store.ts";
import { readMemoryMeta } from "./tools/memory.ts";
import { memoryGet, memoryPut } from "./tools/memory.ts";
import { auditExplain } from "./tools/audit.ts";
import { messageRead } from "./tools/message.ts";
import { spendAuthorize } from "./tools/spend.ts";

export type ToolFn = (call: ToolCall, principal: Principal, ref?: string) => Promise<ToolResult>;

export const TOOL_NAMES = ["memory.get", "memory.put", "audit.explain", "message.read", "spend"] as const;

export type BodyServices = {
  proxy: ReturnType<typeof createProxy>;
  ledger: FileLedger;
  policyHash: string;
  policyDocument: unknown;
  listTools: () => readonly string[];
  explainOpts: () => Promise<ExplainOpts>;
};

/**
 * Tool functions live in a Map that is not exported. The only way to
 * reach them at runtime is `proxy.call` -> `inner`.
 */
export function createBodyServices(opts: {
  stateDir: string;
  policyFile: string;
  recordSigner: RecordSigner;
  effectSigner: EffectSigner;
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
  const explainOpts = async (): Promise<ExplainOpts> => {
    const env = process.env.VERAX_RECORD_PUBKEY_PIN;
    const pem = env && env.trim() !== "" ? env : opts.recordSigner.publicKeyPem;
    return {
      ...(pem
        ? {
            issuerTrust: {
              publicKeyPem: pem,
              source: env && env.trim() !== "" ? "env" : "own-key",
            },
          }
        : {}),
    };
  };
  registry.set("audit.explain", async (call) => auditExplain(call, ledger, await explainOpts()));
  registry.set("message.read", (call) => messageRead(call, opts.stateDir));
  registry.set("spend", (call, _principal, ref) => spendAuthorize(call, ref ?? ""));

  const inner: ToolFn = async (call, principal, ref) => {
    const fn = registry.get(call.name);
    if (!fn) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "unknown-tool", name: call.name }) }],
        isError: true,
      };
    }
    return fn(call, principal, ref);
  };

  const proxy = createProxy({
    policy,
    recordSigner: opts.recordSigner,
    effectSigner: opts.effectSigner,
    ledger,
    now,
    nonce,
    inner,
    resolveInput: (id) => readMemoryMeta(opts.stateDir, id),
  });

  return {
    proxy,
    ledger,
    policyHash: policy.hash,
    policyDocument,
    listTools: () => TOOL_NAMES,
    explainOpts,
  };
}
