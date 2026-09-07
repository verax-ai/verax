import {
  createProxy,
  FileLedger,
  loadPolicy,
  tenantKey,
  type EffectSigner,
  type ExplainOpts,
  type Principal,
  type RecordSigner,
  type ToolCall,
  type ToolResult,
} from "@verax-ai/proxy";
import { readFileSync } from "node:fs";
import { persistPolicySnapshot } from "./policy-store.ts";
import { inputsPrincipal } from "./inputs-read.ts";
import { memoryBelongsToOtherTenant, memoryGet, memoryPut, readMemoryMeta } from "./tools/memory.ts";
import { auditExplain } from "./tools/audit.ts";
import { messageRead, messageSend } from "./tools/message.ts";
import { spendAuthorize } from "./tools/spend.ts";

export type ToolFn = (call: ToolCall, principal: Principal, ref?: string) => Promise<ToolResult>;

export const TOOL_NAMES = [
  "memory.get",
  "memory.put",
  "audit.explain",
  "message.read",
  "message.send",
  "spend",
] as const;

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
  registry.set("memory.get", (call, principal, ref) => memoryGet(call, opts.stateDir, now, principal, ref));
  registry.set("memory.put", (call, principal) => memoryPut(call, opts.stateDir, principal));
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
  registry.set("message.read", (call, principal) => messageRead(call, opts.stateDir, principal));
  registry.set("message.send", (call, principal, ref) =>
    messageSend(call, opts.stateDir, ref ?? "", principal),
  );
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
    resolveInput: (id, principal) => readMemoryMeta(opts.stateDir, id, principal),
    checkTenantMismatch: async (call, principal) => {
      if (call.name === "memory.get") {
        const id = call.arguments.id;
        if (typeof id !== "string") return false;
        return memoryBelongsToOtherTenant(opts.stateDir, id, tenantKey(principal));
      }
      if (call.name === "audit.explain") {
        const ref = call.arguments.ref;
        if (typeof ref !== "string" || ref === "") return false;
        const decisions = await ledger.decisions();
        if (!decisions.some((d) => d.claims.ref === ref)) return false;
        const owner = await inputsPrincipal(opts.stateDir, ref);
        if (owner === null) return true;
        return tenantKey(owner) !== tenantKey(principal);
      }
      return false;
    },
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
