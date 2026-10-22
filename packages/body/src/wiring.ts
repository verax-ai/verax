import {
  createProxy,
  FileLedger,
  loadPolicy,
  tenantKey,
  type EffectSigner,
  type ExplainOpts,
  type Policy,
  type Principal,
  type RecordSigner,
  type ToolCall,
  type ToolResult,
} from "@verax-ai/proxy";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { POLICY_FILE_ERROR_PREFIX, policyFileRefusal } from "./config.ts";
import { persistPolicySnapshot } from "./policy-store.ts";
import { inputsPrincipal } from "./inputs-read.ts";
import { assertRecordKeyTrust, resolveHeadDir } from "./keys.ts";
import { openMemoryStoreSync, publishMemoryStore, type MemoryStore } from "./memory-store.ts";
import {
  memoryBelongsToOtherTenant,
  memoryExistsForTenant,
  memoryGet,
  memoryHistoryUnavailable,
  memoryPut,
  readMemoryMeta,
} from "./tools/memory.ts";
import { auditExplain } from "./tools/audit.ts";
import { messageRead, messageSend } from "./tools/message.ts";
import { spendAuthorize } from "./tools/spend.ts";
import { requestWitnessCheckpoint, requestWitnessSign } from "./witness.ts";

export type BoundInput = { id: string; versionHash: string };

export type ToolFn = (
  call: ToolCall,
  principal: Principal,
  ref?: string,
  bound?: ReadonlyArray<BoundInput>,
) => Promise<ToolResult>;

export const TOOL_NAMES = [
  "memory.get",
  "memory.put",
  "audit.explain",
  "message.read",
  "message.send",
  "spend",
] as const;

export type ExtraTool = {
  name: string;
  fn: ToolFn;
};

export type BodyServices = {
  proxy: ReturnType<typeof createProxy>;
  ledger: FileLedger;
  policy: Policy;
  policyHash: string;
  policyDocument: unknown;
  listTools: () => readonly string[];
  explainOpts: () => Promise<ExplainOpts>;
  recordSigner: RecordSigner;
  memoryStore: MemoryStore;
};

function isLegacyExplainPin(value: string): boolean {
  return value.includes("BEGIN") && value.includes("PUBLIC KEY");
}

/**
 * Tool functions live in a Map that is not exported. The only way to
 * reach them at runtime is `proxy.call` -> `inner`. Extra tools (a
 * downstream prefix) enter that Map at construction; they still pass
 * the gate.
 */
export function createBodyServices(opts: {
  stateDir: string;
  policyFile: string;
  recordSigner: RecordSigner;
  effectSigner: EffectSigner;
  now?: () => number;
  nonce?: () => string;
  extraTools?: readonly ExtraTool[];
  keysDir?: string;
  headDir?: string;
}): BodyServices {
  const extraNames: string[] = [];
  const reserved = new Set<string>(TOOL_NAMES);
  for (const tool of opts.extraTools ?? []) {
    if (reserved.has(tool.name) || extraNames.includes(tool.name)) {
      throw new Error(`downstream-name-collision:${tool.name}`);
    }
    // Same shape as extraToolNameOk in downstream.ts (prefix.childName).
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,31}\.[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(tool.name)) {
      throw new Error(`downstream-name-invalid:${tool.name}`);
    }
    extraNames.push(tool.name);
  }

  // The policy is read before the ledger opens: opening takes the ledger lock,
  // and a start the policy stops must not leave that lock for the next one.
  const policyRefusal = policyFileRefusal(opts.policyFile);
  if (policyRefusal) throw new Error(policyRefusal);
  let policyText: string;
  try {
    policyText = readFileSync(opts.policyFile, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EISDIR") throw new Error(`${POLICY_FILE_ERROR_PREFIX}is a directory: ${opts.policyFile}`);
    throw new Error(`${POLICY_FILE_ERROR_PREFIX}is missing or unreadable: ${opts.policyFile}`);
  }
  const policyDocument = JSON.parse(policyText) as unknown;
  const policy = loadPolicy(policyText);
  const publicKeyPem = assertRecordKeyTrust(opts);
  const ledger = new FileLedger(opts.stateDir);
  ledger.remoteWitness = (row, resultHash) => requestWitnessSign(opts.stateDir, row, resultHash);
  ledger.onPieceClose = async (window) => {
    await requestWitnessCheckpoint(opts.stateDir, {
      epoch: 0,
      startMs: window.startMs,
      endMs: window.endMs,
    });
  };
  let store: MemoryStore;
  try {
    persistPolicySnapshot(opts.stateDir, policy.hash, policyDocument);
    store = publishMemoryStore(
      openMemoryStoreSync({
        stateDir: opts.stateDir,
        publicKeyPem,
        privateKeyPem: opts.recordSigner.privateKeyPem,
        headDir: resolveHeadDir(opts.stateDir, opts.keysDir, opts.headDir ?? process.env.VERAX_MEMORY_HEAD_DIR),
      }),
    );
  } catch (err) {
    ledger.close();
    throw err;
  }
  const now = opts.now ?? (() => Date.now());
  const nonce = opts.nonce ?? (() => crypto.randomUUID());

  const registry = new Map<string, ToolFn>();
  registry.set("memory.get", (call, principal, _ref, bound) =>
    memoryGet(call, opts.stateDir, now, principal, store, bound),
  );
  registry.set("memory.put", (call, principal, ref) => memoryPut(call, opts.stateDir, principal, ref ?? "", store));
  const explainOpts = async (): Promise<ExplainOpts> => {
    const env = process.env.VERAX_RECORD_PUBKEY_PIN?.trim() ?? "";
    const pem = env !== "" && isLegacyExplainPin(env) ? env : opts.recordSigner.publicKeyPem;
    return {
      ...(pem
        ? {
            issuerTrust: {
              publicKeyPem: pem,
              source: env !== "" && isLegacyExplainPin(env) ? "env" : "own-key",
            },
          }
        : {}),
    };
  };
  registry.set("audit.explain", async (call, principal) =>
    auditExplain(call, ledger, await explainOpts(), { principal, stateDir: opts.stateDir }),
  );
  registry.set("message.read", (call, principal) => messageRead(call, opts.stateDir, principal));
  registry.set("message.send", (call, principal, ref) =>
    messageSend(call, opts.stateDir, ref ?? "", principal),
  );
  registry.set("spend", (call, _principal, ref) => spendAuthorize(call, ref ?? ""));

  for (const tool of opts.extraTools ?? []) {
    registry.set(tool.name, tool.fn);
  }

  const inner: ToolFn = async (call, principal, ref, bound) => {
    const fn = registry.get(call.name);
    if (!fn) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "unknown-tool", name: call.name }) }],
        isError: true,
      };
    }
    return fn(call, principal, ref, bound);
  };

  // Halt and resume lines are copied into the ledger when the body opens
  // (`listen` awaits `proxy.syncControlRecords` before the socket accepts)
  // and again before each call. A CLI halt waits for one of those.
  const proxy = createProxy({
    policy,
    recordSigner: opts.recordSigner,
    effectSigner: opts.effectSigner,
    ledger,
    now,
    nonce,
    inner,
    resolveInput: (id, principal) => readMemoryMeta(opts.stateDir, id, principal, store),
    checkTenantMismatch: async (call, principal) => {
      if (call.name === "memory.get") {
        if (memoryHistoryUnavailable(opts.stateDir, store)) return false;
        const id = call.arguments.id;
        if (typeof id !== "string") return false;
        if (memoryExistsForTenant(opts.stateDir, id, principal, store)) return false;
        return memoryBelongsToOtherTenant(opts.stateDir, id, tenantKey(principal), store);
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
    policy,
    policyHash: policy.hash,
    policyDocument,
    listTools: () => (extraNames.length === 0 ? TOOL_NAMES : [...TOOL_NAMES, ...extraNames]),
    explainOpts,
    recordSigner: opts.recordSigner,
    memoryStore: store,
  };
}
