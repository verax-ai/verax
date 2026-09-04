import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadPolicy } from "../src/policy.ts";
import { createProxy } from "../src/proxy.ts";
import { FileLedger } from "../src/ledger.ts";
import type { Principal, ToolCall, ToolResult } from "../src/types.ts";
import { EFFECT_SIGNER, RECORD_SIGNER, queuedNonce, tickingNow } from "./helpers.ts";

const policy = loadPolicy(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "policy", "default.json"), "utf8"),
);

const FULL: Principal = {
  brain: "brain-1",
  scopes: new Set(["verax:read", "verax:memory"]),
};
const NONE: Principal = { brain: "brain-1", scopes: new Set() };

async function inner(call: ToolCall): Promise<ToolResult> {
  if (call.name === "audit.explain") {
    throw new Error("boom");
  }
  return { content: [{ type: "text", text: `ok:${call.name}` }], isError: false };
}

/** 3 allow, 2 deny, 1 throw. Fixed now and nonce sequences. */
export async function runGoldenScenario(dir: string): Promise<FileLedger> {
  const ledger = new FileLedger(dir);
  const proxy = createProxy({
    policy,
    recordSigner: RECORD_SIGNER,
    effectSigner: EFFECT_SIGNER,
    ledger,
    now: tickingNow(10, 10),
    nonce: queuedNonce(["n1", "n2", "n3", "n4", "n5", "n6"]),
    inner,
  });
  const calls: Array<{ call: ToolCall; principal: Principal }> = [
    { call: { name: "memory.get", arguments: { id: "note-1" } }, principal: FULL },
    { call: { name: "memory.put", arguments: { id: "note-1", body: "hello" } }, principal: FULL },
    { call: { name: "message.read", arguments: {} }, principal: FULL },
    { call: { name: "memory.get", arguments: { id: "note-1" } }, principal: NONE },
    { call: { name: "spend", arguments: { amount: "1" } }, principal: FULL },
    { call: { name: "audit.explain", arguments: { ref: "n1" } }, principal: FULL },
  ];
  for (const step of calls) {
    try {
      await proxy.call(step.call, step.principal);
    } catch (err) {
      if (!(err instanceof Error) || err.message !== "boom") throw err;
    }
  }
  return ledger;
}
