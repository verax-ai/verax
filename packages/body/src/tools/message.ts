import { appendFileSync, mkdirSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { tenantKey, type Principal, type ToolCall, type ToolResult } from "@verax-ai/proxy";
import { messageQuotaBytes } from "../config.ts";

/** One in-process chain per tenant directory. The body is one process per state dir. */
const messageQuotaChain = new Map<string, Promise<unknown>>();

function withMessageQuotaLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = messageQuotaChain.get(key) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  const settled = run.then(() => undefined, () => undefined);
  messageQuotaChain.set(key, settled);
  void settled.then(() => {
    if (messageQuotaChain.get(key) === settled) messageQuotaChain.delete(key);
  });
  return run;
}

function tenantDir(stateDir: string, principal: Principal): string {
  return join(stateDir, "tenants", tenantKey(principal));
}

export async function messageRead(_call: ToolCall, stateDir: string, principal: Principal): Promise<ToolResult> {
  const path = join(tenantDir(stateDir, principal), "inbox.jsonl");
  let rows: unknown[] = [];
  try {
    const text = await readFile(path, "utf8");
    rows = text
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => JSON.parse(line) as unknown);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  return {
    content: [{ type: "text", text: JSON.stringify(rows) }],
    isError: false,
  };
}

/** No-network stub: appends to the tenant outbox. Mail/WA reuse the same egress list. */
export async function messageSend(
  call: ToolCall,
  stateDir: string,
  ref: string,
  principal: Principal,
): Promise<ToolResult> {
  const row = {
    to: call.arguments.to,
    text: call.arguments.text,
    ref,
  };
  const dir = tenantDir(stateDir, principal);
  const file = join(dir, "outbox.jsonl");
  const payload = `${JSON.stringify(row)}\n`;
  return withMessageQuotaLock(dir, async () => {
    let used = 0;
    try {
      used = statSync(file).size;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    if (used + Buffer.byteLength(payload) > messageQuotaBytes()) {
      return {
        content: [{ type: "text", text: JSON.stringify({ error: "message-quota" }) }],
        isError: true,
      };
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    appendFileSync(file, payload, { encoding: "utf8", mode: 0o600 });
    return {
      content: [{ type: "text", text: JSON.stringify({ queued: true, ref }) }],
      isError: false,
    };
  });
}
