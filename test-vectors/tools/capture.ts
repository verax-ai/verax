/**
 * Runs a real Verax body over HTTP with a witness process beside it and
 * drives one fixed scenario through it. The ledger it leaves is the source
 * of every vector: `valid-*` are copies, `fail-*` change one thing in a copy.
 *
 * This is a maintainer tool. It writes into a temporary directory that holds
 * the private test keys; `generate.ts` copies only public material out.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { isoBase64URL } from "@simplewebauthn/server/helpers";

import { approvalChallenge } from "../../packages/body/src/approval-signature.ts";
import { saveCredential } from "../../packages/body/src/operator-credentials.ts";
import { listen } from "../../packages/body/src/server.ts";
import { requestWitnessCheckpoint } from "../../packages/body/src/witness.ts";
import { startDevIssuer } from "../../tests/issuer-helper.ts";
import { assertWithSoftwarePasskey, mintSoftwarePasskey } from "../../tests/software-passkey.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const cli = join(root, "packages", "body", "src", "cli.ts");

export const RP_ID = "localhost";
export const ORIGIN = "http://localhost:4173";

export type Capture = { stateDir: string };

function policyFile(dir: string): string {
  const path = join(dir, "vector-policy.json");
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      approvalTtlMs: 86_400_000,
      rules: [
        {
          id: "memory-put",
          tool: "memory.put",
          requires: ["verax:memory"],
          mode: "approve",
          text: "Writes need operator approval.",
        },
        {
          id: "memory-get",
          tool: "memory.get",
          requires: ["verax:read"],
          text: "Reading memory needs the read scope.",
        },
      ],
    }),
    "utf8",
  );
  return path;
}

async function waitFile(path: string, child: ChildProcess, ms = 30_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (existsSync(path)) return;
    if (child.exitCode !== null) throw new Error(`witness-exited:${child.exitCode}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`listen-timeout:${path}`);
}

function decisions(stateDir: string): SignedDecisionRecord[] {
  return readFileSync(join(stateDir, "decisions.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line) as SignedDecisionRecord);
}

/** `stateDir` is left in place; the caller removes it once vectors are written. */
export async function capture(opts: { denyOnly?: boolean } = {}): Promise<Capture> {
  const stateDir = mkdtempSync(join(tmpdir(), "verax-vectors-"));
  const passkey = mintSoftwarePasskey("Ed25519");
  saveCredential(stateDir, {
    id: passkey.id,
    publicKey: isoBase64URL.fromBuffer(passkey.publicKeyCose.slice()),
    counter: 0,
    sub: "operator-1",
  });

  process.env.VERAX_RP_ID = RP_ID;
  process.env.VERAX_RP_ORIGINS = ORIGIN;

  const witness = spawn(process.execPath, ["--experimental-strip-types", cli, "witness", stateDir], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let witnessErr = "";
  witness.stderr?.on("data", (buf: Buffer) => {
    witnessErr += String(buf);
  });

  const audience = "http://127.0.0.1/verax-test-vectors";
  const issuer = await startDevIssuer(0, audience);
  try {
    await waitFile(join(stateDir, "witness.listen.json"), witness).catch((err: unknown) => {
      throw new Error(`${String(err)} ${witnessErr}`);
    });
    const server = await listen({
      issuer: issuer.issuer,
      jwksUrl: issuer.jwksUrl,
      audience,
      stateDir,
      bindHost: "127.0.0.1",
      bindPort: 0,
      policyFile: policyFile(stateDir),
      tlsTerminated: false,
    });
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    try {
      const agent = await issuer.sign({ scope: "verax:read verax:memory", sub: "agent-1" });
      const operator = await issuer.sign({ scope: "verax:audit verax:approve", sub: "operator-1" });

      let rpc = 0;
      const tool = async (name: string, args: Record<string, unknown>): Promise<string> => {
        rpc += 1;
        const res = await fetch(`${base}/mcp`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            authorization: `Bearer ${agent}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: rpc, method: "tools/call", params: { name, arguments: args } }),
        });
        return res.text();
      };
      const asOperator = (path: string, body?: unknown) =>
        fetch(`${base}${path}`, {
          method: "POST",
          headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });

      if (opts.denyOnly) {
        await tool("spend", { amountMinor: 1000, currency: "TRY", payee: "shop-1" });
      } else {
        // The agent names its own reference and sends the same one on the retry.
        const note = {
          _ref: "write-note-1",
          id: "note-1",
          body: { text: "meeting moved to 15:00" },
          source: { uri: "file://notes/today.txt", retrievedAtMs: 1 },
          validUntilMs: Date.now() + 86_400_000,
        };
        // 1. a write the policy will not decide alone: defer
        await tool("memory.put", note);
        // 2. the operator approves it with a passkey: allow + effect
        const held = decisions(stateDir).find((d) => d.claims.decision === "defer");
        if (!held || typeof held.claims.ref !== "string") throw new Error("no-defer");
        const assertion = assertWithSoftwarePasskey(passkey, {
          challenge: approvalChallenge({
            ref: held.claims.ref,
            requestHash: held.claims.requestHash,
            deferRecordHash: decisionRecordHash(held),
          }),
          rpID: RP_ID,
          origin: ORIGIN,
        });
        const approved = await asOperator("/api/approve", {
          ref: held.claims.ref,
          requestHash: held.claims.requestHash,
          assertion,
        });
        if (approved.status !== 200) throw new Error(`approve-${approved.status}:${await approved.text()}`);
        // An approved allow says the operator said yes, not that the write
        // ran. The agent's retry is what runs it and leaves the effect row.
        await tool("memory.put", note);
        // 3. a read the policy allows: allow + effect
        await tool("memory.get", { id: "note-1" });
        // 4. a tool with no rule: deny
        await tool("spend", { amountMinor: 1000, currency: "TRY", payee: "shop-1" });
        // 5. halt; 6. a call while halted is denied; 7. resume; 8. allowed again
        if ((await asOperator("/api/halt")).status !== 200) throw new Error("halt");
        await tool("memory.get", { id: "note-1" });
        if ((await asOperator("/api/resume")).status !== 200) throw new Error("resume");
        await tool("memory.get", { id: "note-1" });
      }

      const times = decisions(stateDir).map((d) => d.claims.timestampMs);
      const signed = await requestWitnessCheckpoint(stateDir, {
        epoch: 0,
        startMs: Math.min(...times),
        endMs: Math.max(...times) + 1,
      });
      if (!signed && !opts.denyOnly) throw new Error("witness did not sign a checkpoint");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  } finally {
    await issuer.close();
    if (witness.exitCode === null && witness.signalCode === null) {
      witness.kill("SIGTERM");
      await new Promise((resolve) => witness.once("close", resolve));
    }
  }
  return { stateDir };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = await capture({ denyOnly: process.argv.includes("--deny-only") });
  console.log(result.stateDir);
  process.exit(0);
}
