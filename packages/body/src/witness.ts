import { randomBytes, generateKeyPairSync } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import {
  buildCheckpointClaims,
  checkpointHash,
  signCheckpoint,
  totalsFromDecisionRecords,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import type { LedgerEffect } from "@verax-ai/proxy";
import { checkpointsPath } from "../../proxy/src/checkpoints.ts";
import { signEffectAttestation } from "../../proxy/src/ledger.ts";
import { pidAlive } from "./unlock.ts";

const WITNESS_CLASS = "same-org" as const;

export type WitnessListen = {
  pid: number;
  port: number;
  token: string;
  publicKeyPem: string;
  startedAt: number;
};

type EffectRowWire = {
  ref: string;
  effectHash: string;
  effectClass: string;
  timestampMs: number;
  actor?: string;
};

function listenPath(stateDir: string): string {
  return join(stateDir, "witness.listen.json");
}

function statusPath(stateDir: string): string {
  return join(stateDir, "witness-status.jsonl");
}

/**
 * Replace a file's contents in one step, so a reader sees the old bytes or the
 * new ones and never a half-written file.
 *
 * Writing in place is not that: measured on 11 Sep 2026, a reader polling this
 * path every 20 ms while the file was rewritten 60 times got 12 unparseable
 * reads. The listen file is read by another process - that is its whole job -
 * and readWitnessListen answers a torn read with `null`, which the caller
 * cannot tell from "no witness is running".
 *
 * The rename needs the retry. On Windows it fails with EPERM while a reader
 * holds the destination open, and in the same measurement 26 of 60 plain
 * renames failed that way. Retrying briefly lost none of them and still let no
 * torn read through.
 */
function writeFileAtomic(path: string, text: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, text, { encoding: "utf8", mode: 0o600 });
  for (let attempt = 0; ; attempt += 1) {
    try {
      renameSync(tmp, path);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (attempt >= 40 || (code !== "EPERM" && code !== "EACCES" && code !== "EBUSY")) throw err;
      const until = Date.now() + 5;
      while (Date.now() < until) {
        // Busy-wait: this runs on the witness's own start-up path, where there
        // is nothing else to do and no event loop turn worth yielding for.
      }
    }
  }
}

function writePemAtomic(path: string, pem: string): void {
  writeFileAtomic(path, pem);
}

/** The same writer the listen file goes through, so its test measures it. */
export const writeListenForTest = writeFileAtomic;

export function loadOrCreateWitnessKeys(stateDir: string): { privateKeyPem: string; publicKeyPem: string } {
  const dir = join(stateDir, "keys");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const priv = join(dir, "witness.private.pem");
  const pub = join(dir, "witness.public.pem");
  if (existsSync(priv) && existsSync(pub)) {
    return { privateKeyPem: readFileSync(priv, "utf8"), publicKeyPem: readFileSync(pub, "utf8") };
  }
  if (existsSync(priv) || existsSync(pub)) {
    throw new Error("witness-keys-partial");
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pair = {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
  writePemAtomic(priv, pair.privateKeyPem);
  writePemAtomic(pub, pair.publicKeyPem);
  return pair;
}

export function readWitnessListen(stateDir: string): WitnessListen | null {
  try {
    const raw = JSON.parse(readFileSync(listenPath(stateDir), "utf8")) as Partial<WitnessListen>;
    if (
      typeof raw.pid !== "number" ||
      typeof raw.port !== "number" ||
      typeof raw.token !== "string" ||
      typeof raw.publicKeyPem !== "string"
    ) {
      return null;
    }
    return {
      pid: raw.pid,
      port: raw.port,
      token: raw.token,
      publicKeyPem: raw.publicKeyPem,
      startedAt: typeof raw.startedAt === "number" ? raw.startedAt : 0,
    };
  } catch {
    return null;
  }
}

function appendStatus(stateDir: string, row: Record<string, unknown>): void {
  appendFileSync(statusPath(stateDir), `${JSON.stringify(row)}\n`, { encoding: "utf8" });
}

function asRow(raw: unknown): EffectRowWire | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  if (
    typeof o.ref !== "string" ||
    typeof o.effectHash !== "string" ||
    typeof o.effectClass !== "string" ||
    typeof o.timestampMs !== "number"
  ) {
    return null;
  }
  return {
    ref: o.ref,
    effectHash: o.effectHash,
    effectClass: o.effectClass,
    timestampMs: o.timestampMs,
    ...(typeof o.actor === "string" ? { actor: o.actor } : {}),
  };
}

async function readJson(req: IncomingMessage, limit = 65_536): Promise<unknown> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    n += buf.length;
    if (n > limit) throw new Error("too-large");
    chunks.push(buf);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text === "" ? {} : JSON.parse(text);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    "x-content-type-options": "nosniff",
  });
  res.end(text);
}

export type CheckpointWindow = {
  epoch: number;
  startMs: number;
  endMs: number;
};

function loadDecisions(stateDir: string): SignedDecisionRecord[] {
  try {
    const text = readFileSync(join(stateDir, "decisions.jsonl"), "utf8");
    const out: SignedDecisionRecord[] = [];
    for (const line of text.split("\n")) {
      if (line === "") continue;
      out.push(JSON.parse(line) as SignedDecisionRecord);
    }
    return out;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

function lastCheckpointHash(stateDir: string): string | null {
  try {
    const text = readFileSync(checkpointsPath(stateDir), "utf8").trim();
    if (text === "") return null;
    const lines = text.split("\n").filter((l) => l !== "");
    const last = JSON.parse(lines[lines.length - 1] ?? "{}") as SignedCheckpoint;
    if (typeof last.coseHex !== "string" || !last.claims) return null;
    return checkpointHash(last);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    return null;
  }
}

function signWindowCheckpoint(
  stateDir: string,
  window: CheckpointWindow,
  keys: { privateKeyPem: string; publicKeyPem: string },
): SignedCheckpoint {
  const startMs = window.startMs;
  const endMs = window.endMs;
  const inWindow = loadDecisions(stateDir).filter(
    (d) => d.claims.timestampMs >= startMs && d.claims.timestampMs < endMs,
  );
  const claims = buildCheckpointClaims(
    window.epoch,
    inWindow,
    startMs,
    endMs,
    lastCheckpointHash(stateDir),
    totalsFromDecisionRecords,
    (row) => decisionRecordHash(row),
  );
  const signed = signCheckpoint(claims, keys.privateKeyPem, keys.publicKeyPem);
  appendFileSync(checkpointsPath(stateDir), `${JSON.stringify(signed)}\n`, { encoding: "utf8" });
  return signed;
}

export async function requestWitnessCheckpoint(
  stateDir: string,
  window: CheckpointWindow,
): Promise<SignedCheckpoint | null> {
  const listen = readWitnessListen(stateDir);
  if (!listen || !pidAlive(listen.pid)) return null;
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 800);
    const res = await fetch(`http://127.0.0.1:${listen.port}/checkpoint`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: listen.token, ...window }),
      signal: ac.signal,
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const body = (await res.json()) as SignedCheckpoint;
    if (typeof body.coseHex !== "string" || !body.claims) return null;
    return body;
  } catch {
    return null;
  }
}

export async function requestWitnessSign(
  stateDir: string,
  row: EffectRowWire,
  resultHash: string | undefined,
): Promise<Pick<LedgerEffect, "receipt" | "attestation" | "witnessClass"> | null> {
  const listen = readWitnessListen(stateDir);
  if (!listen || !pidAlive(listen.pid)) {
    appendStatus(stateDir, {
      atMs: Date.now(),
      ref: row.ref,
      result: "self-fallback",
      reason: "unreachable",
    });
    return null;
  }
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 400);
    const res = await fetch(`http://127.0.0.1:${listen.port}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: listen.token, row, resultHash: resultHash ?? null }),
      signal: ac.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      appendStatus(stateDir, {
        atMs: Date.now(),
        ref: row.ref,
        result: "self-fallback",
        reason: "unreachable",
      });
      return null;
    }
    const body = (await res.json()) as {
      witnessClass?: string;
      receipt?: LedgerEffect["receipt"];
      attestation?: LedgerEffect["attestation"];
    };
    if (body.witnessClass !== WITNESS_CLASS || !body.receipt || !body.attestation?.coseHex) {
      appendStatus(stateDir, {
        atMs: Date.now(),
        ref: row.ref,
        result: "self-fallback",
        reason: "unreachable",
      });
      return null;
    }
    appendStatus(stateDir, { atMs: Date.now(), ref: row.ref, result: "signed", pid: listen.pid });
    return {
      witnessClass: WITNESS_CLASS,
      receipt: body.receipt,
      attestation: body.attestation,
    };
  } catch {
    appendStatus(stateDir, {
      atMs: Date.now(),
      ref: row.ref,
      result: "self-fallback",
      reason: "unreachable",
    });
    return null;
  }
}

export async function runWitness(stateDir: string): Promise<void> {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const existing = readWitnessListen(stateDir);
  if (existing && pidAlive(existing.pid)) {
    process.stderr.write(`witness-already-running:${existing.pid}\n`);
    process.exit(1);
  }
  const keys = loadOrCreateWitnessKeys(stateDir);
  const token = randomBytes(16).toString("hex");
  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        if (req.method === "GET" && url.pathname === "/health") {
          send(res, 200, { ok: true, pid: process.pid });
          return;
        }
        if (req.method === "POST" && url.pathname === "/sign") {
          const body = (await readJson(req)) as { token?: unknown; row?: unknown; resultHash?: unknown };
          if (body.token !== token) {
            send(res, 401, { error: "unauthorized" });
            return;
          }
          const row = asRow(body.row);
          if (!row) {
            send(res, 400, { error: "row-invalid" });
            return;
          }
          const resultHash = typeof body.resultHash === "string" ? body.resultHash : undefined;
          const signed = signEffectAttestation(row, WITNESS_CLASS, resultHash, keys);
          send(res, 200, { witnessClass: WITNESS_CLASS, ...signed });
          return;
        }
        if (req.method === "POST" && url.pathname === "/checkpoint") {
          const body = (await readJson(req)) as {
            token?: unknown;
            epoch?: unknown;
            startMs?: unknown;
            endMs?: unknown;
          };
          if (body.token !== token) {
            send(res, 401, { error: "unauthorized" });
            return;
          }
          if (
            typeof body.epoch !== "number" ||
            !Number.isInteger(body.epoch) ||
            typeof body.startMs !== "number" ||
            typeof body.endMs !== "number" ||
            body.endMs <= body.startMs
          ) {
            send(res, 400, { error: "window-invalid" });
            return;
          }
          const signed = signWindowCheckpoint(
            stateDir,
            { epoch: body.epoch, startMs: body.startMs, endMs: body.endMs },
            keys,
          );
          send(res, 200, signed);
          return;
        }
        send(res, 404, { error: "not-found" });
      } catch {
        send(res, 400, { error: "bad-request" });
      }
    })();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    throw new Error("witness-bind");
  }
  const listen: WitnessListen = {
    pid: process.pid,
    port: addr.port,
    token,
    publicKeyPem: keys.publicKeyPem,
    startedAt: Date.now(),
  };
  writeFileAtomic(listenPath(stateDir), `${JSON.stringify(listen)}\n`);
  process.stderr.write(`witness-pid:${process.pid}\n`);
  process.stderr.write(`witness-port:${addr.port}\n`);
  await new Promise<void>((resolve) => {
    const shutdown = () => {
      try {
        unlinkSync(listenPath(stateDir));
      } catch {
        // already gone
      }
      server.close(() => resolve());
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}
