import { createPublicKey, randomBytes, generateKeyPairSync } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { writeFileAtomic } from "./atomic-write.ts";
import {
  buildCheckpointClaims,
  checkpointHash,
  signCheckpoint,
  totalsFromDecisionRecords,
  verifyCheckpoint,
  verifyCheckpointUnderPin,
  type SignedCheckpoint,
} from "@cedulon/checkpoint";
import { canonical, decisionRecordHash, type SignedDecisionRecord } from "@cedulon/core";
import { coseFromHex, decodeCoseSign1, verifyCoseSign1 } from "@cedulon/cose";
import { verifyEffectExtract } from "@cedulon/effect-extract";
import { appendAnchor, checkpointsPath, listPieceFiles, signEffectAttestation, type LedgerEffect } from "@verax-ai/proxy";
import { pendingAnchors, registerCheckpoint, serviceNameOf, serviceUrl } from "./anchor-cli.ts";
import { assertEd25519PublicKey } from "./keys.ts";
import { lockHolderAlive } from "@verax-ai/proxy";
import { pidAlive } from "./unlock.ts";

const WITNESS_CLASS = "same-org" as const;

export type WitnessListen = {
  pid: number;
  port: number;
  token: string;
  publicKeyPem: string;
  startedAt: number;
  /** The Transparency Service this witness registers each checkpoint with, or absent. */
  anchorService?: string;
};

/** Where `verax witness` sends each checkpoint it signs, read once at start. */
export type WitnessAnchor = { serviceName: string; serviceKey: string | null };

/**
 * `VERAX_ANCHOR_SERVICE` names the service (https; http only on loopback) and
 * `VERAX_ANCHOR_SERVICE_KEY` a file holding its public key. Neither set is no
 * anchoring. A value that is set but unusable is an error, so a witness the
 * operator meant to anchor does not start without anchoring.
 */
export function witnessAnchorFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { ok: true; anchor: WitnessAnchor | null } | { ok: false; reason: string } {
  const raw = env.VERAX_ANCHOR_SERVICE?.trim() ?? "";
  const keyPath = env.VERAX_ANCHOR_SERVICE_KEY?.trim() ?? "";
  if (raw === "") {
    if (keyPath !== "") return { ok: false, reason: "VERAX_ANCHOR_SERVICE_KEY is set without VERAX_ANCHOR_SERVICE" };
    return { ok: true, anchor: null };
  }
  const url = serviceUrl(raw);
  if (!url) {
    return {
      ok: false,
      reason: "VERAX_ANCHOR_SERVICE must be an https URL with no credentials, query or fragment (http only on loopback)",
    };
  }
  let serviceKey: string | null = null;
  if (keyPath !== "") {
    try {
      serviceKey = readFileSync(keyPath, "utf8");
    } catch {
      return { ok: false, reason: `cannot read VERAX_ANCHOR_SERVICE_KEY file ${keyPath}` };
    }
    if (serviceKey.trim() === "") return { ok: false, reason: `VERAX_ANCHOR_SERVICE_KEY file ${keyPath} is empty` };
    // A file that holds something else would start a witness that refuses
    // every receipt it is sent.
    try {
      createPublicKey(serviceKey);
    } catch {
      return { ok: false, reason: `VERAX_ANCHOR_SERVICE_KEY file ${keyPath} is not a public key` };
    }
  }
  return { ok: true, anchor: { serviceName: serviceNameOf(url), serviceKey } };
}

/**
 * Registers every checkpoint in `stateDir` not yet anchored at the service,
 * so a failure is retried with the next checkpoint. A failure is a
 * `witness-status.jsonl` row and nothing else: the checkpoint is already
 * written and the body is not waiting for this.
 */
export async function anchorPendingCheckpoints(
  stateDir: string,
  anchor: WitnessAnchor,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const { pending, problems } = pendingAnchors(stateDir, anchor.serviceName);
  if (problems.length > 0) {
    appendStatus(stateDir, {
      atMs: Date.now(),
      result: "anchor-failed",
      service: anchor.serviceName,
      reason: "unreadable",
    });
    return;
  }
  for (const hash of pending) {
    const got = await registerCheckpoint(anchor.serviceName, hash, anchor.serviceKey, fetchImpl);
    if (!got.ok) {
      appendStatus(stateDir, {
        atMs: Date.now(),
        result: "anchor-failed",
        service: anchor.serviceName,
        checkpointHash: hash,
        reason: got.reason,
      });
      continue;
    }
    appendAnchor(stateDir, got.row);
    appendStatus(stateDir, {
      atMs: Date.now(),
      result: "anchored",
      service: anchor.serviceName,
      checkpointHash: hash,
      receipt: got.checked ? "verified" : "unchecked",
    });
  }
}

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
  const pair = existsSync(priv) && existsSync(pub)
    ? { privateKeyPem: readFileSync(priv, "utf8"), publicKeyPem: readFileSync(pub, "utf8") }
    : existsSync(priv) || existsSync(pub)
      ? null
      : (() => {
          const { publicKey, privateKey } = generateKeyPairSync("ed25519");
          const created = {
            publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
            privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
          };
          writePemAtomic(priv, created.privateKeyPem);
          writePemAtomic(pub, created.publicKeyPem);
          return created;
        })();
  if (!pair) throw new Error("witness-keys-partial");
  assertEd25519PublicKey(pair.publicKeyPem, "witness");
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
      ...(typeof raw.anchorService === "string" && raw.anchorService !== "" ? { anchorService: raw.anchorService } : {}),
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
  const out: SignedDecisionRecord[] = [];
  for (const piece of listPieceFiles(stateDir)) {
    try {
      const text = readFileSync(piece.decisions, "utf8");
      for (const line of text.split("\n")) {
        if (line === "") continue;
        out.push(JSON.parse(line) as SignedDecisionRecord);
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw err;
    }
  }
  return out;
}

/** Last checkpoint hash this process recorded. A truncated file is compared with it. */
function recordedCheckpointHash(stateDir: string): string | null {
  let text: string;
  try {
    text = readFileSync(statusPath(stateDir), "utf8");
  } catch {
    return null;
  }
  let found: string | null = null;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    try {
      const row = JSON.parse(line) as { checkpointHash?: unknown };
      if (typeof row.checkpointHash === "string" && row.checkpointHash !== "") found = row.checkpointHash;
    } catch {
      // A torn status line is not a hash.
    }
  }
  return found;
}

function lastCheckpointHash(stateDir: string): string | null {
  const path = checkpointsPath(stateDir);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("checkpoint-unreadable");
  }
  const trimmed = text.trim();
  if (trimmed === "") {
    // A missing file starts a chain. Zero bytes or whitespace are not that file.
    // They also are not the hash recorded when the last checkpoint was written.
    const recorded = recordedCheckpointHash(stateDir);
    if (recorded === null || !trimmed.includes(recorded)) throw new Error("checkpoint-unreadable");
  }
  const lines = trimmed.split("\n").filter((line) => line !== "");
  try {
    const last = JSON.parse(lines[lines.length - 1] ?? "") as SignedCheckpoint;
    if (!last || typeof last !== "object" || typeof last.coseHex !== "string" || !last.claims) {
      throw new Error("checkpoint-unreadable");
    }
    return checkpointHash(last);
  } catch (err) {
    if (err instanceof Error && err.message === "checkpoint-unreadable") throw err;
    throw new Error("checkpoint-unreadable");
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
  appendStatus(stateDir, {
    atMs: Date.now(),
    result: "checkpoint",
    checkpointHash: checkpointHash(signed),
  });
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
    if (!checkpointMatchesListenKey(body, listen.publicKeyPem)) {
      appendStatus(stateDir, {
        atMs: Date.now(),
        result: "checkpoint-refused",
        reason: "witness-key-mismatch",
      });
      return null;
    }
    return body;
  } catch {
    return null;
  }
}

/** The listen file's key, not whichever key answered on the port. */
function checkpointMatchesListenKey(body: SignedCheckpoint, publicKeyPem: string): boolean {
  if (typeof body.coseHex !== "string" || body.coseHex === "" || !body.claims) return false;
  if (typeof body.publicKeyPem !== "string" || !pemSame(body.publicKeyPem, publicKeyPem)) return false;
  try {
    return verifyCheckpointUnderPin(body, publicKeyPem) && verifyCheckpoint(body, publicKeyPem);
  } catch {
    return false;
  }
}

function pemSame(left: string, right: string): boolean {
  return left.replace(/\r\n/g, "\n").trim() === right.replace(/\r\n/g, "\n").trim();
}

/** The listen file's key, not whichever key answered on the port. */
function answerMatchesListenKey(
  body: {
    receipt?: LedgerEffect["receipt"];
    attestation?: LedgerEffect["attestation"];
  },
  row: EffectRowWire,
  resultHash: string | undefined,
  publicKeyPem: string,
): boolean {
  const receipt = body.receipt;
  const coseHex = body.attestation?.coseHex;
  if (!receipt || typeof coseHex !== "string" || coseHex === "") return false;
  if (typeof receipt.publicKeyPem !== "string" || !pemSame(receipt.publicKeyPem, publicKeyPem)) return false;
  const clean = {
    ref: row.ref,
    effectHash: row.effectHash,
    effectClass: row.effectClass,
    timestampMs: row.timestampMs,
    ...(row.actor !== undefined ? { actor: row.actor } : {}),
  };
  const expected = canonical({
    ref: clean.ref,
    effectHash: clean.effectHash,
    witnessClass: WITNESS_CLASS,
    resultHash: resultHash ?? null,
  });
  try {
    const decoded = decodeCoseSign1(coseFromHex(coseHex));
    const payload = JSON.parse(Buffer.from(decoded.payload).toString("utf8")) as unknown;
    if (canonical(payload) !== expected) return false;
    if (!verifyCoseSign1(coseFromHex(coseHex), publicKeyPem, "application/json")) return false;
    if (!verifyEffectExtract(receipt, publicKeyPem)) return false;
    const signedRow = receipt.body.effects[0];
    if (signedRow == null || canonical(signedRow) !== canonical(clean)) return false;
  } catch {
    return false;
  }
  return true;
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
    if (!answerMatchesListenKey(body, row, resultHash, listen.publicKeyPem)) {
      appendStatus(stateDir, {
        atMs: Date.now(),
        ref: row.ref,
        result: "self-fallback",
        reason: "witness-key-mismatch",
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

/**
 * One registration run at a time: two checkpoints in quick succession must
 * not send the same pending hash twice.
 */
export function anchorInTurn(run: () => Promise<void>, onFailure: () => void): () => void {
  let running = false;
  let again = false;
  const drain = async (): Promise<void> => {
    do {
      again = false;
      try {
        await run();
      } catch {
        // Recording the failure can fail for the reason the run did (a full
        // disk). Nothing may leave this function as a rejection: an unhandled
        // one ends the witness process.
        try {
          onFailure();
        } catch {
          /* the status file was the only place to say so */
        }
      }
    } while (again);
    running = false;
  };
  // A run retries everything still pending, so checkpoints that arrive while
  // one is in flight need one more run after it, not one each.
  return () => {
    if (running) {
      again = true;
      return;
    }
    running = true;
    void drain();
  };
}

export async function runWitness(stateDir: string): Promise<void> {
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const existing = readWitnessListen(stateDir);
  // A restarted container runs the witness under the same pid; a listen file
  // written before this process started is not a running witness.
  if (existing && lockHolderAlive({ pid: existing.pid, startedAt: existing.startedAt })) {
    process.stderr.write(`witness-already-running:${existing.pid}\n`);
    process.exit(1);
  }
  const anchorConfig = witnessAnchorFromEnv();
  if (!anchorConfig.ok) {
    process.stderr.write(`witness-anchor-config: ${anchorConfig.reason}\n`);
    process.exit(64);
  }
  const anchor = anchorConfig.anchor;
  const anchorAfterCheckpoint: () => void = anchor
    ? anchorInTurn(
        () => anchorPendingCheckpoints(stateDir, anchor),
        () =>
          appendStatus(stateDir, {
            atMs: Date.now(),
            result: "anchor-failed",
            service: anchor.serviceName,
            reason: "exception",
          }),
      )
    : () => undefined;
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
          // After the answer: the body waits 800 ms for it, a service up to 15 s.
          anchorAfterCheckpoint();
          return;
        }
        send(res, 404, { error: "not-found" });
      } catch (err) {
        const reason = err instanceof Error ? err.message : "";
        if (reason === "checkpoint-unreadable") {
          appendStatus(stateDir, { atMs: Date.now(), result: "checkpoint-refused", reason });
          send(res, 409, { error: reason });
          return;
        }
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
    ...(anchor ? { anchorService: anchor.serviceName } : {}),
  };
  writeFileAtomic(listenPath(stateDir), `${JSON.stringify(listen)}\n`);
  process.stderr.write(`witness-pid:${process.pid}\n`);
  process.stderr.write(`witness-port:${addr.port}\n`);
  if (anchor) process.stderr.write(`witness-anchor:${anchor.serviceName}\n`);
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
