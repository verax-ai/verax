import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  readdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeSync,
} from "node:fs";
import { chmod, mkdir, open, rename, stat, unlink } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { canonical } from "@cedulon/core";
import { canonicalizeDirPath, resolveHeadDir } from "./keys.ts";

class UncertainAppendError extends Error {
  constructor() {
    super("memory-append-uncertain");
    this.name = "UncertainAppendError";
  }
}

export const MEMORY_COMMITS_FILE = "memory-commits.jsonl";
export const MEMORY_PURPOSE = "verax.memory.v2";
export const MEMORY_HASH_SCHEMA = 2;

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const OBJECT_KEYS = new Set([
  "id",
  "revision",
  "tenantKey",
  "body",
  "source",
  "validFromMs",
  "validUntilMs",
  "versionHash",
]);
const COMMIT_PAYLOAD_KEYS = new Set([
  "v",
  "seq",
  "tenantKey",
  "id",
  "revision",
  "versionHash",
  "objectPath",
  "putRef",
  "prevCommitHash",
  "ts",
]);
const LINE_KEYS = new Set(["payload", "sig"]);
const HEAD_PAYLOAD_KEYS = new Set(["v", "stateDirHash", "seq", "lastHash", "ts"]);

export type MemoryObject = {
  id: string;
  revision: number;
  tenantKey: string;
  body: unknown;
  source: unknown;
  validFromMs: number;
  validUntilMs: number;
  versionHash: string;
};

export type MemoryIndexEntry = {
  revision: number;
  versionHash: string;
  objectPath: string;
};

export type IntegrityReason =
  | "memory-integrity-mismatch"
  | "memory-integrity-missing"
  | "memory-integrity-unattested"
  | "memory-integrity-history-unavailable";

export type VerifiedMemory =
  | { kind: "ok"; object: MemoryObject; versionHash: string }
  | { kind: "not-found" }
  | { kind: "integrity"; reason: IntegrityReason };

export type MemoryCommitPayload = {
  v: 1;
  seq: number;
  tenantKey: string;
  id: string;
  revision: number;
  versionHash: string;
  objectPath: string;
  putRef: string;
  prevCommitHash: string | null;
  ts: number;
};

export type MemoryHeadPayload = {
  v: 1;
  stateDirHash: string;
  seq: number;
  lastHash: string | null;
  ts: number;
};

const stores = new Map<string, MemoryStore>();
const lockChains = new Map<string, Promise<unknown>>();

function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = lockChains.get(key) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  const settled = run.then(() => undefined, () => undefined);
  lockChains.set(key, settled);
  void settled.then(() => {
    if (lockChains.get(key) === settled) lockChains.delete(key);
  });
  return run;
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("hex");
}

function storeKey(stateDir: string): string {
  return resolve(stateDir);
}

export function memoryVersionHash(fields: {
  tenantKey: string;
  id: string;
  revision: number;
  body: unknown;
  source: unknown;
  validFromMs: number;
  validUntilMs: number;
}): string {
  return sha256Canonical({
    purpose: MEMORY_PURPOSE,
    hashSchema: MEMORY_HASH_SCHEMA,
    tenantKey: fields.tenantKey,
    id: fields.id,
    revision: fields.revision,
    body: fields.body,
    source: fields.source,
    validFromMs: fields.validFromMs,
    validUntilMs: fields.validUntilMs,
  });
}

export function memoryStateDirHash(stateDir: string): string {
  return createHash("sha256").update(canonicalizeDirPath(stateDir), "utf8").digest("hex");
}

export function memoryHeadPath(stateDir: string, headDir: string): string {
  return join(headDir, `memory-head-${memoryStateDirHash(stateDir).slice(0, 16)}.json`);
}

function signPayload(payload: unknown, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(canonical(payload), "utf8"), key).toString("base64");
}

function verifyPayload(payload: unknown, sig: string, publicKeyPem: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(canonical(payload), "utf8"),
      createPublicKey(publicKeyPem),
      Buffer.from(sig, "base64"),
    );
  } catch {
    return false;
  }
}

function closedKeys(value: object, allowed: Set<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isCommitPayload(value: unknown): value is MemoryCommitPayload {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (!closedKeys(value, COMMIT_PAYLOAD_KEYS)) return false;
  const row = value as Record<string, unknown>;
  return (
    row.v === 1 &&
    typeof row.seq === "number" &&
    Number.isInteger(row.seq) &&
    row.seq >= 1 &&
    typeof row.tenantKey === "string" &&
    typeof row.id === "string" &&
    ID_RE.test(row.id) &&
    typeof row.revision === "number" &&
    Number.isInteger(row.revision) &&
    row.revision >= 1 &&
    typeof row.versionHash === "string" &&
    /^[0-9a-f]{64}$/.test(row.versionHash) &&
    typeof row.objectPath === "string" &&
    typeof row.putRef === "string" &&
    (row.prevCommitHash === null || (typeof row.prevCommitHash === "string" && /^[0-9a-f]{64}$/.test(row.prevCommitHash))) &&
    typeof row.ts === "number"
  );
}

function isHeadPayload(value: unknown): value is MemoryHeadPayload {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (!closedKeys(value, HEAD_PAYLOAD_KEYS)) return false;
  const row = value as Record<string, unknown>;
  const lastHashOk =
    row.lastHash === null || (typeof row.lastHash === "string" && /^[0-9a-f]{64}$/.test(row.lastHash));
  if (
    row.v !== 1 ||
    typeof row.stateDirHash !== "string" ||
    !/^[0-9a-f]{64}$/.test(row.stateDirHash) ||
    typeof row.seq !== "number" ||
    !Number.isInteger(row.seq) ||
    row.seq < 0 ||
    !lastHashOk ||
    typeof row.ts !== "number"
  ) {
    return false;
  }
  if (row.seq === 0) return row.lastHash === null;
  return typeof row.lastHash === "string";
}

function guardedJoin(root: string, ...parts: string[]): string | null {
  const base = resolve(root);
  const path = resolve(base, ...parts);
  const prefix = base.endsWith(sep) ? base : `${base}${sep}`;
  if (path !== base && !path.startsWith(prefix)) return null;
  return path;
}

export function relativeObjectPath(tenantKey: string, id: string, revision: number): string {
  return `tenants/${tenantKey}/memory/${id}/${revision}.json`;
}

function resolveObjectPath(stateDir: string, objectPath: string): string | null {
  if (objectPath.includes("\0")) return null;
  const parts = objectPath.split("/").filter((part) => part !== "");
  if (parts.some((part) => part === ".." || part === ".")) return null;
  if (parts.length !== 5 || parts[0] !== "tenants" || parts[2] !== "memory") return null;
  if (!parts[4]!.endsWith(".json")) return null;
  return guardedJoin(stateDir, ...parts);
}

function parseMemoryObject(raw: string): MemoryObject | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  if (!closedKeys(parsed, OBJECT_KEYS)) return null;
  const item = parsed as Record<string, unknown>;
  if (typeof item.id !== "string" || !ID_RE.test(item.id)) return null;
  if (typeof item.revision !== "number" || !Number.isInteger(item.revision) || item.revision < 1) return null;
  if (typeof item.tenantKey !== "string") return null;
  if (item.source === null || typeof item.source !== "object" || Array.isArray(item.source)) return null;
  if (typeof item.validFromMs !== "number" || typeof item.validUntilMs !== "number") return null;
  if (typeof item.versionHash !== "string") return null;
  return {
    id: item.id,
    revision: item.revision,
    tenantKey: item.tenantKey,
    body: item.body,
    source: item.source,
    validFromMs: item.validFromMs,
    validUntilMs: item.validUntilMs,
    versionHash: item.versionHash,
  };
}

function isUnsupportedDirFsync(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException).code;
  return code === "EPERM" || code === "EISDIR" || code === "EINVAL" || code === "ENOTSUP" || code === "ENOSYS";
}

async function mkdirDurable(dir: string): Promise<void> {
  const created: string[] = [];
  let current = resolve(dir);
  while (!existsSync(current)) {
    created.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  await mkdir(dir, { recursive: true, mode: 0o700 });
  for (const path of created) await fsyncDir(path);
  await fsyncDir(current);
}

async function writeFileDurable(finalPath: string, payload: string): Promise<void> {
  const dir = dirname(finalPath);
  await mkdirDurable(dir);
  const tmp = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const fh = await open(tmp, "w", 0o600);
  try {
    await fh.writeFile(payload, "utf8");
    await fh.sync();
  } finally {
    await fh.close();
  }
  await rename(tmp, finalPath);
  try {
    await chmod(finalPath, 0o600);
  } catch {
    // Windows may refuse chmod; the file is already written.
  }
  await fsyncDir(dir);
}

async function fsyncDir(dir: string): Promise<void> {
  try {
    const fh = await open(dir, "r");
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch (err) {
    if (isUnsupportedDirFsync(err)) return;
    throw err;
  }
}

function fsyncDirSync(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    if (isUnsupportedDirFsync(err)) return;
    throw err;
  }
}

function mkdirDurableSync(dir: string): void {
  const created: string[] = [];
  let current = resolve(dir);
  while (!existsSync(current)) {
    created.push(current);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const path of created) fsyncDirSync(path);
  fsyncDirSync(current);
}

function writeFileDurableSync(finalPath: string, payload: string): void {
  const dir = dirname(finalPath);
  mkdirDurableSync(dir);
  const tmp = `${finalPath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, payload, 0, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, finalPath);
  try {
    chmodSync(finalPath, 0o600);
  } catch {
    // Windows may refuse chmod; the file is already written.
  }
  fsyncDirSync(dir);
}

function encodeHeadLine(payload: MemoryHeadPayload, privateKeyPem: string): string {
  return `${JSON.stringify({ payload, sig: signPayload(payload, privateKeyPem) })}\n`;
}

function persistHeadSync(opts: {
  stateDir: string;
  headDir: string;
  privateKeyPem: string;
  seq: number;
  lastHash: string | null;
}): void {
  const payload: MemoryHeadPayload = {
    v: 1,
    stateDirHash: memoryStateDirHash(opts.stateDir),
    seq: opts.seq,
    lastHash: opts.lastHash,
    ts: Date.now(),
  };
  writeFileDurableSync(memoryHeadPath(opts.stateDir, opts.headDir), encodeHeadLine(payload, opts.privateKeyPem));
}

function readVerifiedHead(
  path: string,
  publicKeyPem: string,
  expectedStateDirHash: string,
): { kind: "missing" } | { kind: "invalid" } | { kind: "ok"; payload: MemoryHeadPayload } {
  if (!existsSync(path)) return { kind: "missing" };
  try {
    if (!statSync(path).isFile()) return { kind: "invalid" };
    const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || !closedKeys(parsed, LINE_KEYS)) {
      return { kind: "invalid" };
    }
    const row = parsed as { payload?: unknown; sig?: unknown };
    if (typeof row.sig !== "string" || !isHeadPayload(row.payload)) return { kind: "invalid" };
    if (!verifyPayload(row.payload, row.sig, publicKeyPem)) return { kind: "invalid" };
    if (row.payload.stateDirHash !== expectedStateDirHash) return { kind: "invalid" };
    return { kind: "ok", payload: row.payload };
  } catch {
    return { kind: "invalid" };
  }
}

async function appendLineDurable(path: string, line: string): Promise<void> {
  const existed = existsSync(path);
  const fh = await open(path, "a", 0o600);
  let writeStarted = false;
  let firstErr: unknown;
  try {
    writeStarted = true;
    await fh.writeFile(line, "utf8");
    await fh.sync();
  } catch (err) {
    firstErr = err;
  }
  try {
    await fh.close();
  } catch (err) {
    firstErr ??= err;
  }
  if (writeStarted && firstErr) throw new UncertainAppendError();
  if (firstErr) throw firstErr;
  if (!existed) {
    try {
      await fsyncDir(dirname(path));
    } catch {
      throw new UncertainAppendError();
    }
  }
}

function* readCommitLines(path: string): Generator<string> {
  const fd = openSync(path, "r");
  try {
    const buf = Buffer.alloc(64 * 1024);
    let acc = "";
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      acc += buf.toString("utf8", 0, n);
      let idx = acc.indexOf("\n");
      while (idx !== -1) {
        let line = acc.slice(0, idx);
        acc = acc.slice(idx + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);
        yield line;
        idx = acc.indexOf("\n");
      }
    }
    if (acc.length > 0) yield acc.endsWith("\r") ? acc.slice(0, -1) : acc;
  } finally {
    closeSync(fd);
  }
}

function indexKey(tenantKey: string, id: string): string {
  return `${tenantKey}|${id}`;
}

function fileExistsUnder(root: string, ...parts: string[]): boolean {
  const path = guardedJoin(root, ...parts);
  if (path === null) return false;
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function dirHasJson(root: string, ...parts: string[]): boolean {
  const path = guardedJoin(root, ...parts);
  if (path === null) return false;
  try {
    if (!statSync(path).isDirectory()) return false;
    return readdirSync(path).some((name) => name.endsWith(".json"));
  } catch {
    return false;
  }
}

export class MemoryStore {
  readonly stateDir: string;
  readonly headDir: string;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
  historyUnavailable: boolean;
  private readonly index = new Map<string, MemoryIndexEntry>();
  private lastSeq = 0;
  private lastHash: string | null = null;

  constructor(opts: {
    stateDir: string;
    headDir: string;
    publicKeyPem: string;
    privateKeyPem: string;
    historyUnavailable: boolean;
    index: Map<string, MemoryIndexEntry>;
    lastSeq: number;
    lastHash: string | null;
  }) {
    this.stateDir = opts.stateDir;
    this.headDir = opts.headDir;
    this.publicKeyPem = opts.publicKeyPem;
    this.privateKeyPem = opts.privateKeyPem;
    this.historyUnavailable = opts.historyUnavailable;
    this.index = opts.index;
    this.lastSeq = opts.lastSeq;
    this.lastHash = opts.lastHash;
  }

  private async persistHead(seq: number, lastHash: string | null): Promise<void> {
    const payload: MemoryHeadPayload = {
      v: 1,
      stateDirHash: memoryStateDirHash(this.stateDir),
      seq,
      lastHash,
      ts: Date.now(),
    };
    await writeFileDurable(memoryHeadPath(this.stateDir, this.headDir), encodeHeadLine(payload, this.privateKeyPem));
  }

  rememberDecisionSnapshot(_tenantKey: string, _object: MemoryObject): void {}

  lookup(tenantKey: string, id: string): MemoryIndexEntry | undefined {
    return this.index.get(indexKey(tenantKey, id));
  }

  idHeldByTenant(id: string, tenantKey: string): boolean {
    if (!ID_RE.test(id)) return false;
    if (this.index.has(indexKey(tenantKey, id))) return true;
    return this.objectPresent(tenantKey, id);
  }

  idVisibleForOtherTenant(id: string, selfKey: string): boolean {
    if (!ID_RE.test(id)) return false;
    for (const key of this.index.keys()) {
      const sepAt = key.indexOf("|");
      if (sepAt <= 0) continue;
      const tk = key.slice(0, sepAt);
      const storedId = key.slice(sepAt + 1);
      if (tk !== selfKey && storedId === id) return true;
    }
    const tenantsRoot = resolve(this.stateDir, "tenants");
    if (!existsSync(tenantsRoot)) return false;
    let names: string[];
    try {
      names = readdirSync(tenantsRoot);
    } catch {
      return false;
    }
    for (const name of names) {
      if (name === selfKey) continue;
      if (this.objectPresent(name, id)) return true;
    }
    return false;
  }

  objectPresent(tenantKey: string, id: string): boolean {
    const memoryDir = guardedJoin(this.stateDir, "tenants", tenantKey, "memory");
    if (memoryDir === null) return false;
    if (fileExistsUnder(memoryDir, `${id}.json`)) return true;
    return dirHasJson(memoryDir, id);
  }

  verifiedRead(tenantKey: string, id: string): VerifiedMemory {
    if (this.historyUnavailable) {
      return { kind: "integrity", reason: "memory-integrity-history-unavailable" };
    }
    const committed = this.lookup(tenantKey, id);
    if (committed) {
      const path = resolveObjectPath(this.stateDir, committed.objectPath);
      if (path === null) return { kind: "integrity", reason: "memory-integrity-mismatch" };
      let raw: string;
      try {
        raw = readFileSync(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return { kind: "integrity", reason: "memory-integrity-missing" };
        }
        return { kind: "integrity", reason: "memory-integrity-mismatch" };
      }
      const object = parseMemoryObject(raw);
      if (object === null) return { kind: "integrity", reason: "memory-integrity-mismatch" };
      let versionHash: string;
      try {
        versionHash = memoryVersionHash(object);
      } catch {
        return { kind: "integrity", reason: "memory-integrity-mismatch" };
      }
      if (
        object.id !== id ||
        object.tenantKey !== tenantKey ||
        object.revision !== committed.revision ||
        object.versionHash !== versionHash ||
        versionHash !== committed.versionHash
      ) {
        return { kind: "integrity", reason: "memory-integrity-mismatch" };
      }
      return { kind: "ok", object, versionHash };
    }
    if (this.objectPresent(tenantKey, id)) {
      return { kind: "integrity", reason: "memory-integrity-unattested" };
    }
    return { kind: "not-found" };
  }

  async put(opts: {
    tenantKey: string;
    id: string;
    body: unknown;
    source: unknown;
    validFromMs: number;
    validUntilMs: number;
    putRef: string;
    quotaBytes: number;
  }): Promise<
    | { ok: true; id: string; revision: number; versionHash: string }
    | { ok: false; error: "memory-quota" | "memory-integrity-history-unavailable" }
  > {
    if (this.historyUnavailable) {
      return { ok: false, error: "memory-integrity-history-unavailable" };
    }
    const tenantLock = `memory-quota:${resolve(this.stateDir, "tenants", opts.tenantKey, "memory")}`;
    const commitLock = `memory-commits:${storeKey(this.stateDir)}`;
    return withLock(tenantLock, async () => {
      const current = this.lookup(opts.tenantKey, opts.id);
      const revision = current ? current.revision + 1 : 1;
      const versionHash = memoryVersionHash({
        tenantKey: opts.tenantKey,
        id: opts.id,
        revision,
        body: opts.body,
        source: opts.source,
        validFromMs: opts.validFromMs,
        validUntilMs: opts.validUntilMs,
      });
      const object: MemoryObject = {
        id: opts.id,
        revision,
        tenantKey: opts.tenantKey,
        body: opts.body,
        source: opts.source,
        validFromMs: opts.validFromMs,
        validUntilMs: opts.validUntilMs,
        versionHash,
      };
      const objectPath = relativeObjectPath(opts.tenantKey, opts.id, revision);
      const abs = resolveObjectPath(this.stateDir, objectPath);
      if (abs === null) throw new Error("memory-object-path");
      const payload = `${JSON.stringify(object)}\n`;
      const used = await this.currentUsageBytes(opts.tenantKey, opts.id);
      if (used + Buffer.byteLength(payload) > opts.quotaBytes) {
        return { ok: false as const, error: "memory-quota" as const };
      }
      await writeFileDurable(abs, payload);
      await withLock(commitLock, async () => {
        if (this.historyUnavailable) return;
        const commit: MemoryCommitPayload = {
          v: 1,
          seq: this.lastSeq + 1,
          tenantKey: opts.tenantKey,
          id: opts.id,
          revision,
          versionHash,
          objectPath,
          putRef: opts.putRef,
          prevCommitHash: this.lastHash,
          ts: Date.now(),
        };
        const line = `${JSON.stringify({ payload: commit, sig: signPayload(commit, this.privateKeyPem) })}\n`;
        try {
          await appendLineDurable(join(this.stateDir, MEMORY_COMMITS_FILE), line);
        } catch (err) {
          if (err instanceof UncertainAppendError) {
            this.historyUnavailable = true;
            return;
          }
          throw err;
        }
        const nextHash = sha256Canonical(commit);
        try {
          await this.persistHead(commit.seq, nextHash);
          this.lastSeq = commit.seq;
          this.lastHash = nextHash;
          this.index.set(indexKey(opts.tenantKey, opts.id), { revision, versionHash, objectPath });
        } catch {
          this.historyUnavailable = true;
        }
      });
      if (this.historyUnavailable) {
        return { ok: false as const, error: "memory-integrity-history-unavailable" as const };
      }
      if (current) {
        const old = resolveObjectPath(this.stateDir, current.objectPath);
        if (old !== null && old !== abs) {
          try {
            await unlink(old);
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
          }
        }
      }
      return { ok: true as const, id: opts.id, revision, versionHash };
    });
  }

  async reattestLegacy(opts: {
    tenantKey: string;
    id: string;
    body: unknown;
    source: unknown;
    validFromMs: number;
    validUntilMs: number;
    legacyPath: string;
  }): Promise<{ id: string; revision: number; versionHash: string } | { skipped: true }> {
    if (this.historyUnavailable) throw new Error("memory-history-unavailable");
    if (this.lookup(opts.tenantKey, opts.id)) return { skipped: true };
    const result = await this.put({
      tenantKey: opts.tenantKey,
      id: opts.id,
      body: opts.body,
      source: opts.source,
      validFromMs: opts.validFromMs,
      validUntilMs: opts.validUntilMs,
      putRef: "verax.memory.reattest",
      quotaBytes: Number.MAX_SAFE_INTEGER,
    });
    if (!result.ok) throw new Error("memory-quota");
    try {
      await unlink(opts.legacyPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
    return result;
  }

  private async currentUsageBytes(tenantKey: string, excludeId: string): Promise<number> {
    let used = 0;
    for (const [key, entry] of this.index) {
      const sepAt = key.indexOf("|");
      if (sepAt <= 0) continue;
      const tk = key.slice(0, sepAt);
      const id = key.slice(sepAt + 1);
      if (tk !== tenantKey || id === excludeId) continue;
      const path = resolveObjectPath(this.stateDir, entry.objectPath);
      if (path === null) continue;
      try {
        const info = await stat(path);
        if (info.isFile()) used += info.size;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    }
    return used;
  }
}

function openLoadedStore(
  opts: {
    stateDir: string;
    headDir: string;
    publicKeyPem: string;
    privateKeyPem: string;
  },
  loaded: {
    historyUnavailable: boolean;
    index: Map<string, MemoryIndexEntry>;
    lastSeq: number;
    lastHash: string | null;
  },
): MemoryStore {
  const store = new MemoryStore({
    stateDir: resolve(opts.stateDir),
    headDir: opts.headDir,
    publicKeyPem: opts.publicKeyPem,
    privateKeyPem: opts.privateKeyPem,
    historyUnavailable: loaded.historyUnavailable,
    index: loaded.index,
    lastSeq: loaded.lastSeq,
    lastHash: loaded.lastHash,
  });
  return store;
}

function unavailableStore(opts: {
  stateDir: string;
  headDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
}): MemoryStore {
  return openLoadedStore(opts, { historyUnavailable: true, index: new Map(), lastSeq: 0, lastHash: null });
}

function bindHead(
  opts: {
    stateDir: string;
    headDir: string;
    publicKeyPem: string;
    privateKeyPem: string;
  },
  loaded: {
    historyUnavailable: boolean;
    index: Map<string, MemoryIndexEntry>;
    lastSeq: number;
    lastHash: string | null;
    hashBySeq: Map<number, string>;
  },
): MemoryStore {
  if (loaded.historyUnavailable) return unavailableStore(opts);
  const stateDir = resolve(opts.stateDir);
  const headPath = memoryHeadPath(stateDir, opts.headDir);
  const expectedHash = memoryStateDirHash(stateDir);
  const head = readVerifiedHead(headPath, opts.publicKeyPem, expectedHash);
  if (head.kind === "invalid") return unavailableStore(opts);
  if (head.kind === "missing") {
    if (loaded.lastSeq > 0) {
      process.stderr.write(
        `memory-head-missing: the commit chain has ${loaded.lastSeq} lines but no memory head; run "verax memory rehead ${stateDir}" with the body stopped to trust the chain as it is now\n`,
      );
      return unavailableStore(opts);
    }
    persistHeadSync({
      stateDir,
      headDir: opts.headDir,
      privateKeyPem: opts.privateKeyPem,
      seq: loaded.lastSeq,
      lastHash: loaded.lastHash,
    });
    return openLoadedStore(opts, loaded);
  }
  if (loaded.lastSeq < head.payload.seq) return unavailableStore(opts);
  if (head.payload.seq > 0) {
    const atHead = loaded.hashBySeq.get(head.payload.seq);
    if (atHead !== head.payload.lastHash) return unavailableStore(opts);
  }
  if (loaded.lastSeq > head.payload.seq) {
    persistHeadSync({
      stateDir,
      headDir: opts.headDir,
      privateKeyPem: opts.privateKeyPem,
      seq: loaded.lastSeq,
      lastHash: loaded.lastHash,
    });
  }
  return openLoadedStore(opts, loaded);
}

export function publishMemoryStore(store: MemoryStore): MemoryStore {
  stores.set(storeKey(store.stateDir), store);
  return store;
}

function emptyChain(): {
  historyUnavailable: false;
  index: Map<string, MemoryIndexEntry>;
  lastSeq: number;
  lastHash: string | null;
  hashBySeq: Map<number, string>;
} {
  return {
    historyUnavailable: false,
    index: new Map(),
    lastSeq: 0,
    lastHash: null,
    hashBySeq: new Map(),
  };
}

function loadCommitChain(
  stateDir: string,
  publicKeyPem: string,
): {
  historyUnavailable: boolean;
  index: Map<string, MemoryIndexEntry>;
  lastSeq: number;
  lastHash: string | null;
  hashBySeq: Map<number, string>;
} {
  const path = join(stateDir, MEMORY_COMMITS_FILE);
  const unavailable = {
    historyUnavailable: true,
    index: new Map<string, MemoryIndexEntry>(),
    lastSeq: 0,
    lastHash: null as string | null,
    hashBySeq: new Map<number, string>(),
  };
  if (!existsSync(path)) return emptyChain();
  try {
    if (!statSync(path).isFile()) return unavailable;
    const index = new Map<string, MemoryIndexEntry>();
    const hashBySeq = new Map<number, string>();
    let lastSeq = 0;
    let lastHash: string | null = null;
    for (const line of readCommitLines(path)) {
      if (line.trim() === "") continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line) as unknown;
      } catch {
        return unavailable;
      }
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || !closedKeys(parsed, LINE_KEYS)) {
        return unavailable;
      }
      const row = parsed as { payload?: unknown; sig?: unknown };
      if (typeof row.sig !== "string" || !isCommitPayload(row.payload)) {
        return unavailable;
      }
      if (!verifyPayload(row.payload, row.sig, publicKeyPem)) {
        return unavailable;
      }
      if (row.payload.seq !== lastSeq + 1 || row.payload.prevCommitHash !== lastHash) {
        return unavailable;
      }
      if (resolveObjectPath(stateDir, row.payload.objectPath) === null) {
        return unavailable;
      }
      lastSeq = row.payload.seq;
      lastHash = sha256Canonical(row.payload);
      hashBySeq.set(lastSeq, lastHash);
      index.set(indexKey(row.payload.tenantKey, row.payload.id), {
        revision: row.payload.revision,
        versionHash: row.payload.versionHash,
        objectPath: row.payload.objectPath,
      });
    }
    return { historyUnavailable: false, index, lastSeq, lastHash, hashBySeq };
  } catch {
    return unavailable;
  }
}

export function reheadMemoryFromChain(opts: {
  stateDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
  headDir?: string;
}): { ok: true; seq: number; lastHash: string | null } | { ok: false } {
  const loaded = loadCommitChain(opts.stateDir, opts.publicKeyPem);
  if (loaded.historyUnavailable) return { ok: false };
  const stateDir = resolve(opts.stateDir);
  persistHeadSync({
    stateDir,
    headDir: resolveHeadDir(stateDir, undefined, opts.headDir),
    privateKeyPem: opts.privateKeyPem,
    seq: loaded.lastSeq,
    lastHash: loaded.lastHash,
  });
  return { ok: true, seq: loaded.lastSeq, lastHash: loaded.lastHash };
}

export function openMemoryStoreSync(opts: {
  stateDir: string;
  publicKeyPem: string;
  privateKeyPem: string;
  headDir?: string;
}): MemoryStore {
  const bound = {
    stateDir: opts.stateDir,
    headDir: resolveHeadDir(opts.stateDir, undefined, opts.headDir),
    publicKeyPem: opts.publicKeyPem,
    privateKeyPem: opts.privateKeyPem,
  };
  const loaded = loadCommitChain(opts.stateDir, opts.publicKeyPem);
  if (loaded.historyUnavailable) return unavailableStore(bound);
  return bindHead(bound, loaded);
}

export function memoryStoreFor(stateDir: string, keys?: { publicKeyPem: string; privateKeyPem: string }): MemoryStore {
  const existing = stores.get(storeKey(stateDir));
  if (existing) return existing;
  if (!keys) {
    throw new Error("memory-store-unopened");
  }
  return publishMemoryStore(
    openMemoryStoreSync({ stateDir, publicKeyPem: keys.publicKeyPem, privateKeyPem: keys.privateKeyPem }),
  );
}

export function listLegacyMemoryFiles(stateDir: string): Array<{ tenantKey: string; id: string; path: string }> {
  const out: Array<{ tenantKey: string; id: string; path: string }> = [];
  const tenantsRoot = resolve(stateDir, "tenants");
  if (!existsSync(tenantsRoot)) return out;
  let tenants: string[];
  try {
    tenants = readdirSync(tenantsRoot);
  } catch {
    return out;
  }
  for (const tenantKey of tenants) {
    const memoryDir = guardedJoin(tenantsRoot, tenantKey, "memory");
    if (memoryDir === null || !existsSync(memoryDir)) continue;
    let names: string[];
    try {
      names = readdirSync(memoryDir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (!ID_RE.test(id)) continue;
      const path = guardedJoin(memoryDir, name);
      if (path === null) continue;
      try {
        if (!statSync(path).isFile()) continue;
      } catch {
        continue;
      }
      out.push({ tenantKey, id, path });
    }
  }
  return out;
}
