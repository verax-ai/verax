import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { EX_CONFIG } from "./config.ts";

export type KeyPair = { privateKeyPem: string; publicKeyPem: string };

export class KeysPartialError extends Error {
  readonly code = EX_CONFIG;
  constructor() {
    super("keys-partial");
    this.name = "KeysPartialError";
  }
}

export class KeyAlgorithmError extends Error {
  readonly code = EX_CONFIG;
  constructor(which: string) {
    super(`${which} public key is not ed25519`);
    this.name = "KeyAlgorithmError";
  }
}

/** A public key this process will verify with. Anything but Ed25519 stops start. */
export function assertEd25519PublicKey(pem: string, which: string): void {
  let type: string | undefined;
  try {
    type = createPublicKey(pem).asymmetricKeyType;
  } catch {
    throw new KeyAlgorithmError(which);
  }
  if (type !== "ed25519") throw new KeyAlgorithmError(which);
}

function pair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function writePemAtomic(path: string, pem: string): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, pem, { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, path);
}

/** Keys live here. Default is `<stateDir>/keys`; `listen` / `createBodyServices` may pass `keysDir`. */
export function resolveKeysDir(stateDir: string, keysDir?: string | null): string {
  const explicit = keysDir?.trim();
  if (explicit) return explicit;
  return join(stateDir, "keys");
}

/** Memory head lives here. `VERAX_MEMORY_HEAD_DIR` wins; otherwise the keys directory. */
export function resolveHeadDir(stateDir: string, keysDir?: string | null, headDir?: string | null): string {
  const explicit = headDir?.trim();
  if (explicit) return explicit;
  return resolveKeysDir(stateDir, keysDir);
}

/** Physical path for custody and head identity: junctions resolved, win32 case-folded. */
export function canonicalizeDirPath(dir: string): string {
  const abs = resolve(dir);
  let real = abs;
  try {
    real = realpathSync.native(abs);
  } catch {
    // Missing leaf: realpath the nearest existing ancestor, then reattach the rest.
    const missing: string[] = [];
    let cursor = abs;
    for (;;) {
      const parent = dirname(cursor);
      if (parent === cursor) break;
      missing.unshift(basename(cursor));
      try {
        real = join(realpathSync.native(parent), ...missing);
        break;
      } catch {
        cursor = parent;
      }
    }
  }
  return process.platform === "win32" ? real.toLowerCase() : real;
}

/** True when `inner` is `root` or a path under it. */
export function pathIsInsideDir(root: string, inner: string): boolean {
  const rootAbs = canonicalizeDirPath(root);
  const innerAbs = canonicalizeDirPath(inner);
  if (innerAbs === rootAbs) return true;
  const rel = relative(rootAbs, innerAbs);
  if (rel === "") return true;
  if (isAbsolute(rel)) return false;
  return rel !== ".." && !rel.startsWith(`..${sep}`);
}

export function loadOrCreateSigners(stateDir: string, keysDir?: string | null): {
  recordSigner: KeyPair;
  effectSigner: KeyPair;
} {
  const dir = resolveKeysDir(stateDir, keysDir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const recPriv = join(dir, "record.private.pem");
  const recPub = join(dir, "record.public.pem");
  const effPriv = join(dir, "effect.private.pem");
  const effPub = join(dir, "effect.public.pem");
  const paths = [recPriv, recPub, effPriv, effPub];
  const present = paths.filter((p) => existsSync(p)).length;
  if (present !== 0 && present !== 4) {
    throw new KeysPartialError();
  }
  const loaded =
    present === 0
      ? (() => {
          const record = pair();
          const effect = pair();
          writePemAtomic(recPriv, record.privateKeyPem);
          writePemAtomic(recPub, record.publicKeyPem);
          writePemAtomic(effPriv, effect.privateKeyPem);
          writePemAtomic(effPub, effect.publicKeyPem);
          return { recordSigner: record, effectSigner: effect };
        })()
      : {
          recordSigner: {
            privateKeyPem: readFileSync(recPriv, "utf8"),
            publicKeyPem: readFileSync(recPub, "utf8"),
          },
          effectSigner: {
            privateKeyPem: readFileSync(effPriv, "utf8"),
            publicKeyPem: readFileSync(effPub, "utf8"),
          },
        };
  assertEd25519PublicKey(loaded.recordSigner.publicKeyPem, "record");
  assertEd25519PublicKey(loaded.effectSigner.publicKeyPem, "effect");
  return loaded;
}

function publicKeyDer(pem: string): Buffer {
  return createPublicKey(pem).export({ type: "spki", format: "der" }) as Buffer;
}

function publicKeyDerFromPrivate(pem: string): Buffer {
  return createPublicKey(createPrivateKey(pem)).export({ type: "spki", format: "der" }) as Buffer;
}

function assertSignerMatchesPublicKey(publicKeyPem: string, privateKeyPem: string): void {
  if (!publicKeyDer(publicKeyPem).equals(publicKeyDerFromPrivate(privateKeyPem))) {
    throw new Error("record-public-key-mismatch");
  }
}

function resolveTrustPublicKey(opts: {
  stateDir: string;
  keysDir?: string;
  recordSigner: KeyPair;
}): string {
  const explicit = opts.keysDir?.trim();
  if (!explicit) {
    assertSignerMatchesPublicKey(opts.recordSigner.publicKeyPem, opts.recordSigner.privateKeyPem);
    return opts.recordSigner.publicKeyPem;
  }
  const trustPub = join(resolveKeysDir(opts.stateDir, explicit), "record.public.pem");
  if (!existsSync(trustPub)) {
    throw new Error(`record-public-key-missing:${trustPub}`);
  }
  const publicKeyPem = readFileSync(trustPub, "utf8");
  assertEd25519PublicKey(publicKeyPem, "record");
  assertSignerMatchesPublicKey(publicKeyPem, opts.recordSigner.privateKeyPem);
  return publicKeyPem;
}

function assertRecordPubkeyPin(publicKeyPem: string): void {
  const pin = process.env.VERAX_RECORD_PUBKEY_PIN?.trim() ?? "";
  if (pin === "") return;
  let pinnedDer: Buffer;
  try {
    pinnedDer = publicKeyDer(pin);
  } catch {
    throw new Error("record-pubkey-pin-mismatch");
  }
  if (!pinnedDer.equals(publicKeyDer(publicKeyPem))) {
    throw new Error("record-pubkey-pin-mismatch");
  }
}

/**
 * Record public/private match plus `VERAX_RECORD_PUBKEY_PIN` (PEM).
 * Body open, rehead, and reattest call this before any head write.
 */
export function assertRecordKeyTrust(opts: {
  stateDir: string;
  keysDir?: string;
  recordSigner: KeyPair;
}): string {
  const publicKeyPem = resolveTrustPublicKey(opts);
  assertRecordPubkeyPin(publicKeyPem);
  return publicKeyPem;
}
