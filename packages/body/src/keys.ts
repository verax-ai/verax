import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { EX_CONFIG } from "./config.ts";

export type KeyPair = { privateKeyPem: string; publicKeyPem: string };

export class KeysPartialError extends Error {
  readonly code = EX_CONFIG;
  constructor() {
    super("keys-partial");
    this.name = "KeysPartialError";
  }
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

export function loadOrCreateSigners(stateDir: string): {
  recordSigner: KeyPair;
  effectSigner: KeyPair;
} {
  const dir = join(stateDir, "keys");
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
  if (present === 0) {
    const record = pair();
    const effect = pair();
    writePemAtomic(recPriv, record.privateKeyPem);
    writePemAtomic(recPub, record.publicKeyPem);
    writePemAtomic(effPriv, effect.privateKeyPem);
    writePemAtomic(effPub, effect.publicKeyPem);
    return { recordSigner: record, effectSigner: effect };
  }
  return {
    recordSigner: {
      privateKeyPem: readFileSync(recPriv, "utf8"),
      publicKeyPem: readFileSync(recPub, "utf8"),
    },
    effectSigner: {
      privateKeyPem: readFileSync(effPriv, "utf8"),
      publicKeyPem: readFileSync(effPub, "utf8"),
    },
  };
}
