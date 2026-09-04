import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export type KeyPair = { privateKeyPem: string; publicKeyPem: string };

function pair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function writePem(path: string, pem: string): void {
  writeFileSync(path, pem, { encoding: "utf8", mode: 0o600 });
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
  if (!existsSync(recPriv) || !existsSync(effPriv)) {
    const record = pair();
    const effect = pair();
    writePem(recPriv, record.privateKeyPem);
    writePem(recPub, record.publicKeyPem);
    writePem(effPriv, effect.privateKeyPem);
    writePem(effPub, effect.publicKeyPem);
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
