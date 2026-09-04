import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export function loadPem(name: string): string {
  const raw = readFileSync(join(here, "fixtures", "keys", name), "utf8");
  return raw
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("#"))
    .join("\n");
}

export const RECORD_SIGNER = {
  privateKeyPem: loadPem("record-signer.TEST-KEY-NOT-A-SECRET.pem"),
  publicKeyPem: loadPem("record-public.TEST-KEY-NOT-A-SECRET.pem"),
};

export const EFFECT_SIGNER = {
  privateKeyPem: loadPem("effect-signer.TEST-KEY-NOT-A-SECRET.pem"),
  publicKeyPem: loadPem("effect-public.TEST-KEY-NOT-A-SECRET.pem"),
};

export function tickingNow(start = 10, step = 10): () => number {
  let n = start;
  return () => {
    const v = n;
    n += step;
    return v;
  };
}

export function queuedNonce(values: readonly string[]): () => string {
  const q = [...values];
  return () => {
    const next = q.shift();
    if (next === undefined) throw new Error("nonce-exhausted");
    return next;
  };
}
