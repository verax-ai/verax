/**
 * Issues a COSE Sign1 receipt (RFC 9943) over an RFC 9162 inclusion proof for
 * one leaf entry, signed with Ed25519 (COSE alg -8). The payload is detached:
 * it is the tree root the verifier rebuilds from the leaf and the path.
 */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";

import { CborTag, encodeCbor, sign1Structure } from "./cbor.ts";
import type { MerkleLog } from "./merkle.ts";

export type IssuedReceipt = {
  receipt: Buffer;
  treeSize: number;
  leafIndex: number;
  root: Buffer;
};

export function publicKeyPemFromPrivate(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: "spki", format: "pem" }).toString();
}

export function issueReceipt(log: MerkleLog, leafIndex: number, privateKeyPem: string): IssuedReceipt {
  const { treeSize, path, root } = log.proof(leafIndex);
  const protectedBytes = encodeCbor(new Map<unknown, unknown>([[1, -8], [395, 1]]));
  const proofBytes = encodeCbor([treeSize, leafIndex, path]);
  const unprotected = new Map<unknown, unknown>([[396, new Map<unknown, unknown>([[-1, [proofBytes]]])]]);
  const privateKey = createPrivateKey(privateKeyPem);
  const signature = sign(null, sign1Structure(protectedBytes, root), privateKey);
  const receipt = encodeCbor(new CborTag(18, [protectedBytes, unprotected, null, new Uint8Array(signature)]));
  return { receipt, treeSize, leafIndex, root };
}
