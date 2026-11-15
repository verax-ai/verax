/**
 * RFC 9162 SHA-256 Merkle tree over leaf entries. A leaf hashes as
 * SHA-256(0x00 || entry); an interior node as SHA-256(0x01 || left || right).
 * The tree-head and inclusion path follow RFC 9162 §2.1.1 / §2.1.3.2.
 */
import { createHash } from "node:crypto";

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();

export function leafHash(entry: Uint8Array): Buffer {
  return sha256(Buffer.of(0x00), entry);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  return sha256(Buffer.of(0x01), left, right);
}

/** Largest power of two strictly less than `n` (n >= 2). */
function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle tree hash of `leafHashes` (already leaf-hashed). Empty → SHA-256(""). */
export function treeHead(leafHashes: readonly Uint8Array[]): Buffer {
  if (leafHashes.length === 0) return sha256();
  if (leafHashes.length === 1) return Buffer.from(leafHashes[0]!);
  const k = largestPowerOfTwoLessThan(leafHashes.length);
  return nodeHash(treeHead(leafHashes.slice(0, k)), treeHead(leafHashes.slice(k)));
}

/**
 * Inclusion path for `leafIndex` in a tree of these leaf hashes. Each step is
 * the sibling the verifier pairs with the running hash (RFC 9162 §2.1.3.2).
 */
export function inclusionPath(leafIndex: number, leafHashes: readonly Uint8Array[]): Buffer[] {
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error("inclusion-index");
  }
  const path: Buffer[] = [];
  const walk = (index: number, leaves: readonly Uint8Array[]): Buffer => {
    if (leaves.length === 1) return Buffer.from(leaves[0]!);
    const k = largestPowerOfTwoLessThan(leaves.length);
    if (index < k) {
      const left = walk(index, leaves.slice(0, k));
      const right = treeHead(leaves.slice(k));
      path.push(Buffer.from(right));
      return nodeHash(left, right);
    }
    const left = treeHead(leaves.slice(0, k));
    const right = walk(index - k, leaves.slice(k));
    path.push(Buffer.from(left));
    return nodeHash(left, right);
  };
  walk(leafIndex, leafHashes);
  return path;
}

export type LogLeaf = {
  /** 32-byte leaf entry (the digest the register route commits to). */
  entry: Buffer;
  ownerId: string;
  atMs: number;
};

/** In-memory RFC 9162 log rebuilt from the append-only store. */
export class MerkleLog {
  private readonly leaves: LogLeaf[] = [];
  private readonly hashes: Buffer[] = [];

  get size(): number {
    return this.leaves.length;
  }

  leafAt(index: number): LogLeaf {
    const leaf = this.leaves[index];
    if (!leaf) throw new Error("leaf-index");
    return leaf;
  }

  /** First leaf index for this owner and entry, or -1. */
  findLeaf(ownerId: string, entryHex: string): number {
    for (let i = 0; i < this.leaves.length; i += 1) {
      const leaf = this.leaves[i]!;
      if (leaf.ownerId === ownerId && leaf.entry.toString("hex") === entryHex) return i;
    }
    return -1;
  }

  append(leaf: LogLeaf): number {
    if (leaf.entry.length !== 32) throw new Error("leaf-entry-size");
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.hashes.push(leafHash(leaf.entry));
    return index;
  }

  root(): Buffer {
    return treeHead(this.hashes);
  }

  proof(leafIndex: number): { treeSize: number; leafIndex: number; path: Buffer[]; root: Buffer } {
    const treeSize = this.hashes.length;
    const path = inclusionPath(leafIndex, this.hashes);
    return { treeSize, leafIndex, path, root: treeHead(this.hashes) };
  }
}
