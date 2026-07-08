// Transparency log: an append-only Merkle tree over canonical record bytes,
// same construction as Certificate Transparency (RFC 6962 / RFC 9162).
// Inclusion proofs show a record is in the history; consistency proofs show
// today's history extends yesterday's append-only. Signed tree heads are
// anchored externally so insider rewrites after anchoring are mathematically
// evident, not just policy-forbidden.

import { createHash, type KeyObject } from "node:crypto";
import { canonicalBytes, type Json } from "./canonical.ts";
import {
  exportPublicKey,
  generateKeys,
  signBytes,
  verifyBytes,
  type KeyPair,
} from "./identity.ts";

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

function hashBytes(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export function leafHash(leafBytes: Uint8Array): Uint8Array {
  return hashBytes(LEAF_PREFIX, leafBytes);
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return hashBytes(NODE_PREFIX, left, right);
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
}

/** Largest power of two strictly less than n (n >= 2). */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Merkle tree hash over a slice of leaf hashes, per RFC 6962 section 2.1. */
function merkleRoot(leaves: Uint8Array[], start: number, end: number): Uint8Array {
  const n = end - start;
  if (n === 0) return hashBytes(); // sha256 of the empty string
  if (n === 1) return leaves[start]!;
  const k = largestPowerOfTwoBelow(n);
  return nodeHash(merkleRoot(leaves, start, start + k), merkleRoot(leaves, start + k, end));
}

/** Inclusion path for leaf m within [start, end), per RFC 6962 section 2.1.1. */
function inclusionPath(leaves: Uint8Array[], m: number, start: number, end: number): Uint8Array[] {
  const n = end - start;
  if (n <= 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) {
    return [...inclusionPath(leaves, m, start, start + k), merkleRoot(leaves, start + k, end)];
  }
  return [...inclusionPath(leaves, m - k, start + k, end), merkleRoot(leaves, start, start + k)];
}

/** Consistency subproof, per RFC 6962 section 2.1.2. */
function consistencySubproof(
  leaves: Uint8Array[],
  m: number,
  start: number,
  end: number,
  completeSubtree: boolean,
): Uint8Array[] {
  const n = end - start;
  if (m === n) {
    return completeSubtree ? [] : [merkleRoot(leaves, start, end)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    return [
      ...consistencySubproof(leaves, m, start, start + k, completeSubtree),
      merkleRoot(leaves, start + k, end),
    ];
  }
  return [
    ...consistencySubproof(leaves, m - k, start + k, end, false),
    merkleRoot(leaves, start, start + k),
  ];
}

export interface SignedTreeHead {
  tree_size: number;
  root: string; // hex
  timestamp: string; // ISO 8601
  log_public_key: string; // spki base64, self-describing for the verifier
  signature: string;
}

function sthSigningPayload(sth: SignedTreeHead): Uint8Array {
  const { signature: _omitted, ...unsigned } = sth;
  return canonicalBytes(unsigned as unknown as Json);
}

export function verifySignedTreeHead(sth: SignedTreeHead, logPublicKey: string): boolean {
  if (sth.log_public_key !== logPublicKey) return false;
  return verifyBytes(logPublicKey, sthSigningPayload(sth), sth.signature);
}

export class TransparencyLog {
  private readonly leaves: Uint8Array[] = []; // leaf hashes
  private readonly entries: Uint8Array[] = []; // raw leaf bytes, by index
  private readonly keys: KeyPair;

  constructor() {
    this.keys = generateKeys();
  }

  publicKey(): string {
    return exportPublicKey(this.keys.publicKey);
  }

  /** Test-only escape hatch for the log-signing key. */
  unsafePrivateKey(): KeyObject {
    return this.keys.privateKey;
  }

  size(): number {
    return this.leaves.length;
  }

  append(leafBytes: Uint8Array): { index: number; leaf_hash: string } {
    this.entries.push(Uint8Array.from(leafBytes));
    this.leaves.push(leafHash(leafBytes));
    return { index: this.leaves.length - 1, leaf_hash: toHex(this.leaves[this.leaves.length - 1]!) };
  }

  entry(index: number): Uint8Array {
    const bytes = this.entries[index];
    if (bytes === undefined) throw new RangeError(`no log entry at index ${index}`);
    return Uint8Array.from(bytes);
  }

  root(treeSize: number = this.size()): string {
    if (treeSize < 0 || treeSize > this.size()) throw new RangeError(`bad tree size ${treeSize}`);
    return toHex(merkleRoot(this.leaves, 0, treeSize));
  }

  signedTreeHead(now: Date, treeSize: number = this.size()): SignedTreeHead {
    const unsigned: Omit<SignedTreeHead, "signature"> = {
      tree_size: treeSize,
      root: this.root(treeSize),
      timestamp: now.toISOString(),
      log_public_key: this.publicKey(),
    };
    const signature = signBytes(this.keys.privateKey, canonicalBytes(unsigned as unknown as Json));
    return { ...unsigned, signature };
  }

  inclusionProof(index: number, treeSize: number = this.size()): string[] {
    if (index < 0 || index >= treeSize || treeSize > this.size()) {
      throw new RangeError(`bad inclusion proof request: index ${index}, size ${treeSize}`);
    }
    return inclusionPath(this.leaves, index, 0, treeSize).map(toHex);
  }

  consistencyProof(oldSize: number, newSize: number = this.size()): string[] {
    if (oldSize < 0 || oldSize > newSize || newSize > this.size()) {
      throw new RangeError(`bad consistency proof request: ${oldSize} -> ${newSize}`);
    }
    if (oldSize === 0 || oldSize === newSize) return [];
    return consistencySubproof(this.leaves, oldSize, 0, newSize, true).map(toHex);
  }
}

/**
 * Verify an inclusion proof, per RFC 9162 section 2.1.3.2.
 * Pure function: usable by the standalone verifier with no log access.
 */
export function verifyInclusion(
  leafHashHex: string,
  index: number,
  treeSize: number,
  proofHex: string[],
  rootHex: string,
): boolean {
  if (index < 0 || index >= treeSize) return false;
  let fn = index;
  let sn = treeSize - 1;
  let r = fromHex(leafHashHex);
  for (const pHex of proofHex) {
    if (sn === 0) return false;
    const p = fromHex(pHex);
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && equal(r, fromHex(rootHex));
}

/**
 * Verify a consistency proof, per RFC 9162 section 2.1.4.2.
 * Pure function: usable by the standalone verifier with no log access.
 */
export function verifyConsistency(
  oldSize: number,
  oldRootHex: string,
  newSize: number,
  newRootHex: string,
  proofHex: string[],
): boolean {
  if (oldSize < 0 || oldSize > newSize) return false;
  if (oldSize === newSize) return proofHex.length === 0 && oldRootHex === newRootHex;
  if (oldSize === 0) return proofHex.length === 0; // empty log is a prefix of anything
  const proof = proofHex.map(fromHex);

  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let i = 0;
  let fr: Uint8Array;
  let sr: Uint8Array;
  if (fn !== 0) {
    const first = proof[i++];
    if (first === undefined) return false;
    fr = first;
    sr = first;
  } else {
    fr = fromHex(oldRootHex);
    sr = fromHex(oldRootHex);
  }

  for (; i < proof.length; i++) {
    const p = proof[i]!;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(p, fr);
      sr = nodeHash(p, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = nodeHash(sr, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && equal(fr, fromHex(oldRootHex)) && equal(sr, fromHex(newRootHex));
}
