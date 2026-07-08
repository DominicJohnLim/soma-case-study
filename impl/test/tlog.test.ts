import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TransparencyLog,
  leafHash,
  toHex,
  verifyConsistency,
  verifyInclusion,
  verifySignedTreeHead,
} from "../src/tlog.ts";

function leafBytes(i: number): Uint8Array {
  return new TextEncoder().encode(`record-${i}`);
}

function buildLog(n: number): TransparencyLog {
  const log = new TransparencyLog();
  for (let i = 0; i < n; i++) log.append(leafBytes(i));
  return log;
}

test("inclusion proofs verify for every leaf at every tree size up to 20", () => {
  const log = buildLog(20);
  for (let size = 1; size <= 20; size++) {
    const root = log.root(size);
    for (let index = 0; index < size; index++) {
      const proof = log.inclusionProof(index, size);
      const lh = toHex(leafHash(leafBytes(index)));
      assert.equal(
        verifyInclusion(lh, index, size, proof, root),
        true,
        `inclusion must verify: index ${index}, size ${size}`,
      );
    }
  }
});

test("an inclusion proof fails against the wrong leaf, index, or root", () => {
  const log = buildLog(11);
  const size = 11;
  const root = log.root(size);
  const proof = log.inclusionProof(5, size);
  const right = toHex(leafHash(leafBytes(5)));
  const wrongLeaf = toHex(leafHash(new TextEncoder().encode("forged-record")));
  assert.equal(verifyInclusion(wrongLeaf, 5, size, proof, root), false);
  assert.equal(verifyInclusion(right, 6, size, proof, root), false);
  assert.equal(verifyInclusion(right, 5, size, proof, log.root(10)), false);
});

test("consistency proofs verify for every (old, new) size pair up to 16", () => {
  const log = buildLog(16);
  for (let oldSize = 0; oldSize <= 16; oldSize++) {
    for (let newSize = oldSize; newSize <= 16; newSize++) {
      const proof = log.consistencyProof(oldSize, newSize);
      assert.equal(
        verifyConsistency(oldSize, log.root(oldSize), newSize, log.root(newSize), proof),
        true,
        `consistency must verify: ${oldSize} -> ${newSize}`,
      );
    }
  }
});

test("a rewritten leaf breaks consistency with the pre-rewrite root", () => {
  // Yesterday's log, root published (anchored externally).
  const honest = buildLog(8);
  const anchoredRoot = honest.root(8);

  // An insider rebuilds history with entry 3 replaced, then appends more.
  const forked = new TransparencyLog();
  for (let i = 0; i < 8; i++) {
    forked.append(i === 3 ? new TextEncoder().encode("rewritten-record") : leafBytes(i));
  }
  forked.append(leafBytes(8));
  forked.append(leafBytes(9));

  // The forged log cannot produce a consistency proof back to the anchored root.
  const forgedProof = forked.consistencyProof(8, 10);
  assert.equal(verifyConsistency(8, anchoredRoot, 10, forked.root(10), forgedProof), false);

  // Whereas the honest log, extended identically, can.
  honest.append(leafBytes(8));
  honest.append(leafBytes(9));
  const honestProof = honest.consistencyProof(8, 10);
  assert.equal(verifyConsistency(8, anchoredRoot, 10, honest.root(10), honestProof), true);
});

test("signed tree heads verify and reject key substitution", () => {
  const log = buildLog(5);
  const sth = log.signedTreeHead(new Date("2026-07-08T10:00:00Z"));
  assert.equal(verifySignedTreeHead(sth, log.publicKey()), true);
  const other = new TransparencyLog();
  assert.equal(verifySignedTreeHead(sth, other.publicKey()), false);
});
