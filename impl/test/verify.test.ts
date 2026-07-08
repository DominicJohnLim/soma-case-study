// The adversarial suite: an honest bundle must verify, and each of the four
// tamper scenarios from the design must be caught by the standalone verifier
// using nothing but the bundle and two trusted public keys.

import { test } from "node:test";
import assert from "node:assert/strict";
import { runDemo } from "../src/demo.ts";
import { verifyBundle } from "../src/verify.ts";
import { signRecord } from "../src/record.ts";
import {
  CertificateAuthority,
  certFingerprint,
  exportPublicKey,
  generateKeys,
} from "../src/identity.ts";
import { TransparencyLog } from "../src/tlog.ts";
import type { ProofBundle } from "../src/audit.ts";

function clone<T>(value: T): T {
  return structuredClone(value);
}

test("the honest demo bundle verifies end to end", () => {
  const world = runDemo();
  const report = verifyBundle(world.bundle, world.trust);
  assert.deepEqual(report.errors, []);
  assert.equal(report.ok, true);
  // The demo history includes the recorded failure: attempts are first-class.
  const failed = world.bundle.records.find((r) => r.record.outcome === "failure");
  assert.notEqual(failed, undefined);
});

test("tamper 1: edited artifact bytes are caught", () => {
  const world = runDemo();
  const bundle = clone(world.bundle);
  // The LP receives disclosed bytes; someone doctored the approved memo copy.
  const doctored = Buffer.from("# Investment memo: Company X\nTotally rewritten.").toString("base64");
  bundle.artifacts![world.memoArtifact] = doctored;
  const report = verifyBundle(bundle, world.trust);
  assert.equal(report.ok, false);
  assert.ok(report.errors.some((e) => e.includes("does NOT match its bytes")));
});

test("tamper 2: a forged record signed by a self-issued identity is caught", () => {
  const world = runDemo();
  const bundle = clone(world.bundle);

  // Attacker forges the memo record with different content, signs it with
  // their own key, and self-issues a plausible-looking certificate.
  const rogueCa = new CertificateAuthority("ca:soma-org"); // impostor CA, same name
  const rogueKeys = generateKeys();
  const rogueCert = rogueCa.issue({
    subject: "agent:memo-writer/v2.3.1",
    subjectPublicKey: exportPublicKey(rogueKeys.publicKey),
    delegationChain: ["human:jane@soma.vc", "role:memo-agents"],
    notBefore: new Date("2026-07-08T09:00:00Z"),
    ttlMs: 8 * 3600 * 1000,
  });

  const memoEntry = bundle.records.find((r) => r.record.step_id.includes("step_04"))!;
  const { signature: _drop, ...unsigned } = memoEntry.record;
  const forged = signRecord(
    {
      ...unsigned,
      actor: { ...unsigned.actor, cert_fingerprint: certFingerprint(rogueCert) },
    },
    rogueKeys.privateKey,
  );
  memoEntry.record = forged;
  bundle.certificates.push(rogueCert);

  const report = verifyBundle(bundle, world.trust);
  assert.equal(report.ok, false);
  // Caught twice over: the cert does not chain to the real CA, and the
  // altered record is not in the log.
  assert.ok(report.errors.some((e) => e.includes("not signed by trusted CA")));
  assert.ok(report.errors.some((e) => e.includes("inclusion proof failed")));
});

test("tamper 3: a dropped ancestor breaks lineage closure", () => {
  const world = runDemo();
  const bundle = clone(world.bundle);
  // Hide the news snapshot - pretend the memo came from nowhere questionable.
  bundle.records = bundle.records.filter((r) => !r.record.step_id.includes("step_01"));
  const report = verifyBundle(bundle, world.trust);
  assert.equal(report.ok, false);
  assert.ok(report.errors.some((e) => e.includes("lineage incomplete")));
});

test("tamper 3b: a dropped failed attempt breaks the attempt chain", () => {
  const world = runDemo();
  const bundle = clone(world.bundle);
  // Hide the embarrassing failure; the retry's prev_attempt link exposes it.
  bundle.records = bundle.records.filter((r) => r.record.outcome !== "failure");
  const report = verifyBundle(bundle, world.trust);
  assert.equal(report.ok, false);
  assert.ok(report.errors.some((e) => e.includes("attempt chain incomplete")));
});

test("tamper 4: a rewritten log cannot chain back to the anchored root", () => {
  const world = runDemo();
  const bundle = clone(world.bundle);

  // The operator rebuilds the log with one record replaced, re-signs
  // everything with the real log key... but the anchored root is external.
  const rewritten = new TransparencyLog();
  const originalSize = world.log.size();
  for (let i = 0; i < originalSize; i++) {
    rewritten.append(i === 2 ? Buffer.from("innocuous replacement entry") : world.log.entry(i));
  }
  const newHead = rewritten.signedTreeHead(new Date("2026-07-08T12:00:00.000Z"));

  bundle.signed_tree_head = newHead;
  bundle.consistency_proof = rewritten.consistencyProof(
    bundle.anchored_tree_head.tree_size,
    newHead.tree_size,
  );
  for (const entry of bundle.records) {
    entry.inclusion_proof = rewritten.inclusionProof(entry.log_index, newHead.tree_size);
  }

  const report = verifyBundle(bundle, world.trust);
  assert.equal(report.ok, false);
  // The rewritten history cannot be consistent with the anchored root, and
  // the tree heads now come from different log keys.
  assert.ok(
    report.errors.some(
      (e) => e.includes("history may have been rewritten") || e.includes("different log keys"),
    ),
  );
});

test("the bundle is self-contained: verification uses only trust anchors", () => {
  const world = runDemo();
  // Round-trip through JSON: what an external reviewer would actually receive.
  const wire = JSON.parse(JSON.stringify(world.bundle)) as ProofBundle;
  const report = verifyBundle(wire, world.trust);
  assert.equal(report.ok, true);
});

test("wrong trust anchors reject everything", () => {
  const world = runDemo();
  const otherCa = new CertificateAuthority("ca:someone-else");
  const report = verifyBundle(world.bundle, {
    ca_public_key: otherCa.publicKey(),
    tsa_public_key: world.trust.tsa_public_key,
  });
  assert.equal(report.ok, false);
});
