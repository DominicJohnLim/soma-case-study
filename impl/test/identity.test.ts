import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CertificateAuthority,
  exportPublicKey,
  generateKeys,
  verifyCertificate,
} from "../src/identity.ts";

const T0 = new Date("2026-07-08T09:00:00Z");
const HOUR = 3600 * 1000;

function issueAgentCert(ca: CertificateAuthority, ttlMs = 8 * HOUR) {
  const keys = generateKeys();
  return ca.issue({
    subject: "agent:memo-writer/v2.3.1",
    subjectPublicKey: exportPublicKey(keys.publicKey),
    delegationChain: ["human:jane@soma.vc", "role:memo-agents"],
    notBefore: T0,
    ttlMs,
  });
}

test("a freshly issued cert verifies within its validity window", () => {
  const ca = new CertificateAuthority("ca:soma-org");
  const cert = issueAgentCert(ca);
  assert.deepEqual(verifyCertificate(cert, ca.publicKey(), new Date(T0.getTime() + HOUR)), { ok: true });
});

test("an expired cert is rejected: rotation by expiry, no long-lived secrets", () => {
  const ca = new CertificateAuthority("ca:soma-org");
  const cert = issueAgentCert(ca, 2 * HOUR);
  const later = new Date(T0.getTime() + 3 * HOUR);
  const result = verifyCertificate(cert, ca.publicKey(), later);
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /expired/);
});

test("a cert from an untrusted CA is rejected: impersonation fails", () => {
  const realCa = new CertificateAuthority("ca:soma-org");
  const rogueCa = new CertificateAuthority("ca:soma-org"); // same name, different key
  const forged = issueAgentCert(rogueCa);
  const result = verifyCertificate(forged, realCa.publicKey(), new Date(T0.getTime() + HOUR));
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /not signed by trusted CA/);
});

test("an agent cert must delegate from a human principal", () => {
  const ca = new CertificateAuthority("ca:soma-org");
  const keys = generateKeys();
  const orphan = ca.issue({
    subject: "agent:rogue/v0.0.1",
    subjectPublicKey: exportPublicKey(keys.publicKey),
    delegationChain: ["role:unowned-agents"], // no human at the root
    notBefore: T0,
    ttlMs: HOUR,
  });
  const result = verifyCertificate(orphan, ca.publicKey(), new Date(T0.getTime() + 1000));
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /delegation chain terminating at a human/);
});

test("tampering with any cert field breaks the CA signature", () => {
  const ca = new CertificateAuthority("ca:soma-org");
  const cert = issueAgentCert(ca);
  const tampered = { ...cert, subject: "agent:memo-writer/v9.9.9" };
  const result = verifyCertificate(tampered, ca.publicKey(), new Date(T0.getTime() + HOUR));
  assert.equal(result.ok, false);
});
