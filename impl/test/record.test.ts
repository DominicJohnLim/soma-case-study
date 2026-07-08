import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CertificateAuthority,
  certFingerprint,
  exportPublicKey,
  generateKeys,
} from "../src/identity.ts";
import {
  signRecord,
  verifyRecordSignature,
  type ProvenanceRecord,
  type UnsignedRecord,
} from "../src/record.ts";

function makeSignedRecord() {
  const ca = new CertificateAuthority("ca:soma-org");
  const keys = generateKeys();
  const cert = ca.issue({
    subject: "agent:memo-writer/v2.3.1",
    subjectPublicKey: exportPublicKey(keys.publicKey),
    delegationChain: ["human:jane@soma.vc", "role:memo-agents"],
    notBefore: new Date("2026-07-08T09:00:00Z"),
    ttlMs: 8 * 3600 * 1000,
  });
  const unsigned: UnsignedRecord = {
    record_version: 1,
    step_id: "wf_8f2e/step_04/attempt_02",
    workflow_id: "wf_8f2e",
    action_type: "llm_generate",
    outcome: "success",
    actor: {
      identity: "agent:memo-writer/v2.3.1",
      cert_fingerprint: certFingerprint(cert),
      delegation_chain: cert.delegation_chain,
    },
    inputs: [{ artifact: "sha256:" + "a".repeat(64), role: "founder_profile" }],
    output: { artifact: "sha256:" + "b".repeat(64), media_type: "text/markdown" },
    nondeterminism: {
      model: "provider/frontier-model@2026-05",
      prompt_template: "sha256:" + "c".repeat(64),
      rendered_prompt: "sha256:" + "d".repeat(64),
      params: { temperature: "0.7", max_tokens: 4096 },
      provider_request_id: "req_abc123",
    },
    timestamps: { started: "2026-07-08T09:01:00Z", completed: "2026-07-08T09:01:30Z" },
    prev_attempt: "wf_8f2e/step_04/attempt_01",
  };
  return { record: signRecord(unsigned, keys.privateKey), cert, ca };
}

test("a signed record verifies against its certificate", () => {
  const { record, cert } = makeSignedRecord();
  assert.deepEqual(verifyRecordSignature(record, cert), { ok: true });
});

test("mutating any field breaks the signature", () => {
  const { record, cert } = makeSignedRecord();
  const mutations: Array<Partial<ProvenanceRecord>> = [
    { step_id: "wf_8f2e/step_04/attempt_03" },
    { outcome: "failure" },
    { output: { artifact: "sha256:" + "e".repeat(64), media_type: "text/markdown" } },
    { inputs: [] },
    { actor: { ...record.actor, identity: "agent:memo-writer/v9.9.9" } },
    { timestamps: { started: record.timestamps.started, completed: "2026-07-08T23:59:59Z" } },
  ];
  for (const mutation of mutations) {
    const tampered = { ...record, ...mutation } as ProvenanceRecord;
    const result = verifyRecordSignature(tampered, cert);
    assert.equal(result.ok, false, `mutation ${JSON.stringify(Object.keys(mutation))} must break the signature`);
  }
});

test("a substituted certificate is rejected by fingerprint, even if valid", () => {
  const { record } = makeSignedRecord();
  const { cert: otherCert } = makeSignedRecord(); // different keypair and CA
  const result = verifyRecordSignature(record, otherCert);
  assert.equal(result.ok, false);
  assert.match((result as { reason: string }).reason, /fingerprint mismatch/);
});
