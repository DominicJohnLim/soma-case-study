// The provenance record: the deterministic envelope around every step attempt.
// Hash the inputs going in, hash the output coming out, sign the pair with the
// actor's identity. Non-determinism stays contained inside the step; everything
// at the boundary is exact, attributable, and permanent.

import { canonicalBytes, sha256Canonical, signingPayload, type Json } from "./canonical.ts";
import {
  certFingerprint,
  signBytes,
  verifyBytes,
  type Certificate,
} from "./identity.ts";
import type { KeyObject } from "node:crypto";

export type ActionType =
  | "llm_generate"
  | "api_fetch"
  | "db_write"
  | "human_edit"
  | "human_approval";

export interface ArtifactRef {
  artifact: string; // "sha256:<hex>" address in the CAS
  role: string; // "founder_profile", "market_data_snapshot", ...
}

/** The determinism boundary, reified: everything that parameterized an AI call. */
export interface NondeterminismBlock {
  model: string;
  prompt_template: string; // sha256 of the template
  rendered_prompt: string; // sha256 of the fully rendered prompt
  params: { [key: string]: Json };
  provider_request_id: string;
}

export interface ProvenanceRecord {
  record_version: 1;
  step_id: string; // "wf_8f2e/step_04/attempt_02"
  workflow_id: string;
  action_type: ActionType;
  outcome: "success" | "failure";
  actor: {
    identity: string;
    cert_fingerprint: string;
    delegation_chain: string[];
  };
  inputs: ArtifactRef[];
  /** null when the attempt failed before producing an artifact. */
  output: { artifact: string; media_type: string } | null;
  nondeterminism?: NondeterminismBlock;
  timestamps: { started: string; completed: string };
  prev_attempt?: string;
  error?: string; // short operator-facing note on failed attempts
  signature: string; // actor signature over the canonical record minus this field
}

export type UnsignedRecord = Omit<ProvenanceRecord, "signature">;

export function signRecord(
  unsigned: UnsignedRecord,
  actorPrivateKey: KeyObject,
): ProvenanceRecord {
  const signature = signBytes(actorPrivateKey, signingPayload(unsigned));
  return { ...unsigned, signature };
}

/**
 * Verify a record's signature against the certificate it names.
 * The cert must actually be the one fingerprinted inside the record,
 * so a valid-but-different cert cannot be substituted, and the claimed
 * actor identity and delegation chain must be the ones the CA certified,
 * so a valid key holder cannot attribute its records to someone else.
 */
export function verifyRecordSignature(
  record: ProvenanceRecord,
  cert: Certificate,
): { ok: true } | { ok: false; reason: string } {
  if (certFingerprint(cert) !== record.actor.cert_fingerprint) {
    return {
      ok: false,
      reason: `record ${record.step_id}: certificate fingerprint mismatch`,
    };
  }
  if (record.actor.identity !== cert.subject) {
    return {
      ok: false,
      reason: `record ${record.step_id}: actor identity ${record.actor.identity} does not match certificate subject ${cert.subject}`,
    };
  }
  if (
    record.actor.delegation_chain.length !== cert.delegation_chain.length ||
    record.actor.delegation_chain.some((p, i) => p !== cert.delegation_chain[i])
  ) {
    return {
      ok: false,
      reason: `record ${record.step_id}: actor delegation chain does not match certificate delegation chain`,
    };
  }
  if (!verifyBytes(cert.public_key, signingPayload(record), record.signature)) {
    return {
      ok: false,
      reason: `record ${record.step_id}: signature does not verify under ${cert.subject}`,
    };
  }
  return { ok: true };
}

/** The log stores canonical record bytes; this is the one true leaf encoding. */
export function recordLeafBytes(record: ProvenanceRecord): Uint8Array {
  return canonicalBytes(record as unknown as Json);
}

export function recordHash(record: ProvenanceRecord): string {
  return sha256Canonical(record as unknown as Json);
}
