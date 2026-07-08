// Standalone verifier: checks a proof bundle with ZERO trust in the system
// that produced it. The only trust anchors are the org CA public key (for
// identities) and the TSA public key (for external time anchoring). Everything
// else - log continuity, record integrity, lineage completeness - is verified
// from the math inside the bundle.

import { verifyAnchorReceipt } from "./anchor.ts";
import { sha256 } from "./canonical.ts";
import { certFingerprint, verifyCertificate, type Certificate } from "./identity.ts";
import { verifyRecordSignature } from "./record.ts";
import { verifyConsistency, verifyInclusion, verifySignedTreeHead } from "./tlog.ts";
import { recordLeafHashHex, type ProofBundle } from "./audit.ts";

export interface TrustAnchors {
  ca_public_key: string;
  tsa_public_key: string;
}

export interface VerificationReport {
  ok: boolean;
  checks: string[];
  errors: string[];
}

export function verifyBundle(bundle: ProofBundle, trust: TrustAnchors): VerificationReport {
  const checks: string[] = [];
  const errors: string[] = [];
  const pass = (msg: string) => checks.push(msg);
  const fail = (msg: string) => errors.push(msg);

  try {
    runChecks(bundle, trust, pass, fail);
  } catch (err) {
    fail(`bundle malformed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { ok: errors.length === 0, checks, errors };
}

function runChecks(
  bundle: ProofBundle,
  trust: TrustAnchors,
  pass: (msg: string) => void,
  fail: (msg: string) => void,
): void {
  // 1. Tree heads: both signed by the same log key.
  const sth = bundle.signed_tree_head;
  const anchored = bundle.anchored_tree_head;
  if (anchored.log_public_key !== sth.log_public_key) {
    fail("anchored tree head and bundle tree head name different log keys");
  }
  if (verifySignedTreeHead(sth, sth.log_public_key)) {
    pass(`bundle tree head signature valid (size ${sth.tree_size})`);
  } else {
    fail("bundle tree head signature invalid");
  }
  if (verifySignedTreeHead(anchored, sth.log_public_key)) {
    pass(`anchored tree head signature valid (size ${anchored.tree_size})`);
  } else {
    fail("anchored tree head signature invalid");
  }

  // 2. External anchor: the TSA, not the operator, vouches for this root's existence in time.
  if (
    verifyAnchorReceipt(bundle.anchor_receipt, trust.tsa_public_key) &&
    bundle.anchor_receipt.root === anchored.root &&
    bundle.anchor_receipt.tree_size === anchored.tree_size
  ) {
    pass(`anchor receipt valid: root of size-${anchored.tree_size} log existed by ${bundle.anchor_receipt.anchored_at}`);
  } else {
    fail("anchor receipt invalid or does not match the anchored tree head");
  }

  // 3. Log continuity: the bundle head extends the anchored head append-only.
  if (
    verifyConsistency(
      anchored.tree_size,
      anchored.root,
      sth.tree_size,
      sth.root,
      bundle.consistency_proof,
    )
  ) {
    pass(`consistency proof valid: history since anchor is append-only (${anchored.tree_size} -> ${sth.tree_size})`);
  } else {
    fail("consistency proof invalid: history may have been rewritten since anchoring");
  }

  // 4. Certificates: every cert chains to the trusted CA.
  const certsByFingerprint = new Map<string, Certificate>();
  for (const cert of bundle.certificates) {
    certsByFingerprint.set(certFingerprint(cert), cert);
  }

  // 5. Per-record checks: inclusion in the log, signature under a valid cert.
  const producers = new Map<string, string>(); // artifact -> step_id
  const stepIds = new Set<string>();
  for (const [position, entry] of bundle.records.entries()) {
    try {
      const { record, log_index, inclusion_proof } = entry;
      stepIds.add(record.step_id);
      if (record.output !== null) {
        producers.set(record.output.artifact, record.step_id);
      }

      if (
        verifyInclusion(
          recordLeafHashHex(record),
          log_index,
          sth.tree_size,
          inclusion_proof,
          sth.root,
        )
      ) {
        pass(`record ${record.step_id} is in the log at index ${log_index}`);
      } else {
        fail(`record ${record.step_id}: inclusion proof failed - not provably in the log`);
      }

      const cert = certsByFingerprint.get(record.actor.cert_fingerprint);
      if (cert === undefined) {
        fail(`record ${record.step_id}: no certificate in bundle for its actor`);
        continue;
      }
      const certCheck = verifyCertificate(cert, trust.ca_public_key, new Date(record.timestamps.completed));
      if (!certCheck.ok) {
        fail(`record ${record.step_id}: ${certCheck.reason}`);
        continue;
      }
      const sigCheck = verifyRecordSignature(record, cert);
      if (sigCheck.ok) {
        pass(`record ${record.step_id} signed by ${record.actor.identity}`);
      } else {
        fail(sigCheck.reason);
      }
    } catch (err) {
      fail(`record at bundle position ${position} is malformed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // 6. Lineage closure: the target and every input trace to records in the bundle.
  let lineageClosed = true;
  const failLineage = (msg: string) => {
    lineageClosed = false;
    fail(msg);
  };
  if (!producers.has(bundle.target)) {
    failLineage(`no record in the bundle produces the target artifact ${bundle.target}`);
  } else {
    pass(`target artifact is produced by ${producers.get(bundle.target)}`);
  }
  for (const { record } of bundle.records) {
    for (const input of record.inputs) {
      if (!producers.has(input.artifact)) {
        failLineage(`lineage incomplete: input ${input.role} (${input.artifact}) of ${record.step_id} has no producing record in the bundle`);
      }
    }
    if (record.prev_attempt !== undefined && !stepIds.has(record.prev_attempt)) {
      failLineage(`attempt chain incomplete: ${record.prev_attempt} missing from the bundle`);
    }
  }
  if (lineageClosed) {
    pass("lineage closure verified: every input traces to a record in the bundle");
  }

  // 7. Disclosed artifacts: bytes match their addresses.
  if (bundle.artifacts !== undefined) {
    for (const [address, base64] of Object.entries(bundle.artifacts)) {
      if (sha256(new Uint8Array(Buffer.from(base64, "base64"))) === address) {
        pass(`disclosed artifact ${address.slice(0, 18)}... matches its address`);
      } else {
        fail(`disclosed artifact ${address} does NOT match its bytes - modified after creation`);
      }
    }
  }
}
