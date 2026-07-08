// Audit query layer: a graph projection over the records (derived and
// rebuildable), the reverse-BFS lineage walk, and the proof bundle emitter.
// The bundle carries everything an external reviewer needs to verify the
// history without trusting the operator.

import type { AnchorReceipt } from "./anchor.ts";
import type { Certificate } from "./identity.ts";
import { recordLeafBytes, type ProvenanceRecord } from "./record.ts";
import { leafHash, toHex, type SignedTreeHead, type TransparencyLog } from "./tlog.ts";

export interface LoggedRecord {
  record: ProvenanceRecord;
  log_index: number;
}

/**
 * The provenance DAG projection: artifacts and actors as nodes, hash
 * references inside signed records as edges. Rebuildable from the log at
 * any time; nothing here is load-bearing for trust.
 */
export class ProvenanceGraph {
  private readonly byOutput = new Map<string, LoggedRecord>();
  private readonly byStepId = new Map<string, LoggedRecord>();

  add(entry: LoggedRecord): void {
    this.byStepId.set(entry.record.step_id, entry);
    if (entry.record.output !== null) {
      this.byOutput.set(entry.record.output.artifact, entry);
    }
  }

  producerOf(artifact: string): LoggedRecord | undefined {
    return this.byOutput.get(artifact);
  }

  byStep(stepId: string): LoggedRecord | undefined {
    return this.byStepId.get(stepId);
  }

  /**
   * Reverse-BFS from a target artifact along derived-from edges, out to the
   * frontier of external snapshots (records with no inputs). Failed prior
   * attempts ride along via prev_attempt links: history shows what actually
   * happened, including the failures.
   */
  lineage(target: string): LoggedRecord[] {
    const producer = this.producerOf(target);
    if (producer === undefined) {
      throw new Error(`no provenance record produces artifact ${target}`);
    }
    const collected = new Map<string, LoggedRecord>();
    const queue: LoggedRecord[] = [producer];
    while (queue.length > 0) {
      const entry = queue.shift()!;
      if (collected.has(entry.record.step_id)) continue;
      collected.set(entry.record.step_id, entry);
      for (const input of entry.record.inputs) {
        const upstream = this.producerOf(input.artifact);
        if (upstream === undefined) {
          throw new Error(
            `broken lineage: no record produces input ${input.artifact} of ${entry.record.step_id}`,
          );
        }
        queue.push(upstream);
      }
      if (entry.record.prev_attempt !== undefined) {
        const prev = this.byStep(entry.record.prev_attempt);
        if (prev === undefined) {
          throw new Error(
            `broken attempt chain: no record for ${entry.record.prev_attempt}`,
          );
        }
        queue.push(prev);
      }
    }
    return [...collected.values()].sort((a, b) => a.log_index - b.log_index);
  }
}

export interface ProofBundle {
  bundle_version: 1;
  target: string;
  records: Array<{
    record: ProvenanceRecord;
    log_index: number;
    inclusion_proof: string[];
  }>;
  signed_tree_head: SignedTreeHead;
  anchored_tree_head: SignedTreeHead;
  anchor_receipt: AnchorReceipt;
  /** Consistency proof from the anchored head to the bundle head. */
  consistency_proof: string[];
  certificates: Certificate[];
  /** Optional disclosure of artifact bytes (base64) - hashes verify whatever is disclosed. */
  artifacts?: { [address: string]: string };
}

export function buildProofBundle(opts: {
  target: string;
  graph: ProvenanceGraph;
  log: TransparencyLog;
  certificates: Map<string, Certificate>; // by fingerprint
  anchoredTreeHead: SignedTreeHead;
  anchorReceipt: AnchorReceipt;
  now: Date;
  discloseArtifacts?: Map<string, Uint8Array>; // by address
}): ProofBundle {
  const lineage = opts.graph.lineage(opts.target);
  const sth = opts.log.signedTreeHead(opts.now);

  const records = lineage.map((entry) => ({
    record: entry.record,
    log_index: entry.log_index,
    inclusion_proof: opts.log.inclusionProof(entry.log_index, sth.tree_size),
  }));

  const certs = new Map<string, Certificate>();
  for (const entry of lineage) {
    const fp = entry.record.actor.cert_fingerprint;
    const cert = opts.certificates.get(fp);
    if (cert === undefined) {
      throw new Error(`no certificate on file for fingerprint ${fp}`);
    }
    certs.set(fp, cert);
  }

  const bundle: ProofBundle = {
    bundle_version: 1,
    target: opts.target,
    records,
    signed_tree_head: sth,
    anchored_tree_head: opts.anchoredTreeHead,
    anchor_receipt: opts.anchorReceipt,
    consistency_proof: opts.log.consistencyProof(
      opts.anchoredTreeHead.tree_size,
      sth.tree_size,
    ),
    certificates: [...certs.values()],
  };

  if (opts.discloseArtifacts !== undefined) {
    const disclosed: { [address: string]: string } = {};
    for (const [address, bytes] of opts.discloseArtifacts) {
      disclosed[address] = Buffer.from(bytes).toString("base64");
    }
    bundle.artifacts = disclosed;
  }
  return bundle;
}

/** Convenience: the leaf hash a verifier recomputes for a record. */
export function recordLeafHashHex(record: ProvenanceRecord): string {
  return toHex(leafHash(recordLeafBytes(record)));
}
