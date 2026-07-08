// End-to-end demo: one memo, ingest to approval, then the LP audit question.
//
//   news fetch -> financials fetch -> founder profile (attempt 1 fails,
//   attempt 2 succeeds) -> memo draft -> partner edit -> partner approval
//
// Then: "Show me every action and data source that contributed to the decision
// to invest in Company X" - answered with a proof bundle a standalone verifier
// checks without trusting anything that produced it.
//
// Agents are simulated. That is the point: the envelope does not care what
// happens inside the step.

import { randomUUID, type KeyObject } from "node:crypto";
import { TimestampAuthority } from "./anchor.ts";
import { buildProofBundle, ProvenanceGraph } from "./audit.ts";
import { sha256 } from "./canonical.ts";
import { ContentStore } from "./cas.ts";
import {
  CertificateAuthority,
  certFingerprint,
  exportPublicKey,
  generateKeys,
  type Certificate,
} from "./identity.ts";
import {
  recordLeafBytes,
  signRecord,
  type ActionType,
  type ArtifactRef,
  type NondeterminismBlock,
  type ProvenanceRecord,
  type UnsignedRecord,
} from "./record.ts";
import { TransparencyLog } from "./tlog.ts";
import { verifyBundle, type TrustAnchors } from "./verify.ts";
import type { ProofBundle } from "./audit.ts";

/** Deterministic demo clock: fixed start, one second per tick. */
class SimClock {
  private t: number;
  constructor(startIso: string) {
    this.t = new Date(startIso).getTime();
  }
  tick(ms = 1000): Date {
    this.t += ms;
    return new Date(this.t);
  }
  now(): Date {
    return new Date(this.t);
  }
}

interface Actor {
  identity: string;
  cert: Certificate;
  fingerprint: string;
  privateKey: KeyObject;
}

export interface DemoWorld {
  store: ContentStore;
  log: TransparencyLog;
  graph: ProvenanceGraph;
  ca: CertificateAuthority;
  tsa: TimestampAuthority;
  certificates: Map<string, Certificate>;
  trust: TrustAnchors;
  approvalArtifact: string;
  memoArtifact: string;
  bundle: ProofBundle;
  records: ProvenanceRecord[];
}

function makeActor(
  ca: CertificateAuthority,
  identity: string,
  delegationChain: string[],
  notBefore: Date,
  ttlMs: number,
): Actor {
  const keys = generateKeys();
  const cert = ca.issue({
    subject: identity,
    subjectPublicKey: exportPublicKey(keys.publicKey),
    delegationChain,
    notBefore,
    ttlMs,
  });
  return { identity, cert, fingerprint: certFingerprint(cert), privateKey: keys.privateKey };
}

/** Build the full demo world: run the workflow, anchor, emit the LP bundle. */
export function runDemo(): DemoWorld {
  const clock = new SimClock("2026-07-08T09:00:00.000Z");
  const store = new ContentStore();
  const log = new TransparencyLog();
  const graph = new ProvenanceGraph();
  const ca = new CertificateAuthority("ca:soma-org");
  const tsa = new TimestampAuthority("tsa:external-notary");
  const certificates = new Map<string, Certificate>();
  const records: ProvenanceRecord[] = [];
  const workflowId = "wf_8f2e";

  // Short-lived certs: hours, not months. Humans authenticate through SSO and
  // hold hardware-backed keys; agent instances chain to a human principal.
  const certStart = clock.now();
  const dayMs = 8 * 3600 * 1000;
  const sourcing = makeActor(ca, "agent:sourcing/v1.4.0", ["human:jane@soma.vc", "role:sourcing-agents"], certStart, dayMs);
  const enricher = makeActor(ca, "agent:enrichment/v2.1.3", ["human:jane@soma.vc", "role:enrichment-agents"], certStart, dayMs);
  const memoWriter = makeActor(ca, "agent:memo-writer/v2.3.1", ["human:jane@soma.vc", "role:memo-agents"], certStart, dayMs);
  const jane = makeActor(ca, "human:jane@soma.vc", [], certStart, dayMs);
  for (const a of [sourcing, enricher, memoWriter, jane]) {
    certificates.set(a.fingerprint, a.cert);
  }

  function emit(opts: {
    actor: Actor;
    stepId: string;
    actionType: ActionType;
    outcome: "success" | "failure";
    inputs: ArtifactRef[];
    outputText: string | null;
    mediaType?: string;
    nondeterminism?: NondeterminismBlock;
    prevAttempt?: string;
    error?: string;
  }): ProvenanceRecord {
    const started = clock.tick().toISOString();
    const completed = clock.tick().toISOString();
    let output: ProvenanceRecord["output"] = null;
    if (opts.outputText !== null) {
      output = {
        artifact: store.putText(opts.outputText),
        media_type: opts.mediaType ?? "text/markdown",
      };
    }
    const unsigned: UnsignedRecord = {
      record_version: 1,
      step_id: opts.stepId,
      workflow_id: workflowId,
      action_type: opts.actionType,
      outcome: opts.outcome,
      actor: {
        identity: opts.actor.identity,
        cert_fingerprint: opts.actor.fingerprint,
        delegation_chain: opts.actor.cert.delegation_chain,
      },
      inputs: opts.inputs,
      output,
      timestamps: { started, completed },
      ...(opts.nondeterminism !== undefined ? { nondeterminism: opts.nondeterminism } : {}),
      ...(opts.prevAttempt !== undefined ? { prev_attempt: opts.prevAttempt } : {}),
      ...(opts.error !== undefined ? { error: opts.error } : {}),
    };
    const record = signRecord(unsigned, opts.actor.privateKey);
    const { index } = log.append(recordLeafBytes(record));
    graph.add({ record, log_index: index });
    records.push(record);
    return record;
  }

  // Step 1-2: ingestion. Raw response bytes snapshotted at the earliest
  // possible boundary; the records have no inputs - they ARE the frontier.
  const news = emit({
    actor: sourcing,
    stepId: `${workflowId}/step_01/attempt_01`,
    actionType: "api_fetch",
    outcome: "success",
    inputs: [],
    outputText:
      "SNAPSHOT https://technews.example/companyx-series-a fetched 2026-07-08T09:00Z\n" +
      "Company X raises $12M Series A to automate freight brokerage...",
    mediaType: "application/http-snapshot",
  });
  const financials = emit({
    actor: sourcing,
    stepId: `${workflowId}/step_02/attempt_01`,
    actionType: "api_fetch",
    outcome: "success",
    inputs: [],
    outputText:
      'SNAPSHOT https://finapi.example/v2/companies/company-x fetched 2026-07-08T09:00Z\n' +
      '{"arr_usd": 1800000, "growth_yoy": 3.1, "burn_monthly_usd": 250000}',
    mediaType: "application/http-snapshot",
  });

  const profileInputs: ArtifactRef[] = [
    { artifact: news.output!.artifact, role: "news_snapshot" },
    { artifact: financials.output!.artifact, role: "market_data_snapshot" },
  ];

  // Step 3, attempt 1: the LLM call times out. The failure is recorded, not
  // erased - attempts are first-class history.
  const failedAttempt = emit({
    actor: enricher,
    stepId: `${workflowId}/step_03/attempt_01`,
    actionType: "llm_generate",
    outcome: "failure",
    inputs: profileInputs,
    outputText: null,
    error: "provider timeout after 60s",
    nondeterminism: {
      model: "provider/frontier-model@2026-05",
      prompt_template: sha256("founder-profile-template-v7"),
      rendered_prompt: sha256("rendered:founder-profile:company-x:attempt1"),
      params: { temperature: "0.7", max_tokens: 4096 },
      provider_request_id: `req_${randomUUID().slice(0, 8)}`,
    },
  });

  // Step 3, attempt 2: retry succeeds. Same inputs, linked to the failure.
  const profile = emit({
    actor: enricher,
    stepId: `${workflowId}/step_03/attempt_02`,
    actionType: "llm_generate",
    outcome: "success",
    inputs: profileInputs,
    outputText:
      "# Founder profile: Company X\nCEO previously scaled logistics ops at BigFreight; " +
      "technical cofounder ex-mapping infra. ARR $1.8M growing 3.1x YoY.",
    prevAttempt: failedAttempt.step_id,
    nondeterminism: {
      model: "provider/frontier-model@2026-05",
      prompt_template: sha256("founder-profile-template-v7"),
      rendered_prompt: sha256("rendered:founder-profile:company-x:attempt2"),
      params: { temperature: "0.7", max_tokens: 4096 },
      provider_request_id: `req_${randomUUID().slice(0, 8)}`,
    },
  });

  // Step 4: the memo agent consumes the profile and the raw snapshots.
  const memoDraft = emit({
    actor: memoWriter,
    stepId: `${workflowId}/step_04/attempt_01`,
    actionType: "llm_generate",
    outcome: "success",
    inputs: [
      { artifact: profile.output!.artifact, role: "founder_profile" },
      { artifact: financials.output!.artifact, role: "market_data_snapshot" },
    ],
    outputText:
      "# Investment memo: Company X\nThesis: vertical AI for freight brokerage. " +
      "Strong founder-market fit, $1.8M ARR at 3.1x. Recommend proceeding to IC.",
    nondeterminism: {
      model: "provider/frontier-model@2026-05",
      prompt_template: sha256("memo-template-v3"),
      rendered_prompt: sha256("rendered:memo:company-x"),
      params: { temperature: "0.4", max_tokens: 8192 },
      provider_request_id: `req_${randomUUID().slice(0, 8)}`,
    },
  });

  // Step 5: a partner edits the memo. Edits never overwrite: the edit is a new
  // artifact whose record lists the prior memo as input and a human as actor.
  const memoFinal = emit({
    actor: jane,
    stepId: `${workflowId}/step_05/attempt_01`,
    actionType: "human_edit",
    outcome: "success",
    inputs: [{ artifact: memoDraft.output!.artifact, role: "memo_draft" }],
    outputText:
      "# Investment memo: Company X (partner-reviewed)\nThesis: vertical AI for freight " +
      "brokerage. Strong founder-market fit, $1.8M ARR at 3.1x. Diligence caveat: verify " +
      "ARR composition - some revenue may be one-time integration fees. Proceed to IC.",
  });

  // Step 6: approval. Who approved this, and what exact bytes did they
  // approve, is one record. The decision artifact is the audit target.
  const approval = emit({
    actor: jane,
    stepId: `${workflowId}/step_06/attempt_01`,
    actionType: "human_approval",
    outcome: "success",
    inputs: [{ artifact: memoFinal.output!.artifact, role: "approved_memo" }],
    outputText: JSON.stringify({
      decision: "invest",
      company: "Company X",
      approved_artifact: memoFinal.output!.artifact,
      approver: "human:jane@soma.vc",
    }),
    mediaType: "application/json",
  });

  // Hourly anchoring: the signed root goes to the external notary.
  const anchoredHead = log.signedTreeHead(clock.tick());
  const receipt = tsa.anchor(anchoredHead, clock.tick());

  // The LP asks the question; the audit layer answers with a proof bundle.
  const disclose = new Map<string, Uint8Array>();
  for (const r of records) {
    if (r.output !== null) disclose.set(r.output.artifact, store.get(r.output.artifact));
  }
  const bundle = buildProofBundle({
    target: approval.output!.artifact,
    graph,
    log,
    certificates,
    anchoredTreeHead: anchoredHead,
    anchorReceipt: receipt,
    now: clock.tick(),
    discloseArtifacts: disclose,
  });

  return {
    store,
    log,
    graph,
    ca,
    tsa,
    certificates,
    trust: { ca_public_key: ca.publicKey(), tsa_public_key: tsa.publicKey() },
    approvalArtifact: approval.output!.artifact,
    memoArtifact: memoFinal.output!.artifact,
    bundle,
    records,
  };
}

// CLI entry point: run the pipeline, verify the bundle as an outsider, print both.
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === (await import("node:url")).pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  const world = runDemo();
  console.log("=== Workflow history (as recorded) ===");
  for (const r of world.records) {
    const out = r.output === null ? "(no output - failed attempt)" : r.output.artifact.slice(0, 18) + "...";
    console.log(
      `  [${r.outcome === "success" ? "ok" : "FAIL"}] ${r.step_id}  ${r.action_type}  by ${r.actor.identity}  -> ${out}`,
    );
  }
  console.log(`\n=== LP question ===`);
  console.log(`"Show me every action and data source that contributed to the decision to invest in Company X."`);
  console.log(`Target decision artifact: ${world.approvalArtifact}`);
  console.log(`Proof bundle: ${world.bundle.records.length} records, ${world.bundle.certificates.length} identities, anchored at ${world.bundle.anchor_receipt.anchored_at}`);

  console.log(`\n=== Standalone verification (trusting only the CA and the TSA) ===`);
  const report = verifyBundle(world.bundle, world.trust);
  for (const c of report.checks) console.log(`  PASS ${c}`);
  for (const e of report.errors) console.log(`  FAIL ${e}`);
  console.log(report.ok ? "\nVERIFIED: complete, signed, tamper-evident history." : "\nVERIFICATION FAILED");
  process.exit(report.ok ? 0 : 1);
}
