// Static site generator: runs the ACTUAL provenance kernel at build time,
// captures the honest verification report plus four precomputed tamper
// scenarios, and bakes everything into dist/ as static files. No server-side
// code exists at runtime; what reviewers see is real kernel output.

import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { marked } from "marked";

import { runDemo } from "../impl/src/demo.ts";
import { verifyBundle, type VerificationReport } from "../impl/src/verify.ts";
import { TransparencyLog } from "../impl/src/tlog.ts";
import {
  CertificateAuthority,
  certFingerprint,
  exportPublicKey,
  generateKeys,
} from "../impl/src/identity.ts";
import { signRecord } from "../impl/src/record.ts";
import type { ProofBundle } from "../impl/src/audit.ts";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");

function clone<T>(value: T): T {
  return structuredClone(value);
}

console.log("running the kernel demo...");
const world = runDemo();
const honest = verifyBundle(world.bundle, world.trust);
if (!honest.ok) throw new Error("build sanity check failed: honest bundle must verify");

interface TamperScenario {
  id: string;
  title: string;
  simple: string;
  how: string;
  report: VerificationReport;
}

console.log("running tamper scenarios...");
const scenarios: TamperScenario[] = [];

{
  const bundle = clone(world.bundle);
  bundle.artifacts![world.memoArtifact] = Buffer.from(
    "# Investment memo: Company X\nQuietly rewritten after approval.",
  ).toString("base64");
  scenarios.push({
    id: "edit",
    title: "Edit the approved memo after the fact",
    simple: "Someone doctors the memo bytes in the audit bundle and hopes nobody notices.",
    how: "The disclosed bytes no longer match the artifact's content address. One hash comparison catches it.",
    report: verifyBundle(bundle, world.trust),
  });
}

{
  const bundle = clone(world.bundle);
  const rogueCa = new CertificateAuthority("ca:soma-org");
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
  memoEntry.record = signRecord(
    { ...unsigned, actor: { ...unsigned.actor, cert_fingerprint: certFingerprint(rogueCert) } },
    rogueKeys.privateKey,
  );
  bundle.certificates.push(rogueCert);
  scenarios.push({
    id: "forge",
    title: "Forge a record with a lookalike identity",
    simple: "An impostor re-signs altered content under a self-issued certificate that copies the real CA's name.",
    how: "Caught twice: the certificate does not chain to the trusted CA, and the altered record fails its log inclusion proof.",
    report: verifyBundle(bundle, world.trust),
  });
}

{
  const bundle = clone(world.bundle);
  bundle.records = bundle.records.filter((r) => r.record.outcome !== "failure");
  scenarios.push({
    id: "hide",
    title: "Hide the failed AI attempt",
    simple: "Delete the embarrassing first try from the history handed to the auditor.",
    how: "The successful retry's prev_attempt link points at the missing record. The hole is structural and visible.",
    report: verifyBundle(bundle, world.trust),
  });
}

{
  const bundle = clone(world.bundle);
  const rewritten = new TransparencyLog();
  for (let i = 0; i < world.log.size(); i++) {
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
  scenarios.push({
    id: "rewrite",
    title: "Rewrite the entire history log",
    simple: "An insider rebuilds the whole log with one record swapped, re-signing everything with the real log key.",
    how: "The rewritten history cannot produce a consistency proof back to the externally anchored root. The past is out of reach.",
    report: verifyBundle(bundle, world.trust),
  });
}

for (const s of scenarios) {
  if (s.report.ok) throw new Error(`build sanity check failed: scenario ${s.id} must fail verification`);
}

const data = {
  generated_at: new Date().toISOString(),
  stats: {
    records: world.bundle.records.length,
    identities: world.bundle.certificates.length,
    checks_passed: honest.checks.length,
    anchored_at: world.bundle.anchor_receipt.anchored_at,
  },
  workflow: world.records.map((r) => ({
    step_id: r.step_id,
    action_type: r.action_type,
    outcome: r.outcome,
    actor: r.actor.identity,
    output: r.output === null ? null : r.output.artifact,
    error: r.error ?? null,
    prev_attempt: r.prev_attempt ?? null,
    completed: r.timestamps.completed,
  })),
  target: world.approvalArtifact,
  honest_report: honest,
  scenarios: scenarios.map((s) => ({
    id: s.id,
    title: s.title,
    simple: s.simple,
    how: s.how,
    report: s.report,
  })),
};

console.log("writing dist/ ...");
mkdirSync(join(dist, "write-up"), { recursive: true });
cpSync(join(here, "site"), dist, { recursive: true });
writeFileSync(join(dist, "data.json"), JSON.stringify(data, null, 2));
writeFileSync(join(dist, "bundle.json"), JSON.stringify(world.bundle, null, 2));

// /write-up: rendered from content/write-up.md when present, placeholder otherwise.
const writeupPath = join(here, "content", "write-up.md");
const writeupMd = existsSync(writeupPath)
  ? readFileSync(writeupPath, "utf8")
  : "# Write-up\n\n*The full case-study write-up will appear here shortly.*\n\nIn the meantime, the [dashboard](/) shows the running system: the recorded workflow, the verification report, and four tamper attempts caught by the math.";
const writeupHtml = marked.parse(writeupMd) as string;
const shell = readFileSync(join(here, "site", "write-up", "index.html"), "utf8");
writeFileSync(
  join(dist, "write-up", "index.html"),
  shell.replace("<!--WRITEUP-->", writeupHtml),
);

console.log(`done: ${data.stats.records} records, ${data.stats.checks_passed} checks passed, ${scenarios.length} tamper scenarios (all caught)`);
