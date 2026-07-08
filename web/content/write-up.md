# Provenance and Auditability for an Agentic Investment Platform

*System design case study. A working prototype of the trust core accompanies this document (~2,000 lines of TypeScript, zero runtime dependencies, 39 tests); implementation claims cite `file:line`, and the [dashboard](/) shows its real output.*

## 1. Problem and framing

Soma's agents are non-deterministic: they hallucinate, vary between runs, and depend on external APIs we do not control. Yet LPs, partners, and regulators need to know, for any artifact: who produced it, from which inputs, and whether it has been modified. One organizing decision drives the design:

> We cannot make LLM steps deterministic, so we don't try. Instead, we make the *record* of every step deterministic, signed, and tamper-evident: hash the inputs, hash the output, sign the pair with the actor's identity, and append it to a log nobody - including us - can rewrite.

Non-determinism stays contained inside the step; everything observable at the boundary is exact, attributable, and permanent.

**Threat model.** Defends against: silent modification of artifacts (including by administrators); misattribution; history rewriting; impersonation of agents or humans. Does not defend against: false source data faithfully recorded, fluent-but-wrong LLM output, or an attacker holding a live signing endpoint during its validity window (section 6).

**Scale reality.** 50,000 actions/day in two years is under one write per second, with artifacts of 100 B - 50 KB. This is a trust problem, not a throughput problem: boring storage (one ordered log, one Postgres, object storage), with the complexity budget spent on verifiability. The prototype's tests follow suit - Merkle proofs exercised exhaustively at small scale (`impl/test/tlog.test.ts:22,50`) rather than benchmarked.

## 2. Architecture

Three trust zones: untrusted external APIs; a semi-trusted execution zone (orchestrator, agents, identity service); and the trust root (transparency log plus external anchor). Storage and query layers are derived and rebuildable. Six components:

1. **Content-addressed store (CAS).** Every artifact and input snapshot is stored under the SHA-256 of its bytes. The hash is the identity, so "has this been modified?" is definitionally answerable; the prototype re-verifies on every read, so storage-layer tampering cannot silently return altered bytes (`impl/src/cas.ts:34-41`).

2. **Signed provenance records.** One per step *attempt* - the envelope. Section 3 is its deep dive.

3. **Transparency log - the trust root.** Records append to a Merkle tree in strict sequence, yielding inclusion proofs ("this record is in the history") and consistency proofs ("today's history extends yesterday's"). Hourly, the signed root is anchored to an external RFC 3161 timestamp authority; after anchoring, insider rewrites are mathematically evident, not just policy-forbidden. Same construction as Certificate Transparency (`impl/src/tlog.ts:182,217`).

4. **Durable workflow orchestrator.** Temporal-style: checkpointed state, idempotency keys for deterministic steps, recorded outputs reused - never blindly re-executed - for non-deterministic ones; each retry attempt emits its own record. The engine is purchasable infrastructure, deliberately not in the prototype; the property it must preserve is implemented: a failed attempt is a first-class record linked from its successor, and hiding it breaks verification (`impl/test/verify.test.ts:90`).

5. **Identity and keys.** An org CA issues short-lived certificates (hours) to agent instances (`impl/src/identity.ts:82-94`); agent certs must carry a delegation chain terminating at a human or verification rejects (`impl/src/identity.ts:136`). Humans use SSO plus hardware-backed keys. Rotation is automatic by expiry; no long-lived agent secrets exist; issued certs are logged, so emergency denylisting is available.

6. **Audit layer.** A graph projection consumed from the log - derived, and rebuildable by replay if ever distrusted. Answers ship as proof bundles verifiable outside our infrastructure (3.3).

**One memo, end to end** (the prototype's demo): sourcing snapshots a news article and a financials response with fetch records carrying no inputs - the provenance frontier. An enrichment agent produces a founder profile; its first attempt fails and both attempts stay in history. The memo agent consumes the profile; a partner's edit is a *new* artifact citing the prior memo under a human identity - edits never overwrite; the approval record pins the hash of the exact bytes approved (`impl/src/demo.ts:270-280`).

## 3. Deep dive: the record, the DAG, and the log

### 3.1 The provenance record

```json
{ "step_id": "wf_8f2e/step_04/attempt_02",
  "action_type": "llm_generate | api_fetch | db_write | human_edit | human_approval",
  "outcome": "success | failure",
  "actor": { "identity": "agent:memo-writer/v2.3.1", "cert_fingerprint": "sha256:9c1d...",
             "delegation_chain": ["human:jane@soma.vc", "role:memo-agents"] },
  "inputs": [ {"artifact": "sha256:a11f...", "role": "founder_profile"} ],
  "output": { "artifact": "sha256:77e0...", "media_type": "text/markdown" },
  "nondeterminism": { "model": "provider/model-id@2026-05", "prompt_template": "sha256:5dd2...",
                      "rendered_prompt": "sha256:c4a9...", "params": {"temperature": "0.7"},
                      "provider_request_id": "req_abc123" },
  "timestamps": { "started": "...", "completed": "..." },
  "prev_attempt": "wf_8f2e/step_04/attempt_01", "signature": "ed25519:..." }
```

Implemented as written (`impl/src/record.ts:36-55`). The decisions that matter:

- **Hashes, never bytes.** Records stay near 1 KB regardless of artifact size; content lives in the CAS. This split also enables the privacy answer in section 6.
- **Canonical bytes under every signature.** Identical content must produce identical bytes regardless of key order: sorted keys, floats/NaN and non-plain objects rejected (`impl/src/canonical.ts:16-39`); all four signed types share one payload helper (`impl/src/canonical.ts:64`).
- **The `nondeterminism` block is the determinism boundary, reified.** We cannot record why the model produced this output, but we commit to everything that parameterized the call: fully attributable, though not replayable.
- **Attempts are first-class.** `attempt_02` links to `attempt_01`; the lineage walk pulls failed attempts along (`impl/src/audit.ts:66`), and a bundle missing a linked failure fails verification.
- **Identity is bound, not just signed.** The record's claimed identity and delegation chain must exactly match the certificate, not merely verify under its key (`impl/src/record.ts:74-98`); section 4 explains why.
- **Human actions use the same schema.** "Who approved this, and what exact bytes did they approve" is one record.

### 3.2 Hash links are the provenance

Records reference inputs by content hash, and those inputs' records reference theirs, so the records form a Merkle DAG. The edges are hash references inside signed records, not rows in a mutable join table: falsifying ancestry requires a hash preimage or new signed records, and new records cannot enter the already-anchored log. Lineage and integrity are the same mechanism.

### 3.3 The log, and the audit walk

The DAG proves internal consistency; the transparency log proves *completeness* - nothing quietly deleted, no forged parallel history. Inclusion proofs are log2(n) hashes (about 25 at year-two volume); consistency proofs let any holder of yesterday's root verify today's log still contains yesterday's history; hourly anchoring gives an auditor who trusts only the TSA - not Soma - a bound on when history existed (`impl/src/anchor.ts:18-46`).

The LP asks: *"Show me every action and data source that contributed to the decision to invest in Company X."* The audit layer resolves the decision artifact, reverse-walks the DAG to the frontier (`impl/src/audit.ts:46`), and emits a proof bundle: every record in the subgraph with inclusion proofs, the current and last-anchored tree heads with a consistency proof between them, every certificate, the TSA receipt, and optionally the artifact bytes. A standalone verifier checks the entire bundle trusting exactly two public keys - the org CA and the TSA (`impl/src/verify.ts:14`) - covering tree-head signatures, the anchor, append-only consistency, per-record inclusion, certificate chains, record signatures and identity binding, lineage closure, and disclosed bytes. It shares no state with the system that produced the bundle; malformed input yields a failed report, never an exception. The four tamper scenarios on the dashboard - edited artifact, forged record under a lookalike CA, hidden failed attempt, wholesale log rewrite - are this verifier catching each attack (`impl/test/verify.test.ts:33,44,90,100`).

## 4. What building it taught us

Independent adversarial review of the prototype found two real bugs the original tests missed - both attribution failures, the very property this system exists to guarantee, and both invisible to happy-path testing.

**Expired certificates could pass via malformed timestamps.** In JavaScript, every comparison against an invalid date is false, so an unparseable timestamp read as "inside the validity window" - and records carry self-claimed timestamps, so an expired-cert holder could have signed with a garbage timestamp and passed, defeating rotation-by-expiry. Fixed by rejecting unparseable times, fail closed (`impl/src/identity.ts:119-123`).

**Identity was signed but not bound.** Verification checked the signature against the named certificate and the certificate against the CA - but never that the identity claimed *in the record* matched the certificate's *subject*. Any valid certificate holder could attribute its records to someone else: an agent key could produce a `human_approval` record claiming a partner's identity, and every check passed. Fixed by requiring exact identity and delegation-chain match (`impl/src/record.ts:84-98`; tests `impl/test/record.test.ts:74,90`).

The lesson: in a verification system the dangerous bugs are not in what it checks but in what it silently does not check, and the difference only shows up when someone lies.

## 5. Alternatives considered

**Blockchain instead of an anchored log.** A permissionless chain removes the trusted log operator entirely - a real property we give up. But consensus infrastructure and an availability dependency are disproportionate for an internal platform writing under one record per second whose insider-rewrite window is already bounded to an hour by an external notary. Kept as an escape hatch: anchoring roots to a public chain is one added integration.

**Lineage database plus separate audit log.** Simpler to build and query, but lineage and integrity become two systems that can disagree - an edge can be edited while the log stays intact, and the auditor must trust the join. The Merkle DAG makes the signed record stream itself the lineage: one mechanism instead of two.

**Long-lived agent keys with revocation.** Operationally familiar, but revocation is the hard part of any PKI: a stolen key is valid until noticed. Hours-long certificates make rotation automatic and bound exposure to the window, at the cost of always-on issuance whose availability gates agent work. At agent-instance cadence, issuance is the cheaper problem; the trade reverses for identities that must sign offline.

**Verification by replay for AI steps.** For deterministic steps, re-execute and compare - the strongest check, and it remains available. For LLM steps it fails today: re-running yields different output, and providers do not sign inference results. We chose attributable-not-replayable, committing to the full call context and the provider's request ID, and upgrade to provider attestation when it exists.

## 6. Limitations, admitted

Each is structural; we state the choice and why it is acceptable, because auditors distrust systems that claim too much.

1. **Lineage, not truth.** A hallucination is recorded with perfect integrity. Mitigation: `human_approval` records on decision-grade artifacts, so accountable human judgment is in every chain that matters.
2. **AI steps are attributable, never replay-verifiable** (section 5).
3. **A compromised endpoint signs lies with a valid key.** Short-lived certs shrink exposure to hours; the anchored log bounds when forgeries could have entered. Containment, not elimination.
4. **External data is trust-on-first-fetch.** Hash at the earliest boundary with fetch metadata; disputes reduce to "this is exactly what their API returned at 14:02 UTC."
5. **Append-only vs right-to-be-forgotten.** Decided up front because it cannot be retrofitted: only hashes enter the log; sensitive artifacts are encrypted per subject in the CAS, and deleting the key destroys content while every proof still verifies.
6. **Tamper-evident, not tamper-proof.** Until the hourly anchor, an insider controlling the log could rewrite the unanchored tail. A disclosed dial: anchor more often, or to multiple notaries.
7. **Record timestamps are self-claimed** (found during the adversarial review): the anchor bounds the log prefix, not individual record times. Per-record countersigned timestamps are the upgrade path.

Deliberately open: where proof bundles live at scale; anchoring cadence (contractual audit SLAs should set it); selective disclosure - bundles reveal graph structure today, and the hashes-not-bytes split makes redacted disclosure a designed v2.

## 7. Evolution at scale

At 10x-100x: shard the log per fund or workflow class under a super-root; batch anchoring; tier cold CAS content to archival storage (hashes stay hot); move the graph projection to a dedicated graph store if traversal breadth demands. Nothing in the trust core - record schema, DAG, log construction, proofs - changes shape; scale evolves the plumbing around an unchanged guarantee.

*The deep dive (section 3) is where the sharpest follow-up questions are expected and welcomed; every mechanism in it is runnable in the accompanying prototype.*
