# Provenance kernel

A runnable prototype of the provenance and auditability design for an agentic
investment platform. The design's central claim is that non-deterministic AI
steps cannot be made deterministic, but the *record* of every step can be made
deterministic, signed, and tamper-evident. This prototype makes that claim
executable.

## Run it

Requires Node >= 22.18 (runs TypeScript natively). No runtime dependencies -
everything is built on `node:crypto`.

```sh
npm install        # dev tooling only (typescript, @types/node)
npm test           # 36 tests, including the four tamper scenarios
npm run demo       # the full story, end to end
npm run typecheck
```

## What the demo shows

One memo, ingest to approval, then the LP audit question:

1. A sourcing agent snapshots a news article and a financials API response
   into content-addressed storage (`api_fetch` records with no inputs - the
   provenance frontier).
2. An enrichment agent's LLM call fails once and is retried. Both attempts
   are recorded; failures are history, not embarrassments to erase.
3. A memo agent drafts the memo; a partner edits it (a new artifact - edits
   never overwrite); the partner approves (the exact approved bytes are in
   the approval record).
4. The LP asks: *"Show me every action and data source that contributed to
   the decision to invest in Company X."* The audit layer walks the lineage
   and emits a proof bundle.
5. A standalone verifier checks the bundle - signatures, certificate chains,
   hash links, log inclusion proofs, append-only consistency, and the
   external anchor - trusting only two public keys (the org CA and the
   external timestamp authority). Not the log, not the database, not Soma.

## Modules

| Module | Role |
|---|---|
| `src/canonical.ts` | Canonical JSON encoding: the one true byte form that gets hashed and signed |
| `src/cas.ts` | Content-addressed artifact store: the hash is the identity; reads re-verify |
| `src/identity.ts` | Org CA, short-lived ed25519 certs, delegation chains terminating at a human |
| `src/record.ts` | The provenance record: the deterministic envelope, with the `nondeterminism` block and first-class attempts |
| `src/tlog.ts` | Merkle transparency log (RFC 6962/9162): inclusion and consistency proofs |
| `src/anchor.ts` | External timestamp-authority stub with the interface a real RFC 3161 integration would have |
| `src/audit.ts` | Provenance DAG projection, reverse-BFS lineage walk, proof bundle emitter |
| `src/verify.ts` | Standalone verifier: checks a bundle with zero trust in the system that produced it |
| `src/demo.ts` | The end-to-end scenario above |

## What the tests prove

- Merkle proofs are exercised exhaustively at small scale: every leaf at
  every tree size up to 20 (inclusion), every size pair up to 16 (consistency).
- Four adversarial scenarios are caught by the verifier:
  1. **Edited artifact** - disclosed bytes that no longer match their address.
  2. **Forged record** - re-signed content under a self-issued lookalike CA:
     caught twice, by the untrusted cert and by the failed inclusion proof.
  3. **Dropped ancestor** - lineage closure fails; hiding a failed attempt is
     caught by the `prev_attempt` chain.
  4. **Rewritten log** - a rebuilt history cannot produce a consistency proof
     back to the externally anchored root.

## What this deliberately is not

- Not a durable workflow orchestrator: the demo simulates a retry so attempt
  chaining is exercised; a production system would use Temporal-style durable
  execution.
- Not real LLM calls: agents are stubbed. That is the point - the envelope
  does not care what happens inside the step.
- Not a real RFC 3161 integration: the timestamp authority is a stub with the
  same interface and verification semantics.
- Not countersigned timestamps: the verifier evaluates certificate validity at
  the record's self-claimed completion time, so a key holder can claim any
  time inside its certificate window. The external anchor bounds when the log
  prefix existed, not when individual records were created; per-record
  countersigned timestamps (e.g. from the TSA) would be the upgrade.

Provenance proves lineage, not truth: a hallucination gets recorded with
perfect integrity. That boundary is drawn honestly in the design document,
and this prototype inherits it.
