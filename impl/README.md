# Dominic Soma Cap Case Study — runnable core

The prototype behind the case study. It makes one claim executable: AI steps
can't be made deterministic, but the *record* of every step can be made
deterministic, signed, and tamper-evident. Zero runtime dependencies;
everything is built on `node:crypto`. Needs Node >= 22.18, which runs the
TypeScript directly.

## What it demonstrates

The deep-dive mechanisms from the write-up, running end to end: signed
provenance records, a content-addressed store, short-lived agent certificates,
a Merkle transparency log with external anchoring, an audit walk that emits a
proof bundle, and a standalone verifier that checks it while trusting only two
public keys (the org CA and the timestamp authority).

## What's here

| File | What it does |
|---|---|
| `src/canonical.ts` | Canonical JSON: the one byte form that gets hashed and signed. |
| `src/cas.ts` | Content-addressed store; the hash is the address, and reads re-verify. |
| `src/identity.ts` | Org CA, short-lived ed25519 certs, delegation chains ending at a human. |
| `src/record.ts` | The signed record: envelope, `nondeterminism` block, attempt chaining, identity binding. |
| `src/tlog.ts` | Merkle transparency log (RFC 6962 / 9162): inclusion and consistency proofs. |
| `src/anchor.ts` | External timestamp-authority stub (RFC 3161 interface). |
| `src/audit.ts` | Graph projection, reverse-BFS lineage walk, proof bundle builder. |
| `src/verify.ts` | Standalone verifier: checks a bundle with zero trust in what produced it. |
| `src/demo.ts` | The end-to-end scenario. |
| `test/` | 39 tests, including the four tamper scenarios. |

## Reproduce

```sh
npm install      # dev tooling only (typescript, @types/node)
npm test         # 39 tests, including the four tamper scenarios
npm run demo     # one memo, ingest to approval, then the audit and verification
npm run typecheck
```
