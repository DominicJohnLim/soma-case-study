# Dominic Soma Cap Case Study

System design case study for Soma Capital: the infrastructure that gives
verifiable, tamper-evident guarantees about everything AI agents produce, so
anyone can answer who made an artifact, from what, and whether it has changed
since. This repo holds the written submission and a runnable prototype of its
trust core.

## Deliverables

The three deliverables (high-level architecture, deep dive, tradeoffs) are in
[the write-up PDF](/Dominic%20Lim%20Write%20Up.pdf), and served live as a styled
page with the diagrams inline: https://soma-capital-case-study.vercel.app

Backing it up:

- **A runnable prototype** of the record / DAG / log core in `impl/`: about
  2,000 lines of TypeScript, no runtime dependencies, 39 tests including four
  adversarial tamper scenarios.

## What's here

| Path | What it is |
|---|---|
| `web/content/write-up.md` | The written submission: the three deliverables, diagrams inline. |
| `impl/` | The runnable core (the trust kernel). See `impl/README.md`. |
| `web/` | Static site: the styled write-up page served at the root. |

## Reproduce

```sh
# the kernel: run the tests and the end-to-end demo
cd impl && npm install && npm test && npm run demo

# the site: build the styled write-up page
cd web && npm install && npm run build
```
