# AGENTS.md — h00ligan

This repository contains h00ligan: one portable executable that provides a human CLI,
a repository-bound MCP server, immutable indexing, compiler-backed semantic evidence,
and WATCH refreshes for Rust, Go, Python, and TypeScript/JavaScript.

## Start here

Read the root `README.md`, then `docs/agent-integration.md` for productive tool use and
`docs/reference.md` for shared CLI/MCP semantics. `docs/README.md` is the task-oriented
documentation index; `docs/how-it-works.md` explains the model and result labels.
`docs/getting-started.md` and `docs/mcp.md`
cover setup; `docs/languages.md` states the depth limits. The compact
`crates/h00ligan/README.md` also ships in release archives. Route current product judgment through
`docs/project/status.md`, `docs/project/work-plan.md`, and the relevant `docs/architecture/`
page. Read only the source and documentation needed for the active task; historical prose is
context, not authority over live behavior.

When claims disagree, prefer the current operator instruction, live source and executable
evidence, independently verified tests, then documentation and history—in that order.

## Product invariants

- The shipped product remains one executable. Private provider artifacts may be embedded
  and materialized beneath the selected data directory; users must not install a companion
  h00ligan service or helper product.
- CLI and MCP expose the same query semantics. Human rendering may differ from MCP's
  structured envelope, but authority, freshness, ambiguity, and refusal behavior must agree.
- Structural evidence and compiler-backed Calls evidence are distinct. Never turn partial,
  qualified, unavailable, stale, or unknown authority into a confident negative answer.
- Complete Calls does not imply reachability classification support. Python/TypeScript/JavaScript
  classification is not implemented in 0.3.0; retain that limitation in dead-code/risk conclusions.
- Published generations are immutable and repository-bound. WATCH and reindex publish a
  complete replacement or retain the last good generation; they never expose a partial graph.
- MCP is bound to one repository for its process lifetime. Reindex operations are asynchronous,
  exact-ID controlled, cancellation-safe, and terminal-receipt backed.
- Compiler-specific behavior stays explicit behind language-neutral lifecycle contracts. Do
  not force Rust, Go, Python, and TypeScript into a lowest-common-denominator abstraction.
- Released 0.3.0 targets are native Linux AMD64/ARM64 and Apple Silicon. Intel Mac is parked;
  the existing four-target workflow still needs policy reconciliation. Host-development binaries
  are not evidence that the portable product works.

## Working rules

- Preserve unrelated and uncommitted work. Do not restore, reset, clean, stash, commit, push,
  tag, publish, or change remote state unless the current operator explicitly authorizes it.
- A behavior change needs a falsifier that fails on the prior behavior for the intended reason.
  An absence claim needs a populated search and a same-run known-positive control.
- Compilation is not product acceptance. Verify the real CLI, MCP, WATCH, provider, package,
  and installed-binary boundary in proportion to the change.
- Fix defects at the owning abstraction. Treat compensating state, cleanup, retries, and special
  cases as design smells unless executable evidence proves they belong there.
- The product is not yet constrained by an external stable compatibility contract. Prefer the
  cleanest correct present design, while preserving real files, evidence, and Git history.
- Keep secrets, credentials, machine-local paths, build products, provider caches, indexes, and
  runtime state out of tracked files.

## Development and gates

Use the pinned Devbox environment for repository tooling and exact gates:

```bash
devbox shell
just ci
```

Use `just ci-product` for changes that can affect the installed executable, CLI/MCP parity,
WATCH, providers, packaging, or performance. `just perf-smoke` and `just perf` exercise the
distribution-shaped product rather than a Cargo development binary.

For mutating index probes, create a fresh scratch directory and pass it explicitly with
`--data-dir`. Do not overwrite an existing user's graph bundle merely to run a test.

## Dogfooding h00ligan

Use h00ligan when it materially reduces broad source scanning, but treat its output as measured
evidence rather than infallible authority. A useful sequence is:

```bash
h00ligan status
h00ligan overview
h00ligan find 'SymbolName'
h00ligan inspect 'SymbolName'
```

Check the reported generation freshness and per-language authority before relying on Calls,
impact, dead-code, or zero-result claims. Corroborate correctness-critical findings against live
source or an independent command, and report misleading output as a product defect.
