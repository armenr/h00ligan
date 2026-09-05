# Semantic-provider lifecycle

Last verified: 2026-08-28

## Boundary

Tree-sitter extraction is h00ligan's compiler-free structural floor. Semantic providers are
optional accelerators that add compiler-backed Calls evidence for a specific source population,
project configuration, execution root, toolchain, and provider build. A provider response does
not publish a generation or grant itself authority.

The language-neutral coordinator owns process/session acceleration, exact structural
reconciliation, terminal admission, and canonical normalization. The immutable publisher remains
the sole owner of persisted generation authority.

## Lifecycle

1. Build one exact project inventory and discover language execution roots.
2. Resolve the required provider components into a `ResolvedToolchain` with a content identity.
3. Start or reuse a disposable, parent-bound provider process for the admitted root and lifecycle
   policy.
4. Send typed protocol requests containing the repository, configuration, source-population,
   operation, epoch, provider-build, and toolchain witnesses.
5. Recheck terminal responses against those witnesses and the current cancellation epoch.
6. Reconcile provider documents with exact structural source evidence.
7. Normalize admitted relationships into one canonical provider payload.
8. Return that payload and its coverage evidence to the publisher; do not persist it directly.

Process reuse is an optimization. A session that cannot prove its identity or current inputs is
replaced or quarantined rather than trusted because it is warm.

## Shared ownership versus language policy

The shared coordinator owns:

- typed request/terminal framing and size limits;
- process startup, health, cancellation, quarantine, and cleanup;
- a concurrency limit across execution roots;
- exact source-population and structural joins;
- canonical relationship normalization;
- common terminal identity and freshness checks.

Each language adapter explicitly owns:

- execution-root discovery and configuration witnesses;
- required toolchain/provider components;
- invocation and configuration schemas;
- whether source changes can certify in retained sessions or require replacement;
- whether invalidation is whole-provider or execution-root local;
- language-specific omissions and qualification reasons.

This separation is deliberate. Rust, Go, Python, and TypeScript do not have identical compiler
lifecycles, and pretending otherwise would hide authority gaps.

## Installed-provider shape

| Language | Installed execution | Ambient requirement |
| --- | --- | --- |
| Rust | Hidden same-executable provider entrypoint | Compatible repository Cargo/Rust toolchain for semantic Calls |
| Go | Content-verified private provider embedded and materialized beneath the selected data directory | Compatible repository Go toolchain for semantic Calls |
| Python | Content-verified private provider embedded and materialized beneath the selected data directory | None for the installed-product provider path |
| TypeScript/JavaScript | Content-verified private provider embedded and materialized beneath the selected data directory | None for the installed-product provider path |

Private artifacts are implementation details, not separately installed products. Their bytes,
source trees, patches, lockfiles, and transforming scripts are bound into build receipts.

## WATCH and invalidation

Source, project configuration, execution-root membership, provider build, and resolved toolchain
identity are semantic inputs. A relevant change invalidates the affected certification. With
explicit capability-downgrade permission, semantic WATCH may publish current structural truth
before semantic enrichment. That publication does not claim complete Calls; a later semantic
generation must be admitted separately. Strict complete-Calls mode remains atomic.

If inputs change during a provider operation, the terminal is discarded. Cancellation,
supersession, provider exit, malformed framing, identity drift, or incomplete persistence cannot
upgrade authority. A failure remains retryable and is not reused as proof that a capability is
stably absent.

## Performance boundary

Provider roots may run concurrently up to a CPU-aware limit. Persistent sessions and
affected-document refresh avoid unnecessary cold compiler loads, but exact terminal validation is
never skipped for speed. Current profiling identifies cold provider work and broad refresh scope
as major remaining latency targets.

Managed downloading of language toolchains is intentionally outside this coordinator until local
resolution, identity, drift, cancellation, and installed-product behavior are fully accepted.
