# Review and adjudication history

Last reconciled: 2026-08-30

This page records bounded review outcomes, not raw reviewer prose and not product authority. Live
source, executable controls, and accepted receipts outrank every historical review.

## Review method

Each review wave separates two axes:

1. **Correctness:** can the implementation publish, report, or reuse evidence it has not proved?
2. **Design integrity:** did the repair move ownership to the right abstraction, or add
   compensating code around a deeper defect?

Design observations are adjudicated as `reshape now`, `accept then refactor`, `no deeper issue
evidenced`, or `speculative`. Architectural preference does not become a correctness blocker
without a concrete failure path.

External reviews receive a bounded named source tranche and prompt. They are read-only. Findings
must be reproduced against the current tree; severity labels from a reviewer are not accepted
without independent classification.

## Provider and authority campaign

Earlier Fable/GLM waves produced 31 raw findings, reconciled to 28 unique observations across
adapter census, identity, relationship semantics, composition, and lifecycle. Accepted repairs
included:

- an exact structural adapter census instead of inferred language coverage;
- typed query state owning one graph and generation rather than reopening split state;
- exact artifact, provider, source-population, configuration, and toolchain identities;
- terminal rechecks for snapshots and semantic inputs;
- native tool-byte and private-provider verification;
- provider quarantine and explicit cancellation/supersession behavior.

A later retained-generation review exposed an open-handle ABA race and overly broad operation-state
retention. The subsequent authority campaign introduced authenticated generation content, shared
immutable inventory ownership, and typed terminal operation receipts. Complete parent and
standalone installed-product gates passed after those repairs.

## Standalone isolation audit

The first independent isolation audit reproduced the source and prior final candidate identities
but blocked external release review on four concrete gaps:

| Gap | Current disposition |
| --- | --- |
| Build/binary/benchmark evidence was not sealed to one final candidate | Repaired by a cross-artifact acceptance manifest whose exact current identity remains external to the candidate |
| A filtered public registry left a second dormant hidden-handler population | Repaired by deleting `init`, `replace_symbol`, `match`, and orphaned support; one exact 18-tool registry remains |
| Ten durable product, status, architecture, performance, review, and genealogy documents were absent | Repaired in the standalone-native overlay and exercised through assembly, gate, and acceptance sealing |
| Benchmark examples and comments retained parent-local agent/cache assumptions | Repaired with `.h00ligan/performance` and repository-neutral prose |

The local campaign also replaced the ancient-donor migration seam with a successor merge,
separated product and authority-receipt addressing, admitted the reproducible `.devbox` directory
as build output rather than source, and repaired installed-gate Python bytecode residue. Each
repair has a right-reason regression and populated sabotage control. The audit did not authorize
publication.

## Standalone acceptance review

Anthropic Opus 5 and Z.AI GLM 5.3 independently returned
`SOUND_WITH_NONBLOCKING_FINDINGS` for the reviewed predecessor. Both found the product/WATCH
repair sound and found no release-critical deeper rewrite. Their acceptance-authority observations
were independently reproduced rather than accepted from severity labels:

- candidate and build-mirror source substitution could retain stale build evidence;
- the gate log could come from an unrelated path and proved only unordered prose markers;
- assembly overlay partition/accounting was not fully rederived;
- cancellation, borrowed overflow authority, and manual-preemption hint transfer lacked direct
  lifecycle falsifiers;
- one installed Go workspace WATCH regression was not named by the CI contract;
- an always-true `watch_population_complete` field duplicated explicit uncertainty authority.

The corrected source binds the exact live product-source revision before building, emits one typed
terminal receipt over the accepted source tree, artifact, build/product-source receipts, and
benchmark report, bounds the gate log beneath the build mirror, requires singleton ordered source
and installed markers, rederives exact overlay/accounting closure, adds the missing lifecycle and
CI controls, and deletes the unreachable parallel flag. A suggestion to embed an expected
successor identity in its own hashed test was rejected because that would create a self-reference
loop rather than independent authority.

The earlier transient semantic-provider failure remains unexplained and has not reproduced; it is
retained as an evidence limit, not claimed fixed. The corrected candidate subsequently passed the
complete installed-product gate, sealing, replay, and exact-source audit. A later Go workspace
WATCH falsifier exposed an invalid `token.FileSet` pointer-identity assumption; the provider now
builds and validates one exact non-overlapping file-set union for SSA, and the regression plus its
restart companion pass. This source delta and the clean-import documentation reconciliation have
not been sent externally. Any further external send requires a new bounded packet and operator
authorization.
