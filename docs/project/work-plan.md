# Work plan

Last reconciled: 2026-09-06

Keep the durable goal: truthful, portable, fast code intelligence that humans
and agents can use in real polyglot repositories. Historical plans explain
past decisions; they do not override current evidence or operator direction.

## Completed baseline

Standalone extraction, clean import, remote establishment, and the 0.3.0
three-platform release are complete. See [status](status.md) and
[genealogy](../history/h00sh-genealogy.md). Do not restart the old assembly,
transfer, or Git-cutover program. Preserve the incubator's unrelated work.

## 1. Completed correctness slice: explicit Go build configuration

Switchboard's real adoption trial exposed discarded `GOFLAGS`: native Go
included a tagged test while h00ligan omitted it. The product captured explicit
flags and then replaced them with `-mod=readonly`, twice; the external-provider
adapter repeated that substitution. Fix selection at the shared Go toolchain
owner, not with a gopls-local workaround or a second cache identity system.

- Preserve admitted build tags and keep module writes disabled.
- Reject unsupported input redirection explicitly; do not silently index a
  different configuration or certify untracked overlays/manifests.
- Retain Go's quoted-field semantics and language-local errors.
- Prove default/tagged populations against native Go, CLI/MCP parity, generation
  invalidation, and WATCH edit/restore/restart with changed tags.
- Run the complete source and installed-product gates, then retry the specific
  Switchboard case without modifying its source or existing analysis state.
- Classify other reported omissions/dynamic regions separately. Their counts
  do not prove that this one defect explains all of them.

This is a focused correctness interruption before returning to section 2;
it does not replace the retained release, classification or performance work.
The published 0.3.0 assets remain unchanged.

Local completion (2026-09-06): resolver/adapter controls, installed CLI and MCP
tag-selected reindexing, configuration-switch invalidation, tagged WATCH
edit/restore/restart, and the complete Linux AMD64 `just ci-product` gate pass.
The production change stays in the existing toolchain owner; no new cache,
session or receipt subsystem was introduced. The actual Switchboard standalone
backend now passes the requested tag case: native Go selects the test document,
and h00ligan returns seven source-verified call sites and its test root. The
untagged control still excludes it. All 727 tracked backend files stayed
unchanged. [Exact real-repository evidence](../evidence/go-build-selection-2026-09-06.md).
Other reported omissions and dynamic regions remain separate qualifications,
not inferred fixes; native Go also excludes 138 explicitly constrained files
under the requested tag.

An installed-gate repeat exposed an existing build-lock handoff/cleanup race.
It was repaired at lock admission/release, with deterministic right-reason and
ownership controls; the full product gate passed afterward. This build-only
repair is separate from Go semantic configuration and the wider CI-cost work.
The checked repair merged as main `74dc46f` through PR #20, with all required
PR and post-merge source checks green. Resume section 2 without starting
another release.

### Completed: make the released tool understandable and usable

- One getting-started guide with install/prerequisites and a runnable tour.
- Human CLI investigations; host-neutral MCP setup and exact operation lifecycle.
- A shared verb/argument/result reference, not two competing semantics guides.
- Copyable agent guidance for selection, focused reading, evidence, and refresh.
- Honest language depth and troubleshooting, including Python/TypeScript
  classification being unavailable despite complete Calls.
- Released-binary examples, CLI/MCP parity, WATCH, links, and documentation contracts.

Exit: a human or agent can install, index, ask a useful question, interpret the
answer's limits, and keep the index current without undocumented machinery.

## 2. Baseline release operations and the open PR queue

The operator requested open-PR cleanup after downloadable binaries existed.
That condition is met; documentation was explicitly prioritized next.

- Review each open PR against current main; integrate useful remaining work
  through normal checks, and close only genuinely superseded work with context.
- Reconcile the future native release matrix with Linux AMD64/ARM64 and
  Apple Silicon. Intel Mac repair is **parked**, not waived as a success.
- Keep the published 0.3.0 source/tag/assets immutable.
- Reduce evidenced cold/redundant CI work and cost without reducing acceptance.
- Release Please's permission repair created PR #21 for 0.3.1 without a build
  or publication. Finish the GitHub App token integration and verify a real
  release-PR update starts its exact-head source checks without manual approval.
  Keep the release PR unmerged until an intentional shipping decision.
- Keep release summaries useful to humans, not just generated commit lists;
  describe improvements, remaining limitations, and upgrade implications.

Exit: a comprehensible PR baseline and a truthful, repeatable release path.
No unrelated visibility, permission, history, or license change is implied.

## 3. Close the evidenced language-depth gap; continue real dogfood

The documentation tour confirmed an owning classification gap:
`discover_entry_points_from_inventory` admits Rust/Go units, not Python/TS.
Resolve roots, reachability policy, and per-language authority deliberately;
do not paste synthetic “live” labels over unclassified nodes. Cover standalone
and mixed repositories with right-reason, non-vacuous tests and installed
CLI/MCP/WATCH acceptance before claiming equal dead-code depth.

Alongside that correctness work:

- Use CLI/MCP/WATCH on real Rust, Go, Python, TypeScript and polyglot projects.
- Treat actively edited repositories as live work: preserve others' changes
  and separate generation evidence from current-source observations.
- Record misleading answers, excess calls, setup friction, and scope confusion.
- Run the task-level comparisons in the
  [product evaluation contract](../product/thesis-and-evaluation-contract.md).
- Improve agent selection from observed use rather than mandatory hooks.

Exit: evidence of better maintenance decisions, not merely more green tests.
Review correctness and deeper design integrity separately; classify reshape-now,
accept-then-refactor, no-deeper-issue-evidenced, and speculative observations.

## 4. Resume measured performance work

The largest retained opportunities are whole-generation WATCH publication and
cold semantic-provider indexing. Profile first; prioritize incremental
publication, shared immutable projections, compiler-session reuse, and narrower
invalidation at their owning boundaries. Preserve exact freshness, publication
and capability evidence.

Sparse graph/matrix projections, semiring algorithms, delta overlays, and ring
buffers remain candidates—not adopted architecture. Use them only for an
evidenced algorithmic/contention bottleneck with an installed-product A/B
proving the gain. Keep deterministic fixture benchmarks separate from changing
real-repository scale probes. [Baseline and battery](../performance/baseline.md).

## 5. Later distribution/DX and language breadth

- Improve installation and eventually settle public licensing/macOS signing
  policy without turning either into unrelated documentation ceremony.
- Design managed toolchain acquisition around detection, verified identity,
  consent, offline behavior, pruning, drift, and rollback. Keep network
  acquisition outside the correctness-critical coordinator until designed.
- Add languages/configuration breadth with structural facts, semantic depth,
  WATCH invalidation, installed acceptance, and performance controls.

PHP, SQL lineage, shell/config relationships, and complexity ranking remain
ideas to evaluate against concrete questions. They are not shipped promises.
