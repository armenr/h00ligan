# Project status

Last verified: 2026-09-06

## Released product

**h00ligan 0.3.0 is published** in the standalone repository:
[release and downloads](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0).
The repository is public as verified on 2026-09-06; older private-status notes
do not describe its current visibility.

- Tag: `h00ligan-v0.3.0`.
- Source: `0bd933483ceeef6e25a0d11c822bb0e7d03bd9d9`.
- Published: 2026-09-05 at 16:05:06 UTC.
- Downloads: Linux AMD64, Linux ARM64, Apple Silicon, and `SHA256SUMS`.
- Intel Mac: explicitly deferred, not silently passed or included.
- Each archive: one executable, compact guide, changelog, target SBOM, notices,
  licenses, and build metadata.

The accepted three native jobs in
[distribution run 33971941146](https://github.com/armenr/h00ligan/actions/runs/33971941146)
passed their installed-product checks. Intel failed a build-authority fixture
barrier after compilation. The four-target aggregate therefore failed and
automatic packaging was skipped. The three accepted artifacts were packaged
and published separately without changing their binary bytes. Fresh downloads
matched checksums and native binary identities; downloaded Linux CLI/MCP,
reindex, WATCH edit/stop, terminal controls and shutdown were exercised.

**This is a successful three-target release, not proof that the full
four-target automated pipeline is green.** Reconcile the future workflow with
the parked Intel policy before another native dispatch. Published 0.3.0 tags
and assets stay immutable. See [the runbook](../releasing-h00ligan.md).

## Product boundary

The standalone workspace has four crates: `h00ligan`, `h00ligan-engine`,
`h00ligan-interface`, and `h00ligan-provider-protocol`. It has no runtime
dependency on h00.sh, Engram, or another h00 package. The clean-import
extraction and Git cutover are completed history, not upcoming release gates;
[genealogy](../history/h00sh-genealogy.md) retains their provenance.

One executable owns CLI, MCP's 18 tools, WATCH, and private embedded semantic
providers. Rust/Go semantic loading still needs compatible project toolchains.
Python/TypeScript semantic providers require no ambient language executable.
All languages need suitable project/dependency resolution for complete evidence.

## Current documentation and verified depth gap

The current documentation pass separates human CLI workflows, MCP connection
and lifecycle, agent guidance, and one shared verb/result reference.
The dependency-free Python tour is exercised against the actual 0.3.0 binary,
not merely a development build or invented output.

**Confirmed limitation:** Python/TypeScript/JavaScript reachability
classification is not implemented in 0.3.0. Complete Calls does not imply
complete deadness/health/risk support. The Python tour has two exact callers
and one test entry, yet `dead` refuses with
`reachability_evidence_unavailable`. The owning entry-point inventory
dispatch in
[`entry_points.rs`](../../crates/h00ligan-engine/src/entry_points.rs)
admits Rust packages and Go modules only. This is a product-depth gap, not
missing SCIP installation and not fixed by repeating an unchanged index.

The tracked
[documentation probe](../../scripts/test-h00ligan-docs.py)
preserves that evidence along with CLI/MCP parity, caller/test positives,
pagination and invalid bounds, stale/refused/restored source, reindex reuse,
terminal cancellation, and a semantic WATCH edit/restore/stop lifecycle.
It uses disposable source/index state and never updates a user's bundle.
When classification is implemented, reconcile this probe and the guides.

## Current sequence and evidence limits

The documentation and plain-language cleanup landed on main at `79b5300`.
Current correctness work addresses Go build tags being discarded before
provider launch; both a resolver regression and an installed-product fixture
reproduce the omission with native Go and an untagged caller as controls.
The development repair passes the full local Linux AMD64 `just ci-product`
gate: explicit flags reach CLI and MCP indexing, configuration switches cannot
reuse the old semantic generation, and tagged WATCH edits/restoration and
restart under different tags preserve the selected caller population. The gate
also exercises 18 installed WATCH lifecycles and four-language performance
smoke with zero new process residue. This is not a new macOS/ARM64 acceptance
claim and is not part of the published 0.3.0 binaries.

The verification repeat also exposed a portable-builder lock handoff race.
Lock cleanup now owns only successfully acquired locks; a lock released
between contention and inspection is a normal handoff. Deterministic controls
cover release, timed-out waiters, invalid entries and source-cache ownership.
This is build machinery, not a new runtime dependency or lock subsystem.

The [actual Switchboard retest](../evidence/go-build-selection-2026-09-06.md)
now passes: the requested tag admits the previously omitted test helper, with
seven source-verified call sites and one test root. Native Go agrees on tag
selection; the untagged helper remains explicitly excluded. Both indexes used
fresh scratch data and preserved all 727 tracked backend files. Native Go also
excludes 138 explicitly constrained files under this selection; matching
aggregate omission counts alone neither prove more defects nor establish exact
provider per-file parity. Dynamic dispatch and bundled JavaScript qualifications
remain visible and separate from the repaired tag-selection defect.

The Go repair merged through [PR #20](https://github.com/armenr/h00ligan/pull/20)
at main `74dc46f`; all four required source/policy checks passed on the PR and
merged main. Release Please's permission repair then created
[PR #21 for 0.3.1](https://github.com/armenr/h00ligan/pull/21), without building
or publishing. Its original built-in token left source CI waiting for approval.
The current workflow change uses a repository-scoped GitHub App token to start
those checks automatically; installed acceptance must still observe that real
update and its exact-head CI. No release-PR auto-merge is configured.

Return to the queued PR baseline and three-target release automation/
CI-cost follow-up. Address the evidenced
classification depth gap before advertising full four-language dead-code
parity. Preserve real-repository dogfood, task-level comparison, and the
performance program in [the work plan](work-plan.md).

The [performance baseline](../performance/baseline.md) remains dated,
artifact- and fixture-bound reference evidence, not a new 0.3.0 benchmark.
The historical clean-import candidate counts and replay identities describe
that extraction stage; do not require rebuilding it to edit user documentation.
Future product acceptance must still bind its exact source and artifact.
