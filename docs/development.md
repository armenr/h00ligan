# Developing h00ligan

[Docs](README.md) / Development

These are **contributor** instructions. Release users do not need this build
environment; start with [installation](getting-started.md#install) instead.

Improving the guides? See [documentation style](documentation-style.md) for the
voice, navigation, examples, and proportionate checks used here.

## Environment and source build

Use the repository's pinned Devbox environment for Git/hooks, Rust, Go,
packaging tools, and gates. From the checkout:

```bash
devbox shell
just install-hooks
just build
```

For a noninteractive command, use `devbox run -- just check`, for example.
`just build` creates host-development artifacts. A host binary built inside
Nix/Devbox may depend on that environment; it is not a distribution artifact.

To build or install the one-file product:

```bash
just build-portable
just install
```

The builder prints the exact artifact path. Installation defaults to
`~/.local/bin/h00ligan`. Private providers are bound to the product build; do
not distribute a Cargo development binary or a loose helper instead.

## Quality gates

```bash
just fmt-check
just check
just lint
just test
just ci
just ci-product
```

`ci` covers the four-crate source workspace, strict lint, serial tests,
dependency policy, portability controls, release/Action/SBOM/package checks,
and executable gate/performance contracts. `ci-product` adds the installed
one-file CLI/MCP/WATCH/provider boundary and performance smoke, then emits a
source/artifact-bound receipt. Compilation alone does not establish that the
shipped executable works.

Run verification proportional to the change. Documentation examples can be
checked against an already-built release with the documentation probe; they
do not require another four-platform native rebuild:

```bash
python3 scripts/test-h00ligan-docs.py --binary /absolute/path/to/released/h00ligan
```

This copies the tour into temporary storage, checks 14 CLI/MCP query/error
pairs and the documented limits, and runs reindex plus semantic WATCH
edit/restore/stop. It removes its source/index/log state and checks server exit.
It requires a one-file product with the embedded Python provider, not a host
development binary. It does not replace the full installed-product gate.

Product behavior changes need their owning regression, relevant complete gates,
and installed evidence.
Do not weaken a gate to work around a missing development environment.

Indexing probes must use a fresh, explicit `--data-dir`, not someone else's
working bundle. Keep temporary state, transcripts, benchmarks, and machine-local
paths out of tracked files. Preserve unrelated work in shared checkouts.

## Performance battery

```bash
just perf-contract
just perf-smoke
just perf
```

The fast contract is sabotage-tested. Smoke measures one cold index, one
edit/restore cycle per language, and five repetitions of each CLI/MCP query.
The full battery expands to three cold indexes, three cycles, and 25 query
repetitions. Both drive the distribution-shaped executable with correctness,
coverage, parity, restoration, terminal-receipt, and process-cleanup controls.

```bash
scripts/bench-h00ligan-product.sh full --output .h00ligan/performance/h00ligan-full.json
scripts/bench-h00ligan-product.sh full --baseline .h00ligan/performance/h00ligan-full.json
```

Reports retain raw samples, median/p95, artifact/fixture identities and phase
timings. Exclusive phases can be summed; overlapping concurrent spans cannot.
Establish repeated quiet-host baselines before calling a number a regression
threshold. [Historical measured results](performance/baseline.md) state their
scale and limits; do not relabel them as measurements of a newer release.

## Where changes belong

The executable crate assembles the product and CLI; the engine owns indexing,
publication and queries; the interface owns MCP adapters; the provider protocol
owns private process contracts. Start with [architecture](architecture/product-contract.md)
and the [current work plan](project/work-plan.md).

When reviewing a fix, separately ask whether it repairs the owning abstraction
or adds compensating state around a deeper defect. Classify design findings
as reshape now, accept then refactor, no deeper issue evidenced, or speculative.
Don't disguise architectural preference as an executable correctness failure.

Use Conventional Commits (`docs:`, `fix:`, `feat:`, `test:`, etc.) and preserve
normal hooks. Tags, assets, version synchronization and publication have their
own [release runbook](releasing-h00ligan.md). Intel Mac repair is parked; the
three shipped 0.3.0 platform lanes must not be confused with a green four-target
automated release.
