# h00ligan

`h00ligan` is a standalone, GPU-free code-intelligence binary. One
executable provides both the interactive CLI and a repo-bound MCP stdio server.
It does not require a daemon, database service, embedding model, or API key.

Current language support is Rust, Go, Python, and TypeScript/JavaScript.
Tree-sitter provides the structural floor; compiler-backed providers add exact
Calls evidence when requested.

## Install a release

Each GitHub Release provides native archives for these platforms:

| Release asset | Machines |
| --- | --- |
| `h00ligan-X.Y.Z-linux-amd64.tar.gz` | x86-64 / Intel / AMD Linux |
| `h00ligan-X.Y.Z-linux-arm64.tar.gz` | AArch64 / ARM64 Linux |
| `h00ligan-X.Y.Z-macos-amd64.tar.gz` | Intel macOS 10.12+ |
| `h00ligan-X.Y.Z-macos-arm64.tar.gz` | Apple Silicon macOS 11.0+ |

Download the matching archive and release-wide `SHA256SUMS`, verify it, then
install the binary somewhere on `PATH`. On Linux AMD64:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf h00ligan-X.Y.Z-linux-amd64.tar.gz
install -m 0755 h00ligan-X.Y.Z-linux-amd64/h00ligan "$HOME/.local/bin/h00ligan"
h00ligan --version
```

On macOS, use `macos-amd64` for Intel or `macos-arm64` for Apple Silicon.
macOS ships `shasum` rather than `sha256sum`:

```bash
grep 'h00ligan-X.Y.Z-macos-arm64.tar.gz$' SHA256SUMS | shasum -a 256 --check
tar -xzf h00ligan-X.Y.Z-macos-arm64.tar.gz
install -m 0755 h00ligan-X.Y.Z-macos-arm64/h00ligan "$HOME/.local/bin/h00ligan"
h00ligan --version
```

Each archive also contains a target-specific CycloneDX SBOM, third-party
license report, build metadata, changelog, and the applicable workspace
licenses.

The declared macOS versions are verified Mach-O deployment targets. CI runs
the binaries on current native GitHub runners; it does not separately exercise
the oldest supported OS releases. macOS archives are not yet Developer ID
signed or notarized, so Gatekeeper may show its normal unidentified-developer
approval flow.

## Quick start

Run from a Git repository, or bind the repository explicitly:

```bash
h00ligan --root /path/to/repository index
h00ligan --root /path/to/repository status
h00ligan --root /path/to/repository overview
h00ligan --root /path/to/repository find '*Handler'
h00ligan --root /path/to/repository inspect HandlerName
```

Every `find` match carries a `symbol_id`. Pass that value through the existing
symbol argument of `type`, `read`, `calls`, `assess`, `inspect`, `dead`, or
`tests` when a name is ambiguous or exact occurrence identity matters:

```bash
h00ligan --root /path/to/repository find 'impl Widget' \
  --name --definitions-only --format json
h00ligan --root /path/to/repository read \
  'sym-v1.<opaque-occurrence>.<opaque-binding>'
```

The human `find` renderer prints the same value as `SELECTOR`. IDs are opaque
and bound to one repository and immutable generation. They fail closed after a
new generation is published or when used with another repository. For casual
queries, keep using a name; `--file` remains a convenient assertion or
cross-file homonym disambiguator.

Without `--root`, h00ligan discovers the nearest Git ancestor from its startup
directory. The default graph bundle is repo-local:

```text
<repo>/.h00ligan/code-intel/
```

Use `--data-dir /some/path` to put the bundle elsewhere. Run
`h00ligan --help` and `h00ligan <command> --help` for the current command and
flag contracts.

### Immutable generation versus live worktree

Generation-bound queries remain useful after a source edit, but they must not
pretend that an internally complete old snapshot describes current files.
Every shipped generation-bound JSON/MCP result therefore includes
`repository.live_inputs`:

```json
{
  "freshness": "fresh | stale | unknown",
  "consistency": "per_file_non_atomic",
  "indexed_file_count": 289
}
```

`authority.status` continues to describe the explicitly named immutable
population. `live_inputs.freshness` is a separate current-worktree axis. When
it is `stale` or `unknown`, the result carries a qualification explaining that
it describes the immutable generation rather than current source; the human
CLI prints that qualification too. `status` reports the same exact source and
project-input comparison. `diff` deliberately compares the generation with
live source, while source-materializing `read`/`inspect` additionally refuse a
selected file whose bytes no longer match its indexed record.

Freshness is observed during one bounded request, not under a repository-wide
filesystem transaction, hence `per_file_non_atomic`. Publish a current
generation with `h00ligan index` when current-worktree conclusions matter.

## MCP server

The same binary serves the exact graph-only tool set over newline-delimited MCP
JSON-RPC on stdin/stdout:

```bash
h00ligan --root /path/to/repository mcp-serve
```

Configure an MCP host with an absolute binary path and an explicit project
root. The outer configuration key varies by host; the server entry is commonly
shaped like this:

```json
{
  "mcpServers": {
    "h00ligan": {
      "command": "/absolute/path/to/h00ligan",
      "args": [
        "--root",
        "/absolute/path/to/repository",
        "mcp-serve"
      ]
    }
  }
}
```

To keep generated state outside the repository, add `--data-dir` and an
absolute directory before `mcp-serve` in the argument list.

The server exposes these 18 deterministic tools:

```text
reindex, reindex_status, reindex_cancel, watch, type, read, calls, assess,
inspect, dead_code, status, find, tests, overview, audit, deps,
grep_context, diff
```

Start with `status`. To build or recover a graph through MCP, call `reindex`
with `{}`. It returns immediately with an `operation_id`; poll
`reindex_status` with that exact ID until its immutable receipt has
`"terminal":true`. Use `reindex_cancel` with the exact ID to stop an unwanted
operation. Cancellation keeps the last good publication queryable and never
publishes the private partial generation. The process retains only its latest
operation, so an unknown or superseded ID fails closed.

MCP reindexing is structural by default; add `"scip":true` when
compiler-backed Calls evidence is required. The release executable already
contains its private semantic-provider artifacts; Rust semantic analysis also
requires a repository-compatible Cargo/Rust toolchain. When a damaged or
conflicting publication must be replaced deliberately, add
`"recover_publication":true`. Source mutation is deliberately absent from the
standalone h00ligan registry while its edit contract is redesigned.

`type`, `calls`, and `deps` return typed, cursor-paged results. `deps` separates
direct forward dependencies from direct dependents crossing one indexed file
or directory boundary; its authority reports structural, Calls, and project-dependency
coverage independently. It is not a transitive blast-radius query—use `assess`
for symbol-level change impact. `overview` returns the
versioned `h00/code-intel/overview/v2` result: structural project topology is
always visible, while per-unit reachability health and mixed Calls/FieldOf
fan-in are `null` unless that language unit has complete Calls authority. Its
aggregate dead-code count remains unknown when any callable language is
uncovered. `health_action_needed` and `health_guidance` distinguish repairable
provider failures from stable loose-source limitations. `audit` returns the
versioned `h00/code-intel/audit/v1` result over the same immutable generation.
Its default `production` scope ranks incoming coupling without letting test
callers or test-only targets manufacture production hotspots; `conditional`,
`tests`, and `all` expose the other populations deliberately. Provider Calls,
structural call hints, and field uses remain separate counts. A mixed-language
generation keeps authoritative per-project-unit dead-code observations even
when its whole-repository total must remain unknown. Its
`project_unit_authority` rows reconcile the authoritative/withheld counts by
language without emitting an unbounded list of monorepo unit IDs. Results are
deterministic, cursor-paged, and include the relevant hotspot project-unit
projection for each page.
MCP structured content is the same result serialized by the corresponding CLI
command with `--format json`; the default CLI renderer remains human-oriented.

`grep_context` / `grep-context` is intentionally a live-worktree query. It
searches the current bytes of registered-language files with a bounded regex,
match limit, and context-line limit. Its `h00/code-intel/source-search/v1`
result labels that source authority explicitly. A containing symbol is attached
only when the exact whole-file hash still matches the pinned immutable
generation; changed or newly added files remain searchable but report
`source_changed_since_generation` or `not_indexed_in_generation` and withhold
stale graph labels. CLI JSON and MCP structured content are identical, including
`context_lines`, truncation, skipped-file evidence, and graph-context coverage.
Successful results are product-bounded below the MCP transport ceiling; narrow
the path/pattern or lower `limit`/`context_lines` when the typed result would be
too large.

The process is bound to one project for its lifetime. Tool arguments cannot
switch `root`, `workspace`, `project`, `data_dir`, or `graph_dir`. Managed
artifact and invalid-publication guards fail closed before mutation. Stdout is
reserved exclusively for JSON-RPC frames; diagnostics go to stderr.

Protocol support:

- current stateless MCP `2026-07-28`, including `server/discover`, per-request
  protocol/client metadata, `resultType`, response server identity, and
  conservative private/immediately-stale cache hints on discovery and tool
  catalogs;
- legacy initialization revisions `2025-11-25`, `2025-06-18`, `2025-03-26`,
  and `2024-11-05` for hosts that have not moved to the stateless era.

The advertised MCP server version is the h00ligan executable's release version,
the same component version reported by `h00ligan --version`.

## Recommended precision providers

Indexing is structural-only by default. Pass `--scip` (or `"scip":true` to MCP
`reindex`) to request best-effort compiler-aware provider evidence. The
structural baseline needs no language indexer. A best-effort refresh publishes
every validated provider result and reports uncovered language/project-unit
scopes honestly. Calls authority has three useful distinctions:

- `complete` covers the provider-resolved invocation population with no known
  source exclusions;
- `qualified` is exact within provider-covered source and lists every known
  excluded region, so positive results remain useful but a zero is not a
  repository-wide negative claim; and
- `partial` or `unavailable` identifies a missing, failed, or invalid provider
  scope rather than silently falling back to structural hints.

Add `--require-complete-calls` (or
`"require_complete_calls":true` with `"scip":true` over MCP) when incomplete
or qualified Calls authority must refuse publication before the current
generation changes.
When source bytes, project inputs, the structural indexer identity, and the
requested capability evidence are all unchanged, CLI `index` returns the
current immutable generation without rerunning providers. MCP `reindex` still
returns a start receipt immediately; its terminal `reindex_status` result
reports the reused generation. Use `--force` (or `"force":true`) only to request
an unconditional fresh build. Provider execution failures are retryable and
therefore never qualify for reuse; a still-missing project root such as
`go.mod` is stable evidence until project inputs change.

Each provider run currently represents one deterministic default build
configuration. In Go, files omitted by that configuration because of build
constraints, `GOOS`, or `GOARCH` are preserved as whole-file
`provider_document_omitted` qualifications rather than poisoning covered Go
results or being mistaken for covered source. Selectable multi-configuration
indexing is not yet exposed; use strict mode whenever negative Calls authority
must span every source configuration.

The release executable contains content-verified private provider artifacts for
Rust, Go, Python, and TypeScript/JavaScript. Users do not install `scip-go`,
`gopls`, Pyrefly, TypeScript, or a second h00ligan installation. Rust uses a
hidden same-executable provider entrypoint. The other providers are
content-addressed private artifacts materialized beneath the selected data
directory; they are implementation details, not separately installed products.
Go, Python, and TypeScript/JavaScript installed-product acceptance runs with no
ambient language toolchain. Rust semantic loading currently still requires a
repository-compatible Cargo/Rust toolchain; structural Rust indexing does not.

`h00ligan status` reports provider coverage per language after publication.
Human indexing output names the active structural/provider/publication phase and
emits a heartbeat every ten seconds while a phase is still running. CLI JSON
and the terminal MCP `reindex_status.result` retain `reused_generation` plus
coarse `phase_timings`. Each timing declares `aggregation: "exclusive"` when
it participates in the additive wall-clock partition or
`aggregation: "concurrent_span"` when it measures an overlapping worker;
concurrent spans are rankable diagnostics and must not be summed. `--profile`
adds the detailed extraction and batch breakdown for performance investigation.
This repository's Devbox is the pinned reference build and test environment.
The one-file builder binds every embedded provider, provider source tree,
patch, lockfile, and transforming script into immutable receipts before it
publishes an artifact.

## Performance battery

Performance is an installed-product contract, not an isolated microbenchmark.
The repository battery builds and verifies the portable executable, creates a
deterministic mixed Rust/Go repository, and uses a fresh explicit data directory
to measure the real CLI, long-lived MCP, provider-backed indexing, publication,
and WATCH boundaries:

```bash
just perf-smoke
just perf
```

The smoke lane uses one cold index, one language change/restore cycle, and
five repetitions of each CLI/MCP query. The full lane uses three independent
cold indexes, three change/restore cycles, and 25 query repetitions. Reports
include every raw sample plus median and p95 summaries, detailed product phase
timings, executable/source receipts, provider versions, host shape, and fixture
identity. Every timing run must also prove Complete Calls authority for its
Rust, Go, Python, and TypeScript populations,
query-positive controls, CLI/MCP JSON parity, exact fingerprint and source-byte
restoration, complete WATCH receipts, and zero new h00ligan or scip-go processes.
A fast sabotage-only contract is available as `just perf-contract` and is
part of the regular h00ligan gate; the timed battery is deliberately opt-in so
normal correctness work does not silently normalize regressions under variable
host load.

Store a machine-local report or compare against a previously reviewed report
without committing host-specific numbers:

```bash
scripts/bench-h00ligan-product.sh full \
  --output .h00ligan/performance/h00ligan-full.json
scripts/bench-h00ligan-product.sh full \
  --baseline .h00ligan/performance/h00ligan-full.json
```

Baseline comparison checks median and p95 for each top-level cold, WATCH, CLI,
and MCP metric. One run is evidence, not a durable threshold: establish a
baseline from repeated quiet-host runs on each supported architecture before
using it as a regression gate. Real-repository A/B runs remain a separate scale
lane because changing repositories are useful performance evidence but are not
deterministic CI fixtures.

## Build from source

The repository pins Rust, Zig, and cargo-zigbuild. From the repository root,
the portable recipe enters Devbox when necessary and produces the same artifact
shape enforced for releases:

```bash
just build-portable
just install
h00ligan --version
```

Linux output is a fully static musl executable. macOS output is a thin native
Intel or Apple-Silicon binary with the documented deployment target and only
Apple system-library dependencies. The build prints its exact artifact path;
installation defaults to `~/.local/bin/h00ligan` and is atomic.
The `cargo-zigbuild` 0.23.0 builder pin was checked against its
[upstream package source](https://github.com/rust-cross/cargo-zigbuild/blob/main/Cargo.toml)
on 2026-08-19; changing it requires the same four-target release gates.

Plain `cargo build --release` remains useful for host development, but inside a
Nix/Devbox shell it may embed that host's dynamic loader. It is therefore not a
distribution or installation artifact. The shared binary verifier rejects such
an artifact instead of calling it portable.

For the rigorous h00ligan-only inner loop, use the repository's pinned Devbox
environment:

```bash
devbox run -- just ci
devbox run -- just ci-product
```

`ci` covers the complete standalone source workspace plus dependency,
portability, performance-contract, release, Action-pin, SBOM/package, and shell
authorities. `ci-product` adds the exact one-file CLI, MCP, WATCH, embedded
provider, and installed performance-smoke boundaries. The executable contract
has sabotage controls, so silently removing a population makes the gate fail.

## Versioning and releases

h00ligan has an independent SemVer train and tags of the form
`h00ligan-vX.Y.Z`. Before 1.0, features advance the minor version, fixes
advance the patch version, and breaking changes advance the minor version.
`h00ligan --version` adds the source revision after `+` as build metadata; the
package version before `+` is the release and MCP server version.

GitHub Releases, changelogs, tags, four native builds, checksums, SBOMs, and
license reports are automated. crates.io publication is intentionally disabled.
See the repository's
[release runbook](../../docs/releasing-h00ligan.md).
