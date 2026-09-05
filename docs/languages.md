# Languages, projects, and evidence depth

h00ligan indexes Rust, Go, Python, and TypeScript/JavaScript, including JSX/TSX.
That is not a claim that every query has equal depth in every language. Start
with the question you need answered, then check its evidence.

## What is included, and what the project supplies

| Language | Included in the executable | Needed for semantic indexing |
| --- | --- | --- |
| Rust | Structural parser and private rust-analyzer-based provider | Compatible Cargo/Rust toolchain, resolvable project dependencies and build inputs. |
| Go | Structural parser and private gopls-based provider | Compatible Go toolchain and resolvable module/workspace dependencies. |
| Python | Structural parser and private Pyrefly-based provider | Recognized project configuration and resolvable imports/type information; no ambient Python executable required by the provider. |
| TypeScript / JavaScript | Structural parsers and private TypeScript-Go-based provider | Recognized project configuration and resolvable packages/types; no ambient Node/TypeScript executable required by the provider. |

Users install **one h00ligan executable**, not `scip-go`, gopls, rust-analyzer,
Pyrefly, or a separate h00ligan helper. Private embedded components can be
materialized in the selected data directory. That is product-owned runtime
state, not a prerequisite to install manually.

`index` is structural only and does not execute project toolchains.
`index --scip` explicitly requests compiler-backed enrichment. SCIP is the
provider interchange format, not an index file you need to generate yourself.
An existing root `index.scip` is not automatically adopted or overwritten.

The included provider is **not** a package manager. Set up your project's
normal dependencies when they are needed to resolve imports. “No ambient
Python/Node required” does not mean every missing external library can be
inferred. Automatic compiler/toolchain download is not implemented.

## Depth and known limits

| Question | Rust / Go | Python / TypeScript / JavaScript |
| --- | --- | --- |
| Definitions, source, types, structural relationships | Supported; valid but unrepresented syntax is qualified. | Supported; language-owned extraction and qualification. |
| Explicit source callers and test-call paths | Provider-backed, scoped to the analyzed configuration. | Provider-backed, scoped to the analyzed configuration. |
| Impact and dossiers | Structural and semantic facets, each with its own evidence. | Useful structural/caller/test facets; classification-dependent risk can be unavailable. |
| Reachability / dead-code classification | Implemented, with evidence and language-specific limits. | **Not implemented in 0.3.0.** Complete Calls alone does not make `dead` available. |

The [quickstart](getting-started.md#try-the-guided-tour) is a concrete Python
control: two callers and one test are found, Calls is complete, but `dead`
refuses with `reachability_evidence_unavailable`. `status` can therefore report
unclassified nodes and attention despite successful semantic indexing. Do not
repeat indexing to “fix” an unimplemented capability. In a mixed repository,
classification of one language does not certify another.

For every language, preserve these boundaries:

- Explicit calls are not a runtime trace. Reflection, callbacks, callable
  values, decorators, hooks, and dynamic dispatch can retain uncertainty.
- Build/configuration exclusions are not dead code. A Go file excluded by
  the current platform or tags is not proven unused on another platform.
  Rust features, macros/build scripts, and alternate targets also matter.
- Missing provider documents or unresolved local targets qualify coverage;
  h00ligan must not convert them into “no callers.”
- A test relationship is an evidenced path to a runnable test entry, not a
  passing test, measured coverage, or support for every test framework.
- Exported APIs may have consumers outside the selected repository.
  A local absence claim is not proof that deleting an API is safe.

Strict `--require-complete-calls` is useful for tasks that demand full applicable
Calls coverage, but can legitimately reject a repository with configuration
exclusions. Inspect the reason; don't weaken the task's conclusion to hide it.

## Monorepos and workspaces

Select the repository boundary once. h00ligan inventories project units and
analysis contexts under it rather than treating every source file as one
flat program. Examples of recognized inputs include:

- Cargo packages/workspaces, target manifests, lockfiles, and local configuration;
- Go modules/workspaces, member inputs, and local replacement relationships;
- Python `pyproject.toml`, supported requirements/Pipfile and uv workspace
  shapes, and supported analysis configuration;
- TypeScript/JavaScript packages, supported npm/pnpm workspace shapes,
  `tsconfig` inheritance and project references.

“Recognized” does not mean arbitrary dynamic configuration is understood.
Malformed, unresolved, conditional, or unsupported relationships are explicit
gaps. Loose files can have useful structural facts without belonging to a
semantic execution root. Provider imports do not automatically expand the
repository's owned source population.

Use `overview`, `status`, and result scopes to see what was actually admitted.
A complete provider in one unit/language cannot certify missing sibling units.
Cross-language runtime connections such as HTTP calls or Python spawning a
TypeScript process are not automatically inferred as function Calls edges.

Repository ignore rules affect discovery. Generated/cache output should stay
ignored; do not work around a gap by indexing dependencies as project source.
Supported source symlinks are refused rather than followed silently; some
project/semantic-input symlinks have separately validated ownership rules.

## Toolchain and configuration changes

### Go build tags

**Released 0.3.0 discards explicit `GOFLAGS`.** The development repair retains
supported flags and has passed local Linux AMD64 source and installed-product
checks. It is not in the released binaries; rebuilding an unchanged 0.3.0 index
with different tags does not work around that release's defect.

With the repaired build, select tags explicitly when starting the process:

```bash
GOFLAGS='-tags=integration,contract' h00ligan index --scip
GOFLAGS='-tags=integration,contract' h00ligan watch --scip
GOFLAGS='-tags=integration,contract' h00ligan mcp-serve
```

The resolver adds `-mod=readonly` if absent. It preserves Go's quoted-field
syntax, including `GOFLAGS='"-tags=integration contract"'`. Supported options
are `-tags`, `-mod=readonly`, `-p`, `-race`, `-msan`, `-asan`, `-trimpath`,
`-buildvcs`, `-a`, `-v`, and `-x`. Unsupported flags are reported rather than
discarded. Module writes, vendor mode, alternate manifests, source overlays,
and compiler/package redirection need additional input tracking before support.

The process captures its environment at startup: changing another shell's
`GOFLAGS` does not change a running MCP server or watcher. Restart with the
desired selection and reindex; a changed selection cannot reuse the previous
configuration's semantic authority. Results describe that selection, not the
union of every platform/tag combination. Files excluded by it remain qualified.
An intentional reduction from complete to partial coverage can require
`--allow-capability-downgrade` / `allow_capability_downgrade:true`.

Explicit environment values are used, not the mutable per-user `go env -w`
defaults (`GOENV=off`). Automatic Go toolchain downloads remain disabled
(`GOTOOLCHAIN=local`). Prepare the project's compiler and dependencies first.

### Other input changes

Toolchain identity and project inputs participate in semantic validity.
WATCH observes relevant source/configuration changes and reconciles against
current evidence; identity changes can require semantic recertification rather
than a cheap body-edit refresh. A provider result that no longer matches its
inputs is discarded instead of certified under an old identity.

After changing a compiler, feature configuration, workspace membership, or
dependency resolution, inspect `status` and the next indexing receipt. A
previously warm query timing does not predict the cost of recertification.

## Trust and future languages

Structural parsing is not permission to execute a repository's build scripts.
Semantic analysis can run project toolchains and build logic. Use trusted
projects; the provider process boundary is not an untrusted-code sandbox.

PHP, SQL lineage, shell/config relationships, and arbitrary XML/YAML/JSON
analysis are not shipped language capabilities. Some configuration formats
are **inputs to project discovery**, not fully indexed programming languages.
New support needs meaningful questions, truthful evidence, and lifecycle
tests—not merely another parser in a list.
