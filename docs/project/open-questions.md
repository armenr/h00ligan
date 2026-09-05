# Open questions

Last reconciled: 2026-09-05

Only unresolved product choices belong here. Implemented behavior is documented in the
architecture pages and verified by source and executable gates.

## Release decisions

### Final open-source license

The extracted crates retain their existing declarations, but the standalone product's final
open-source license has not been selected. Decide before public release packaging. This does not
block local isolation, correctness work, or private evaluation.

### macOS signing and notarization

Current macOS artifacts are normal native binaries but are not Developer ID signed or notarized.
Choose between unsigned open-source distribution with documented Gatekeeper handling and a signed,
notarized release lane. No persistent service, login item, or elevated installation should be
introduced merely to satisfy this decision.

## Semantic authority breadth

### Python/TypeScript entry roots and reachability

The 0.3.0 documentation tour proves complete Python Calls and useful test paths
without dead-code availability. The current reachability owner admits Rust/Go only.
Which language-owned roots, externally callable APIs, and dynamic execution exclusions
should govern Python/TypeScript classification? Implement the owning policy with
standalone and mixed-language falsifiers; do not equate complete Calls with that policy.
This correctness work is sequenced in the [work plan](work-plan.md), not a reason to
hide already-useful caller queries or repeat an unchanged index.

### Managed compiler toolchains

Structural indexing is self-contained; compiler-backed Rust and Go Calls currently need a
repository-compatible Cargo/Rust or Go toolchain, respectively. Decide whether h00ligan should
detect only, recommend installation, or download verified toolchains into product-owned state.
The answer must define consent, checksums/signatures, offline behavior, version drift, pruning,
and rollback.

### Multiple build configurations

Each provider currently certifies one deterministic default configuration. Go build constraints,
TypeScript project references/configurations, Python environments, Rust feature sets, and target
triples can describe additional valid programs. Determine the smallest user-facing configuration
model that preserves exact per-configuration authority without multiplying work invisibly.

## Product validation

### Comparative value

Does h00ligan materially reduce wrong or unsupported maintenance conclusions compared with
ordinary tools and credible code-intelligence alternatives? Run the controlled evaluation contract
before treating the differentiation thesis as proven.

### Agent adoption

Will agents select and interpret CLI/MCP operations from concise repository guidance, or is a
vendor-neutral skill package useful? Measure real use first. Avoid mandatory hooks, transcript
scraping, or agent-specific policy that creates another product-semantic authority.

## Future scope

### Additional languages and domains

PHP is the next likely programming-language candidate. SQL lineage and shell/config analysis may
be valuable, but their questions and authority models differ from ordinary Calls graphs. Decide
from demonstrated workflows and fixtures rather than adding parsers for coverage theater.

### Standalone protocol schema names

Some persisted and result schemas retain `h00/...` lineage names. They are identifiers, not a
runtime dependency. Rename them only if the value of a clean standalone namespace outweighs a
schema migration before the first public release.
