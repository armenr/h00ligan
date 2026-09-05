# Product contract and public surfaces

Last verified: 2026-09-05 (released 0.3.0)

## One product, shared query semantics

The shipped product is one `h00ligan` executable:

- CLI: human text by default, typed query results with `--format json`.
- MCP: bounded tools over stdio, one repository/data binding per process.
- WATCH: source/configuration/toolchain observation and immutable publication.

The executable crate owns assembly and CLI rendering. `h00ligan-engine`
owns indexing, publication, authority and queries; `h00ligan-interface`
owns the tool adapters and MCP transport; `h00ligan-provider-protocol` owns
the private provider process contract.

The canonical [surface map](../reference.md#choose-a-verb-by-the-question)
defines every CLI/MCP pairing. Do not create a second semantic vocabulary in
host-specific skills or instructions. MCP has exactly 18 tools; its two
reindex-control tools serve the asynchronous lifecycle, while foreground CLI
indexing owns the operation until it ends. `dead` / `dead_code` and
`grep-context` / `grep_context` are spelling differences.

`calls` is incoming explicit source invocations, not outgoing callees.
`assess` is bounded transitive impact; `deps` is a direct boundary view.
`tests` identifies runnable test entries through evidenced paths, not
runtime coverage. `audit` ranks observed coupling, not cyclomatic complexity.
Source editing, `init`, `replace_symbol`, and `match` are not shipped.

## Identity and bounds

`find` returns opaque `symbol_id` values bound to repository, generation
and occurrence. A changed generation requires a new selector. Ambiguity is
reported, not resolved by choosing an arbitrary candidate.

The engine owns typed query results and product size/page/depth bounds before
transport. CLI JSON and MCP structured content share the result contract.
MCP adds protocol and tool-error envelopes, not different evidence. CLI index
and MCP operation wrappers deliberately have different lifecycle shapes.

## Authority and freshness

Keep structural coverage, compiler-backed Calls, classification, publication
integrity, repository identity, and live freshness distinct. Complete Calls
does not establish reachability support: the 0.3.0 classification owner admits
Rust/Go, not Python/TypeScript. [Language depth](../languages.md) records the
user-visible consequences.

Generation-bound queries can answer with explicitly stale immutable evidence.
`diff` intentionally compares it with live source. `read` refuses a
selected file whose bytes changed; `inspect` can withhold its source facet
while preserving other usable facets. A qualified empty result is not a
confident negative conclusion. See [publication and authority](publication-and-authority.md).

## Effects and lifecycle

Normal queries do not edit project source. Index/WATCH write generated
analysis state to the selected bundle, and its managed ignore file preserves
local generated-state hygiene. Semantic analysis may additionally invoke
project compilers/build scripts and their normal build effects; process
isolation is not a sandbox for untrusted repositories.

MCP root/data binding is fixed at startup. Exact-ID reindex control, cancellation,
recovery and publication retain the last valid generation until an admissible
replacement is durable. Each published generation is internally complete.
Opt-in staged WATCH can publish weaker structural evidence before later
semantic enrichment; it must not describe the first publication as completed
semantic work.
