# Product contract and public surfaces

Last verified: 2026-08-28

## One product, three operating modes

The shipped product is one `h00ligan` executable:

- the CLI renders concise text by default and exact structured results with `--format json`;
- `mcp-serve` exposes bounded structured operations over stdio for one repository per process;
- `watch` observes source, project configuration, and toolchain changes and publishes complete
  immutable replacement generations.

The executable owns orchestration and packaging. `h00ligan-engine` owns indexing, publication,
authority, and query semantics. `h00ligan-interface` owns the typed tool registry and MCP
transport. `h00ligan-provider-protocol` owns the private provider process contract.

## Surface map

| Human CLI | MCP tool | Question or operation |
| --- | --- | --- |
| `status` | `status` | What generation exists, is it fresh, and which language evidence is trustworthy? |
| `overview` | `overview` | What are the repository's languages, units, topology, and coverage? |
| `find` | `find` | Which definitions or symbols match this name or pattern? |
| `type` | `type` | Where is the exact type definition and what identifies it? |
| `read` | `read` | What indexed source bytes define this exact symbol? |
| `calls` | `calls` | Which exact call relationships enter or leave this symbol? |
| `assess` | `assess` | What symbol-level change impact is evidenced, qualified, or unknown? |
| `inspect` | `inspect` | What definition, relationships, and local evidence describe this symbol together? |
| `dead` | `dead_code` | Is this code unreachable under the reported Calls authority? |
| `tests` | `tests` | Which indexed tests relate to this code? |
| `audit` | `audit` | Where are coupling and reachability hotspots within the selected scope? |
| `deps` | `deps` | What direct dependencies and dependents cross this file or directory boundary? |
| `grep-context` | `grep_context` | Where does a bounded pattern occur in current registered-language source? |
| `diff` | `diff` | How does the live worktree differ from the immutable generation? |
| `index` | `reindex` | Build and publish a structural or semantic immutable generation. |
| `watch` | `watch` | Start, inspect, or stop continuous refresh. |
| — | `reindex_status` | Has this exact asynchronous MCP reindex reached a terminal receipt? |
| — | `reindex_cancel` | Cancel this exact MCP reindex without disturbing the last good generation. |
| `mcp-serve` | — | Start the repository-bound MCP transport. |

MCP exposes exactly 18 registered tools. `reindex_status` and `reindex_cancel` are transport-side
operation controls because MCP reindex returns immediately; the foreground CLI `index` command
owns its operation until completion. `dead`/`dead_code` and
`grep-context`/`grep_context` are presentation-name differences only.

The standalone surface does not expose source editing, repository initialization, or the removed
`match` prototype. Adding a mutating operation requires an explicit effect, authority, recovery,
and installed-product contract—not a hidden handler.

## Identity, ambiguity, and bounds

`find` results carry opaque `symbol_id` values bound to one repository and immutable generation.
Use one when a name is ambiguous or occurrence identity matters. It fails closed in another
repository or after publication changes the generation.

Typed query results are deterministic and cursor-paged where their result population can grow.
MCP structured content and CLI JSON share the same semantics. The MCP envelope adds protocol,
size, and transport metadata; it does not change the answer.

## Authority and freshness

Every result preserves separate axes:

- structural coverage from exact parsed source;
- compiler-backed Calls coverage by language and project unit;
- immutable-generation identity and publication integrity;
- current-worktree freshness observed during a bounded request.

Generation-bound queries may return useful stale results with an explicit qualification. `diff`
intentionally compares the generation with live source. Source-materializing `read` and `inspect`
refuse a selected file when its current bytes no longer match the indexed record.

Partial, qualified, unavailable, stale, and unknown never mean empty. Negative Calls, impact, or
dead-code conclusions are valid only within the authority reported by that exact result.

## Mutation and lifecycle boundary

Index and WATCH publication are the only shipped repository-analysis mutations. They write only
to the selected data directory. MCP binds the root and data directory at process startup; request
arguments cannot switch either one. Reindex, cancellation, publication recovery, and WATCH retain
the last valid generation until a complete replacement is durably published.
