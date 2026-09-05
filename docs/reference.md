# CLI and MCP reference

One repository model; two ways to ask it questions. The CLI's text renderer is
for people, `--format json` is for scripts and CLI-using agents, and MCP serves
the same typed query results through tools. This is the shared reference for
the **0.3.0** release. Use `h00ligan <verb> --help` or MCP tool discovery for
the exhaustive argument schema of your installed build.

## Choose a verb by the question

| Question | CLI | MCP | What the answer means |
| --- | --- | --- | --- |
| What can I trust right now? | `status` | `status` | Publication, freshness, capability coverage, classification, and remedies. |
| What is this repository made of? | `overview` | `overview` | Project units, topology, previews, and qualified health. |
| Where is this definition? | `find QUERY` | `find` | Matching names/paths, kinds, and exact symbol selectors. |
| What defines this type? | `type SYMBOL` | `type` | Structural members, methods, and represented relationships. |
| Show me its source. | `read SYMBOL` | `read` | A paged source slice whose file still matches the indexed bytes. |
| Who calls this? | `calls SYMBOL` | `calls` | Incoming, provider-evidenced source invocations—not outgoing callees. |
| What could this change affect? | `assess SYMBOL` | `assess` | Transitive impact/blast radius, callers, tests, and qualified risk. |
| Give me the useful context together. | `inspect SYMBOL` | `inspect` | A concise dossier of source, structure, callers, tests, and warnings. |
| What tests could exercise this? | `tests SYMBOL` | `tests` | Runnable test entries connected through evidenced call paths; no test execution. |
| What code deserves a dead-code review? | `dead [SYMBOL]` | `dead_code` | Qualified candidates or a single verdict, when reachability evidence exists. |
| Where is coupling concentrated? | `audit` | `audit` | Ranked incoming coupling and qualified per-unit dead-code health, not complexity. |
| What crosses this file/directory boundary? | `deps PATH` | `deps` | Direct dependencies and dependents, not transitive blast radius. |
| Where does this text occur now? | `grep-context PATTERN` | `grep_context` | Live registered-source search with a match limit and qualified symbol context. |
| What changed since indexing? | `diff [PATH]` | `diff` | Live structural changes against the indexed generation, not Git history. |
| Build or refresh the index. | `index` | `reindex` | Structural by default; explicit `--scip` / `scip:true` requests semantics. |
| Observe that refresh. | Foreground progress | `reindex_status` | Exact operation progress and terminal receipt. |
| Cancel that refresh. | Ctrl-C | `reindex_cancel` | Cancel the exact operation; never infer success from cancellation acceptance. |
| Keep the index current. | `watch` | `watch` | Foreground CLI watcher, or MCP `start` / `status` / `stop`. |
| Connect an MCP client. | `mcp-serve` | — | Start stdio transport, bound to one root and data directory. |

There are **18 MCP tools**. No source-editing tool, `init`, `replace_symbol`,
or `match` is shipped. `--help`, `--version`, and server startup are CLI concerns.

## The deliberate surface differences

| CLI | MCP equivalent |
| --- | --- |
| Global `--root` and `--data-dir` | Server launch arguments only; never per-request inputs. |
| `read greeting --file app.py --format json` | Tool `read`, arguments `{"symbol":"greeting","file":"app.py"}`. |
| `find greeting --name --definitions-only` | `{"query":"greeting","mode":"name","definitions_only":true}`. |
| `find app.py --path` | `{"query":"app.py","mode":"path"}`. |
| `--sections source,callers,tests` | `"sections":["source","callers","tests"]`. |
| Hyphenated flags, e.g. `--require-complete-calls` | Snake-case keys, e.g. `"require_complete_calls":true`. |
| Human text, or `--format json` | Structured tool result; no `format` input. |
| Index runs until it finishes | `reindex` returns immediately; poll its exact `operation_id`. |
| WATCH emits text or JSON event lines | `watch` returns lifecycle/status objects. |
| Index/WATCH `--jobs`, `--debug`, `--profile` | CLI-only diagnostic/scheduling options. |

The query result contract is shared, not the whole transport. MCP adds tool
errors, protocol negotiation, and an envelope. Index progress and operation
receipts are not byte-identical to the foreground CLI index report.

## Identity, scope, and defaults

Symbol verbs accept a name or an opaque `symbol_id` returned by `find`. Add
`--file` / `file` to disambiguate names. An exact ID identifies one occurrence
in one repository **and generation**; reacquire it after publication changes.
Ambiguity is an error with candidates, not permission to choose the first row.
File selectors must stay within the bound repository.

`find` defaults to `auto` name/path interpretation. Force `name` or `path` when
intent matters. Its optional `kind` uses structural vocabulary, not a single
closed Rust-specific enum; inspect actual results before filtering by kind.

`calls` and `assess` default to `live`: exclude `Dead`/`Orphan` classifications,
**not** exclude tests or prove execution. `all` is inclusive, `dead` selects
those dead/orphan classes, and `test_only` selects that indexed class. In an
unclassified language, this filter cannot manufacture classification evidence.

`inspect` sections: `source`, `structure`, `callers`, `field_usage`, `tests`,
`warnings`. `assess` sections: `blast_radius`, `callers`, `tests`, `risk`.
Omit sections for all. `assess` defaults to depth 3; range 1–10. Preserve any
reported depth cutoff in conclusions about completeness.

`audit` defaults to `scope=production`, `min_fan_in=20`, and
`min_dead_ratio_percent=10`. Other scopes: `conditional`, `tests`, `all`.
`dead --production-only` / `production_only:true` filters the full candidate
report; `dead SYMBOL` selects a single verdict.

## Pagination and bounds

| Result | Default limit | Maximum | Continuation |
| --- | --- | --- | --- |
| `find`, `audit` | 20 items | 100 | `page.next_cursor` |
| `calls`, `type`, `tests`, `deps`, full `dead`, `assess` impact | 50 items | 100 | `page.next_cursor` |
| `read` | 8,000 Unicode characters | 20,000 | `page.next_cursor` |
| `overview` | 50 rows per preview | 100 | No cursor; use the dedicated query for detail. |
| `inspect` | Facet previews | Serialized result size limit | No top-level limit/cursor; use dedicated queries. |
| `diff`, `grep-context` | 50 items | 100 | No cursor; narrow the path/pattern if truncated. |

For pageable results, `page.returned` is this page, `page.total_items` is the
selected population, and `page.has_more` / `page.next_cursor` tell you whether
to continue. `assess` pages impact, not every optional preview. Serialized
size limits can reduce a requested page; an irreducibly large result is a typed
error, not silently cut JSON. The minimum limit is 1.

Continue with the same verb, selector, filters, sections, depth, and limit.
Copy the cursor unchanged. If the generation changes or the cursor expires,
restart the query; don't splice pages from different snapshots.

For example, first request `calls` with
`{"symbol":"greeting","file":"app.py","filter":"all","limit":1}`.
If `page.has_more` is true, repeat those arguments with `"cursor"` set to the
returned `page.next_cursor`. The CLI uses the same pattern with `--cursor`.
`read` limits count characters, not lines or UTF-8 bytes.

## Read the answer, including its qualifications

Typed queries carry `schema_version`, generation/repository identity, and
operation-specific evidence. There is no universal boolean that certifies
every possible conclusion. Check the selected result and facet:

- **Authority:** the represented population, provider, scope, exclusions, and
  completeness of the particular question.
- **Freshness:** whether current inputs still match the immutable generation;
  inspect `repository.live_inputs.freshness`, status, and result qualifications.
  Its `per_file_non_atomic` consistency means observation during the request,
  not a repository-wide filesystem transaction.
- **Bounds:** returned page, previews, depth cutoffs, and omitted populations.

`complete` means complete for the named evidence and configuration—not runtime
tracing or every possible program configuration. A qualified empty result is
not proof of absence. `not_applicable`, `unavailable`, and `unknown` are not zero.
Complete Calls is not the same as reachability/deadness support; see
[language depth](languages.md#depth-and-known-limits).

CLI query errors use an `error` object with a stable code and supporting detail.
MCP tool errors are distinguishable from JSON-RPC/transport failures. Check
the error before reading normal result fields; consult
[troubleshooting](troubleshooting.md) for the next action.
