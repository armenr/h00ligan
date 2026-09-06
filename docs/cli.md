# CLI workflows

[Docs](README.md) / CLI field guide

**A good investigation starts with a question, not a thousand-line dump.**

The examples use the [guided-tour project](getting-started.md#try-the-guided-tour).
Index it first, or substitute your own repository root, symbols, and file paths.

[Understand a definition](#find-and-understand-a-definition) ·
[Trace a change](#before-changing-a-function) ·
[Explore boundaries](#understand-a-boundary-or-choose-a-refactor) ·
[Review dead code](#investigate-dead-code-candidates) ·
[Watch edits](#keep-the-index-current-with-watch)

The CLI prints human-readable text by default. Every query also accepts
`--format json`; [the reference](reference.md) explains shared bounds and fields.

## Find and understand a definition

“I’ve found the name. Now what am I actually looking at?”

```bash
h00ligan --root examples/quickstart find greeting --name --definitions-only
h00ligan --root examples/quickstart read greeting --file app.py
h00ligan --root examples/quickstart type GreetingStyle --file app.py
h00ligan --root examples/quickstart inspect greeting --file app.py
```

`find` resolves identity; `read` returns source; `type` lists structural members;
`inspect` combines source, structure, callers, tests, and warnings into a concise
dossier. A missing facet does not necessarily make the other facets unusable.

Use `--sections source,callers,tests` with `inspect` to request only those facets.
If a dossier preview is too short, use its dedicated verb and pagination.

For file navigation, force path interpretation:

```bash
h00ligan --root examples/quickstart find app.py --path --definitions-only
```

Quote glob patterns such as `'*Handler'` so your shell doesn't expand them.
There is no fuzzy “pick the nearest symbol” fallback for an ambiguous query.

## Before changing a function

“If I change `greeting`, who needs my attention?”

```bash
h00ligan --root examples/quickstart calls greeting --file app.py --filter all
h00ligan --root examples/quickstart assess greeting --file app.py --filter all --depth 3
h00ligan --root examples/quickstart tests greeting --file app.py
```

`calls` answers **who calls this symbol**, including source-level execution
origins that are not named functions. It is not an outgoing-callee browser.
`assess` adds transitive impact—the “blast radius”—with callers, tests, and
qualified risk information. Its depth bound is explicit; a cutoff is not proof
that no further dependents exist. `tests` follows evidenced invocation paths
to runnable test entries; it does not execute your test suite.

`calls` and `assess` default to the `live` caller filter, not the full population.
Use `all` for an inclusive investigation; other choices are `dead` and
`test_only`. These are indexed classifications, not runtime tracing.

After making the change, run the project's normal tests yourself. Static
relationships help you choose what to inspect and test; they don't replace tests.

In the tour, `calls` identifies `greet` and `test_greeting`; `tests` identifies
`test_greeting`. Read those callers before changing the return format. You have
a concrete review-and-test list, not a guarantee that a change is safe.

## Understand a boundary or choose a refactor

“Is this module doing too much, or just used a lot?”

```bash
h00ligan --root examples/quickstart overview
h00ligan --root examples/quickstart deps app.py
h00ligan --root examples/quickstart audit --scope all --min-fan-in 1
```

`deps` separates direct dependencies from direct dependents crossing the chosen
file or directory boundary. It is not a transitive impact query. `overview`
shows project units, relationships, and qualified health. `audit` ranks observed
incoming coupling and reports qualified dead-code health; it does **not** rank
cyclomatic complexity or prove an architectural design is good or bad.

`audit` defaults to production scope and a fan-in threshold of 20. On a small
project, a lower threshold may be more useful. `--scope tests`, `conditional`,
or `all` changes the population; preserve that scope when comparing results.

High fan-in can describe a healthy shared utility. Read the dependencies and
callers before proposing a split. Use the numbers to choose where to look,
not to automate architectural taste.

## Investigate dead-code candidates

“What deserves a closer look—not an automatic delete?”

For a Rust/Go project with current reachability and complete relevant Calls evidence:

```bash
h00ligan dead --production-only
h00ligan dead --production-only --limit 20 --format json
```

Pass a symbol and optional `--file` for one verdict. A report is a review queue,
not an automatic deletion plan. Public APIs, configuration-excluded code,
callbacks, dynamic dispatch, and missing evidence need different treatment.
Never equate zero rows, unknown health, or unavailable authority with “safe to delete.”

In 0.3.0, Python/TypeScript-only projects lack the reachability classification
required by `dead`, even when their Calls evidence is complete. See
[language limits](languages.md#depth-and-known-limits).

## Compare the index with an edit

“What changed since the map was made?”

```bash
h00ligan --root examples/quickstart diff app.py
h00ligan --root examples/quickstart grep-context 'Hello' --path app.py -C 1
```

`diff` compares the indexed structural snapshot with current files, **not** two
Git commits. Run it before reindexing if you want to see the edit against that
baseline. `grep-context` searches live registered-language source; it is not a
general replacement for searching Markdown, YAML, or arbitrary text with `rg`.

While the index is stale, graph queries can return qualified snapshot answers.
`read` refuses a selected file whose bytes changed; `inspect` can withhold its
source facet. Read live files normally or refresh the index. Do not try an old
line number and assume it still names the same definition.

## Keep the index current with WATCH

```bash
h00ligan watch --scip
```

WATCH is foreground work, not an installed service. It indexes/reconciles, then
observes changes until Ctrl-C. Query the same root and data directory from other
processes. An MCP server notices external publication on later requests.

By default, an existing stronger generation is preserved until an acceptable
replacement is ready. If you explicitly want current structure published before
slower semantics finish:

```bash
h00ligan watch --scip --allow-capability-downgrade
```

That flag allows a temporary semantic downgrade. Readers can see a current
structural generation with unavailable Calls evidence before a later semantic
generation arrives. Each publication is internally complete; do not mistake the
structural publication for completed semantic enrichment.

Use `watch --scip --require-complete-calls` when a non-complete Calls replacement
must not publish. Don't combine this with an expectation of early, weaker output.
No mode turns a failed provider into a successful semantic result.

Defaults: 75 ms debounce, 1 s publication-control probe, 60 s deep integrity
reconciliation. **75 ms is a quiet window, not an end-to-end latency promise.**
Compiler work and publication follow it. Leave these defaults alone initially;
profile your workload before tuning. `--format json` emits one event object per
line, not a single JSON document.

## Scripts and automation

Use `--format json`, check the process exit status, and inspect the result's
authority/freshness before acting. Diagnostics go to stderr. Query domain errors
have typed JSON, but early argument, startup, and binding failures can still
be stderr-only; do not assume every nonzero exit has a JSON body.

On pageable verbs, continue with the returned `page.next_cursor`, keeping the
same arguments and generation. Do not raise `--limit` beyond its advertised
bound. [Pagination and limits](reference.md#pagination-and-bounds) explain the
non-pageable previews and the source-character limit used by `read`.

Next: [the command reference](reference.md) for exact flags, or
[agent prompts](agent-integration.md#give-your-agent-a-real-job) to delegate an investigation.
