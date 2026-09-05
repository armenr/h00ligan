# Using h00ligan with coding agents

An agent can use the CLI with `--format json` or the [MCP tools](mcp.md).
Neither is a lesser interface. Both answer the same questions from the same
index; MCP adds a persistent process and nonblocking indexing controls.

The objective is to get to a defensible answer with less source scanning.
Use h00ligan for identities and relationships, then read and edit source with
the agent's ordinary tools. Do not use it ceremonially on every file.

## A practical investigation

Suppose you need to change a function without missing a caller or a test:

1. **Establish the boundary.** Check `status`: right repository, generation,
   freshness, and relevant language capability. If unindexed or stale and the
   task authorizes analysis-state writes, index with semantic enrichment or
   use the existing watcher. Wait for the exact terminal outcome.
2. **Resolve the name.** `find` a definition; retain its file and
   `symbol_id`. Resolve ambiguity before using another symbol verb.
3. **Read just enough.** `inspect` gives a bounded dossier; `read` supplies
   exact source and `type` describes members. Request selected sections when
   a full dossier would add noise.
4. **Trace the relevant edges.** `calls` finds incoming callers; `assess`
   gives transitive impact; `tests` identifies potential test entries.
   Use `filter=all` for an inclusive caller investigation.
5. **Check the conclusion.** Follow pagination and keep exclusions/depth
   cutoffs. Corroborate important claims in source. A test path does not mean
   the test passes, and unknown deadness does not authorize deletion.
6. **Make and verify the change.** Edit using normal tools and run the
   project's real tests. Use `diff` before refreshing to compare with the
   indexed baseline, then observe WATCH/reindex and reacquire stale selectors.

With the [example project](getting-started.md#try-the-guided-tour), `greeting`
resolves to `app.py`; `calls` finds `greet` and `test_greeting`;
`tests` identifies `test_greeting`. This is enough to inspect both callers
and select a test. It is not evidence that every Python capability works:
`dead` remains unavailable in 0.3.0.

## Copyable repository guidance

Add this small block to the repository instructions your agents already read
(for example, `AGENTS.md` or `CLAUDE.md`), adjusting the root/data location
and write permission to your project:

```markdown
## Code navigation with h00ligan

Use h00ligan for symbol identity, callers, impact, tests, and project boundaries
when it saves broad source scanning. CLI: request --format json. MCP: use the
discovered tools. Start with status for the intended repository and index.

Use find to resolve ambiguity; carry the exact file/symbol_id into read, type,
inspect, calls, assess, or tests. Follow page.next_cursor without changing the
query. Never combine pages or selectors from different generations.

Preserve authority scope, coverage exclusions, freshness, and depth cutoffs.
Qualified/unknown/empty is not proof of absence. Complete Calls does not imply
dead-code classification is supported. Verify deletion/correctness claims in
live source and run normal tests; h00ligan does not edit source or run tests.

When this task permits updating generated analysis state, use index --scip or
MCP reindex with scip:true, and observe its exact terminal result. Keep WATCH
under one owner. Recovery, force, and capability downgrade are deliberate
choices, not default retries. Analyze only trusted repositories semantically.

Use ordinary file/search tools for unsupported files, current source that
read cannot materialize, and independent verification. Report misleading
h00ligan output with the version, query, scope, and a small reproducer.
```

This teaches tool selection and evidence handling without requiring a hook,
service, login item, or vendor-specific plugin. A separate skill can later
package useful workflows, but should link the [shared contract](reference.md)
rather than redefine it. MCP permission/trust approval belongs to the host;
repository guidance does not silently grant new privileges.

## Avoid expensive or misleading habits

- Don't reindex before every query. Check freshness, or leave WATCH running.
- Don't replace a semantic index with structure merely because `index`
  defaults to structural. Request the capability the investigation needs.
- Don't ask for the whole repository when a file, symbol, page, or section
  would answer the question.
- Don't treat `calls` as “callees,” `tests` as runtime coverage, `audit`
  as cyclomatic complexity, or `diff` as Git diff.
- Don't turn `terminal:true` into success. Inspect the operation state,
  result, and coverage. Keep the operation ID from the call you started.
- Don't prescribe a rebuild for an unchanged unsupported capability.
  [Language limits](languages.md) and [troubleshooting](troubleshooting.md)
  distinguish product limits from repairable setup problems.

## What to retain in your work notes

Keep the question, selected root/generation, exact query and scope, evidence
used, limitations, and the resulting decision. A concise account is more
useful than copying a full tool transcript. If source changes concurrently,
say what was verified against the generation and what was checked live.

For example: “Calls found two source invocations of `greeting` in generation
X, with complete Python invocation coverage and no exclusions. Both callers
were inspected. One test entry was identified; it still needs to be run.
No dead-code conclusion was made.”
