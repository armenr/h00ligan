# h00ligan — quick guide

**Know the code. Then make your move.**

h00ligan maps source definitions, callers, tests, and dependencies so humans
and coding agents can understand a codebase before changing it. One local
executable provides a human CLI, structured CLI output, repository-bound MCP,
and WATCH. No database server, GPU, API key, or persistent service is required.

This compact guide also ships inside release archives. Full guides live in the
[documentation home](https://github.com/armenr/h00ligan/blob/main/docs/README.md).

## Install and prerequisites

**0.3.0** ships Linux AMD64, Linux ARM64, and Apple Silicon archives plus
`SHA256SUMS`. Intel Mac is deferred. The repository and downloads are public.
Verify the downloaded archive against the checksum
manifest before extracting and installing its `h00ligan` on your `PATH`.
Linux products are static; Apple Silicon targets macOS 11.0+ (acceptance runs
on a current native runner, not every older OS). macOS is not Developer ID
signed/notarized and may require normal OS approval.

From an extracted archive, on Linux or macOS:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 ./h00ligan "$HOME/.local/bin/h00ligan"
"$HOME/.local/bin/h00ligan" --version
```

Add that directory to your shell's `PATH`, or keep using the full path.
The 0.3.0 executable reports `h00ligan 0.3.0+0bd9334`.

All structural parsers and private semantic providers are included. Rust/Go
semantic indexing still needs compatible project Cargo/Rust or Go tools and
resolvable dependencies. Python/TypeScript providers need no ambient Python
or Node executable, but still need resolvable project configuration/imports.
No separate SCIP indexer install is needed. Devbox is for building/testing
h00ligan, not for running a release. Use semantic indexing only on trusted
repositories: project toolchains and Rust build scripts can execute.

## CLI: start with a question

From a trusted Git repository:

```bash
h00ligan index --scip
h00ligan status
h00ligan overview
h00ligan find '*Handler' --name --definitions-only
```

Use `--root /path/to/project` for an explicit boundary, required outside Git.
The default index is `<root>/.h00ligan/code-intel`; use the same `--data-dir`
on every command to select another. Relative data paths anchor to the root.

Use a returned name and file with `read`, `type`, `inspect`, `calls`,
`assess`, or `tests`. Exact `symbol_id` values from `find` disambiguate
occurrences but must be reacquired after the generation changes.

| Question | Verb |
| --- | --- |
| Find a definition / read it / inspect its type | `find`, `read`, `type` |
| Show a concise dossier | `inspect` |
| Who calls it? What could a change affect? | `calls`, `assess` |
| Which tests could exercise it? | `tests` (does not run tests) |
| What dependencies cross a file/directory? | `deps` |
| Review dead candidates / incoming-coupling hotspots | `dead`, `audit` |
| Compare live source with the index / search live source | `diff`, `grep-context` |
| Inspect index truth / repository structure | `status`, `overview` |

Text is the default. Add `--format json` for scripts/agents and inspect errors,
authority, freshness, and pagination. `calls` means incoming callers, not
outgoing callees. Use `--filter all` for the full caller population.
`audit` is not cyclomatic complexity; `diff` is not Git diff.

`index` alone is structural. `--scip` requests best-effort semantics;
`--scip --require-complete-calls` refuses incomplete applicable Calls
coverage. Complete Calls does **not** enable unimplemented classification:
Python/TypeScript reachability/dead-code classification is unavailable in
0.3.0. Caller/test queries can still work. Do not interpret that gap as zero
dead code or fix it by repeatedly reindexing.

Leave `h00ligan watch --scip` running for updates; Ctrl-C stops it. WATCH
can preserve a stronger last-good generation while semantics are pending.
`--allow-capability-downgrade` explicitly permits early structural output
and temporarily weaker semantic evidence. It is not a generic retry option.

## MCP: the same answers

Configure your MCP client's stdio server to execute:

```text
/absolute/path/to/h00ligan --root /absolute/path/to/project mcp-serve
```

Host configuration syntax varies. Use explicit paths, keep stdout free of
shell banners, and use the host's approval/reconnect flow. Startup does not
index. One process owns one root/data directory; requests cannot switch them.

The 18 tools are:

```text
reindex, reindex_status, reindex_cancel, watch, type, read, calls, assess,
inspect, dead_code, status, find, tests, overview, audit, deps,
grep_context, diff
```

Call `reindex` with `{"scip":true}`, retain its `operation_id`, and poll
`reindex_status` with that exact ID. Require `terminal:true` **and**
`state:"succeeded"`, then inspect result coverage. Cancellation uses
`reindex_cancel` and the same ID. For continuous refresh use `watch`
with `{"action":"start","scip":true}`; inspect/stop with action-only
`{"action":"status"}` / `{"action":"stop"}`.

Query arguments mirror CLI flags: `read` takes
`{"symbol":"Name","file":"relative/path"}`; `find` takes
`{"query":"Name","mode":"name","definitions_only":true}`.
Hyphenated flags become snake-case keys; section lists become arrays.
`dead` is `dead_code`, and `grep-context` is `grep_context`.
MCP wraps the same typed query result as CLI JSON; index lifecycle envelopes
differ. Closing MCP stops its watcher/providers, not the durable index.

## Interpret results correctly

Results separate immutable authority from `repository.live_inputs.freshness`.
Stale graph evidence can be useful when labeled as such; `read` refuses
changed selected source and `inspect` can withhold that facet. Qualified
or unknown is not empty. Complete evidence is configuration- and scope-bound,
not a guarantee about all runtime behavior or every build variant.

On pageable verbs follow `page.next_cursor` with unchanged arguments. Most
limits are 1–100 items; `read` is 1–20,000 Unicode characters, default 8,000.
`inspect`/`overview` use previews; `diff`/`grep-context` have
no cursor and may require narrower scopes. Don't combine generations.

Schema identifiers retain historical names, not runtime dependencies:
overview uses `h00/code-intel/overview/v4`; audit uses
`h00/code-intel/audit/v2`. Treat schemas as versioned contracts, not prose
to scrape. Modern MCP clients receive structured content; older supported
clients receive the JSON in text content.

## More detail

- [Getting started and guided tour](https://github.com/armenr/h00ligan/blob/main/docs/getting-started.md)
- [How it works](https://github.com/armenr/h00ligan/blob/main/docs/how-it-works.md)
- [Human CLI workflows](https://github.com/armenr/h00ligan/blob/main/docs/cli.md)
- [MCP setup and lifecycle](https://github.com/armenr/h00ligan/blob/main/docs/mcp.md)
- [Agent playbook](https://github.com/armenr/h00ligan/blob/main/docs/agent-integration.md)
- [Shared verb/result reference](https://github.com/armenr/h00ligan/blob/main/docs/reference.md)
- [Language depth and limits](https://github.com/armenr/h00ligan/blob/main/docs/languages.md)
- [Troubleshooting](https://github.com/armenr/h00ligan/blob/main/docs/troubleshooting.md)
- [Development and gates](https://github.com/armenr/h00ligan/blob/main/docs/development.md)
- [Release runbook](https://github.com/armenr/h00ligan/blob/main/docs/releasing-h00ligan.md)
