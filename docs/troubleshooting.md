# Troubleshooting

[Docs](README.md) / Troubleshooting

**Let’s get you unstuck. Start with the symptom.**

Start with `h00ligan --version` and `h00ligan status` for the intended root/data
directory. Keep the error code and scope; they explain which next step matters.
Do not begin by deleting the index, using `--force`, or reinstalling providers.

[Can’t connect?](#setup-and-connection) ·
[Answer looks wrong?](#coverage-and-answers) ·
[Index or WATCH trouble?](#indexing-and-watch) ·
[Need recovery?](#publication-recovery)

## Setup and connection

| Symptom | What to check / do |
| --- | --- |
| `h00ligan` is not found | Use its full installed path, then fix your shell's `PATH`. A GUI MCP host may use a different environment. |
| Release link is inaccessible | Use the public [0.3.0 release page](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0). Check the tag, asset name, network/proxy, and any GitHub error; an account invitation is not required. |
| An Intel Mac archive is absent | Intel Mac is deferred. 0.3.0 ships Linux AMD64/ARM64 and Apple Silicon only. |
| macOS refuses to open the binary | Verify its release checksum and use the normal macOS approval UI if you trust it. Do not disable security globally. |
| MCP is connected but the index is unavailable | Discovery does not index. Call `reindex`, or run CLI `index`, with the intended semantic mode. |
| MCP tools are missing or an old version is loaded | Check the configured executable and reconnect/restart that server through your client. A running process does not change when a file is upgraded. |
| MCP startup hangs | Confirm the exact binary can run `--version` and `status` with the same root/environment. Check host stderr/logs and wrappers. `mcp-serve` is a stdio server: waiting silently for protocol input in a terminal is normal. |
| CLI and MCP appear to see different code | Compare their root, data directory, version, and generation. Request-level MCP root switching is not supported. |

## Coverage and answers

| Symptom | Meaning and next step |
| --- | --- |
| Calls unavailable after `index` | Structural mode was requested. Use `index --scip` / `reindex {"scip":true}` if you need semantics. |
| Provider failed or could not resolve a toolchain | Rust/Go need compatible project tools. Check that project's normal build/dependency setup and the provider's reported cause. Python/TS providers are embedded; don't install an unrelated SCIP command as a workaround. |
| A loose file has no provider execution root | Check the recognized manifest/workspace ownership. Structural source can exist outside a configured semantic project. |
| Provider omitted documents / build variants | Inspect the named files and configuration. Excluded/unresolved code is not dead. Best-effort queries retain qualification; strict Calls mode may properly refuse publication. |
| Python/TS Calls complete, but nodes unclassified or `dead` unavailable | Reachability classification is not implemented for these languages in 0.3.0. Caller/test queries can still work. Repeating the index does not enable it. |
| `read` reports changed source | Its selected file no longer matches the indexed bytes. Read the live file normally, use `diff`, or refresh; do not apply the old span to new bytes. |
| `inspect` has a missing/qualified facet | Use the other evidenced facets. Unavailable Calls or source does not erase trustworthy structural data. |
| Symbol ambiguous / exact selector stale | Disambiguate using `--file`, or run `find` and copy a fresh `symbol_id`. Never select the first candidate arbitrarily. |
| Empty or short results | Check authority, filters, limits, pages, and cutoffs. `calls` defaults to `live`; `audit` defaults to fan-in 20. Empty under a filter is not universal absence. |
| Cursor rejected | Restart the same query from page one. Cursors bind to a generation and arguments and can expire. |
| Result exceeds a bound | Page where supported, reduce the limit/sections, or narrow the path. Do not strip metadata or reconstruct a silently truncated answer. |

## Indexing and WATCH

Cold semantic indexing can be expensive. Watch the active provider, progress,
and heartbeat; don't compare a whole compiler load with a warm query. Use
`--profile` for CLI timing detail. [Recorded benchmarks](performance/baseline.md)
describe their own fixture and artifact, not a universal latency guarantee.

WATCH's default 75 ms debounce is not its complete update time. Source discovery,
semantic work, validation, and publication follow. Configuration/toolchain
changes can require more work than an ordinary body edit.

If WATCH seems stale, confirm it is still running, inspect its latest operation
and error, and compare CLI/MCP roots. Stop or reconfigure the watcher through its
own owner: Ctrl-C for CLI, `watch {"action":"stop"}` for MCP. Do not start an
independent second writer just to hide an unresolved operation.

With capability preservation, a stronger last-good generation may remain while
new semantics are pending or failed. `allow_capability_downgrade` deliberately
permits weaker replacement evidence; with semantic WATCH it also enables early
structural publication. It is a policy choice, not an error-clearing switch.

## Publication recovery

Damaged/conflicting controls, a moved repository, or an index bound to a
different root can require explicit recovery. First confirm the selected root
and data directory, stop competing writers, and preserve any state you need.
An unrelated bundle is not something to “adopt” just to make status green.

For a confirmed intended bundle, CLI `index --scip --recover-publication` or
MCP `reindex {"scip":true,"recover_publication":true}` requests rebuild and
rebind through the normal validation path. It does not bypass source/path
safety. A fresh separate `--data-dir` is also useful for diagnosis without
overwriting the original bundle.

`--force` asks to build even when exact current evidence could be reused; it
is not publication recovery. `--allow-capability-downgrade` permits a weaker
result; it is not complete semantic evidence. Use only the option that matches
your intent, and inspect the terminal receipt.

## Report a useful defect

Include the version, platform/architecture, exact command or tool arguments,
expected vs actual answer, result error/coverage reason, and minimal project
shape (language, manifests, workspace/build configuration). A small reproducer
is more useful than a raw repository or transcript. Redact secrets and private
source; say whether files/toolchains changed during the operation. Report a
misleading result even if its process exit status was successful.

[Open a bug report](https://github.com/armenr/h00ligan/issues/new?template=bug_report.yml).
Small examples with an expected answer help us fix the owning problem faster.
