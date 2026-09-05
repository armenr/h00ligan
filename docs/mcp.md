# MCP: the same engine inside your agent

MCP is an alternative interface to the installed `h00ligan` executable, not a
hosted service or a second analyzer. Your client starts a local process over
stdio. It reads the same repository-local index as the CLI.

## Connect one repository

Install [the release executable](getting-started.md#install), then configure
your client's local stdio server with:

```text
command: /absolute/path/to/h00ligan
args: ["--root", "/absolute/path/to/your/repository", "mcp-serve"]
```

For clients that accept an `mcpServers` JSON configuration, the corresponding
shape is:

```json
{
  "mcpServers": {
    "h00ligan": {
      "command": "/absolute/path/to/h00ligan",
      "args": ["--root", "/absolute/path/to/your/repository", "mcp-serve"]
    }
  }
}
```

This is a configuration **shape**, not a universal host-specific filename or
installation command. Use your client's MCP settings and approval/reload flow.
Replace both paths; do not expect `~` or shell variables in JSON to expand.
GUI clients may not inherit your terminal's `PATH`, which is why the binary
path is explicit. Do not wrap the server in a shell that prints banners to stdout.

The default data directory is `<root>/.h00ligan/code-intel`. To use another,
insert `"--data-dir", "/absolute/path/to/index"` before `"mcp-serve"`, and
give the CLI the same data directory. The server binds both paths for its
whole lifetime. Use separate server entries/processes for independent repos;
tool arguments cannot switch roots. One monorepo can instead use one root.

After reconnecting, the client should discover **18 tools**. Start with
`status` and `overview`. Startup/discovery does not index the project. An
unindexed status is a valid connected server, not a connection failure.

## Build the first semantic index

The examples below name the tool and its **arguments**, not a raw JSON-RPC
message. The client handles transport details.

Call **`reindex`**:

```json
{"scip": true}
```

Save its returned `operation_id`. Call **`reindex_status`**, replacing the
placeholder with that exact value:

```json
{"operation_id": "<operation_id returned by reindex>"}
```

Poll at a reasonable interval while `terminal` is false; follow the reported
phase and progress. `terminal:true` means it ended, **not** that it succeeded.
Require `state:"succeeded"`, inspect `result` and its capability coverage, and
then query `status`. `failed`, `cancelled`, and `superseded` are distinct outcomes.
Best-effort semantic indexing can succeed with an explicit coverage gap.

For an automated task that needs complete applicable Calls coverage, start
with `{"scip":true,"require_complete_calls":true}`. Without `scip:true`, a
reindex is structural only. These flags do not enable unimplemented language
capabilities or make dynamic behavior statically knowable.

To cancel, call **`reindex_cancel`** with the same exact `operation_id`, then
observe its terminal result. IDs belong to that process; do not reuse one
after reconnecting or cancel whatever happens to be “latest.” The optional-ID
status call is useful for inspection, not ownership of another operation.

## Ask the same questions as the CLI

For a server rooted at `examples/quickstart`, call these in order:

**`find`**

```json
{"query":"greeting","mode":"name","definitions_only":true}
```

**`read`**

```json
{"symbol":"greeting","file":"app.py"}
```

**`calls`**

```json
{"symbol":"greeting","file":"app.py","filter":"all"}
```

**`tests`**

```json
{"symbol":"greeting","file":"app.py"}
```

These match the [CLI tour](getting-started.md#try-the-guided-tour). A real
project will have different names; use `find` output, not invented IDs.
`inspect` combines a concise dossier; `assess` asks about change impact.
Use [the shared reference](reference.md) for all tools, defaults, and paging.

## Keep the index current

Call **`watch`** to start semantic refresh:

```json
{"action":"start","scip":true}
```

Inspect it with `{"action":"status"}` and stop it with
`{"action":"stop"}`. Configuration fields are accepted only on `start`.
Use one watcher per root/data bundle. Starting WATCH does not mean its initial
semantic reconciliation has finished; inspect its operation state and status.

An optional start with `allow_capability_downgrade:true` allows fast structural
publication before semantic enrichment finishes. Only use that if your
workflow accepts temporarily weaker Calls evidence. Strict complete-Calls
mode stays atomic. [CLI WATCH guidance](cli.md#keep-the-index-current-with-watch)
explains the tradeoff and cadence.

The MCP process owns its watcher and providers; disconnect/shutdown stops
that work, not the durable index. An ended client does not leave a persistent
service behind. You can instead run CLI WATCH in a terminal and let MCP read
its publications. External publications become visible on later requests.

## Results and safe operation

Modern protocol negotiation returns the typed result in `structuredContent`.
Older supported clients receive the JSON payload in text content instead.
The server implements stateless protocol `2026-07-28` and initialized revisions
`2025-11-25`, `2025-06-18`, `2025-03-26`, and `2024-11-05`; let the host negotiate.
Do not ask for `format`, parse the human CLI table, or count both transport
representations as separate results. Preserve authority, freshness, and paging
metadata alongside the answer.

Invalid tool arguments (for example, `limit:101` on `calls`) are rejected
before execution with JSON-RPC invalid-params code `-32602`. This is distinct
from a valid query returning a typed capability or source-materialization error.

Index/WATCH write generated state. Semantic providers may execute project
toolchains/build scripts, so configure only trusted repositories. Recovery,
forced rebuild, and capability downgrade are explicit operations—not generic
retry switches. Normal query tools do not edit project source.

If the client cannot connect, tools are absent, an old binary remains loaded,
or queries return qualifications, use [troubleshooting](troubleshooting.md).
For agent behavior rather than host plumbing, see [the playbook](agent-integration.md).
