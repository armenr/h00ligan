![h00ligan owl and wordmark](docs/assets/h00ligan.svg)

<p align="center">
  <a href="docs/getting-started.md">Get started</a> ·
  <a href="docs/cli.md">Use the CLI</a> ·
  <a href="docs/mcp.md">Connect MCP</a> ·
  <a href="docs/agent-integration.md">For agents</a> ·
  <a href="docs/README.md">All docs</a>
</p>

# h00ligan

h00ligan is a local code-intelligence tool for developers and coding agents.
It indexes source definitions and relationships so you can find callers, trace
dependencies, locate relevant tests, and assess a change before making it.

One executable provides a CLI, an MCP server, and incremental WATCH updates.
Analysis runs locally, without a hosted service, API key, or embedding model.
CLI and MCP query the same engine and index.

## Start with a question

| Question | Command |
| --- | --- |
| “Where is this defined?” | `find`, then `read` or `type` |
| “What do I need to know about this function?” | `inspect` — source, structure, callers, and tests together |
| “Who calls this, and what could I break?” | `calls`, then `assess` for the blast radius |
| “Which tests should I look at?” | `tests` — discover test-call paths, then run the tests yourself |
| “Which modules depend on this?” | `deps` and `audit` for dependencies and incoming coupling |
| “Could this code be unused?” | `dead` — review candidates where the language and evidence support it |

See [CLI workflows](docs/cli.md) for examples, or use the
[complete command reference](docs/reference.md#choose-a-verb-by-the-question).

## Getting started

[Get h00ligan 0.3.0](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0)
for **Linux x86_64, Linux ARM64, or Apple Silicon**.
[Verify and install it](docs/getting-started.md#install), then open a trusted project:

```bash
h00ligan --version
h00ligan index --scip
h00ligan status
h00ligan overview
h00ligan find '*Handler' --name --definitions-only
```

Use a returned name and file with `read`, `calls`, or `assess`.
The [guided tour](docs/getting-started.md#try-the-guided-tour) includes a small
Python project with expected results for each query.

> [!TIP]
> `--scip` means “use the semantic providers included in h00ligan,” not
> “go install SCIP.” Rust and Go also need compatible project toolchains.
> Python/TypeScript providers need no separate Python or Node executable;
> project dependencies and configuration still matter. [What’s included](docs/languages.md).

Plain `index` builds structure only. Add `--scip` for compiler-backed call
relationships. Semantic indexing can run project toolchains and build scripts;
use it on code you trust. Your index stays in `<root>/.h00ligan/code-intel`.

## Language support

Support varies by capability. In **0.3.0**:

| Capability | Support |
| --- | --- |
| Definitions, source, types, and project structure | Rust, Go, Python, TypeScript/JavaScript, including JSX/TSX |
| Compiler-backed callers and test-call paths | All four language families, with explicit coverage and configuration limits |
| Impact and inspection | Structural/caller/test evidence; some risk facets need classification |
| Reachability and dead-code classification | Rust/Go implemented; **Python/TypeScript/JavaScript not implemented yet** |
| CLI, 18 MCP tools, and foreground WATCH | Included in one executable |
| Native downloads | Linux x86_64/ARM64 and Apple Silicon |

[Language support and known limitations](docs/languages.md) covers setup,
configuration, and coverage. Finding a caller is different from proving code
is unused: incomplete call coverage cannot establish that a function has no callers.

## CLI and MCP

Using the guided tour’s `greeting` function:

```bash
# For you
h00ligan --root examples/quickstart calls greeting --file app.py --filter all

# For a script or CLI-using agent
h00ligan --root examples/quickstart calls greeting --file app.py --filter all --format json

# For an MCP client to launch
h00ligan --root examples/quickstart mcp-serve
```

The equivalent MCP call is `calls` with
`{"symbol":"greeting","file":"app.py","filter":"all"}`.

[Connect your client](docs/mcp.md), then request an investigation:

```text
Use h00ligan to investigate the function I’m changing. Find its definition,
trace callers and relevant tests, and read the important source. Tell me
what the index proves, what remains uncertain, and what I should test.
```

The [agent guide](docs/agent-integration.md) includes repository instructions
and task prompts. No additional hook or agent plugin is required.

## Incremental updates

```bash
h00ligan watch --scip
```

Leave WATCH in one terminal; query from another terminal or MCP using the same
root and data directory. Ctrl-C stops it. WATCH runs in the foreground and
does not register a system service or login item.

WATCH publishes complete snapshots and can retain the last good one while
new semantics are pending. [Choose the refresh behavior](docs/cli.md#keep-the-index-current-with-watch)
that fits your work.

## Performance

A recorded four-language smoke run measured **7.7–9.0 ms CLI query medians**,
**2.3–3.4 ms long-lived MCP query medians**, and **141–251 ms WATCH edit/restore
completion**. That fixture had **48 source files / 5,161 bytes** on one host.
It is a pre-release reference, not a fresh 0.3.0 benchmark or a large-repo promise.

The [performance report](docs/performance/baseline.md) includes artifact identity,
methodology, and a separate **24,575-node / 123,984-edge** real-repository WATCH
comparison. Cold indexing, warm queries, and WATCH are measured separately.

## Documentation and development

[Documentation home](docs/README.md) ·
[How it works](docs/how-it-works.md) ·
[Troubleshooting](docs/troubleshooting.md) ·
[Project status](docs/project/status.md) ·
[Work plan](docs/project/work-plan.md)

To build from source, use the pinned Devbox environment. It is not required
to run a release binary:

```bash
devbox shell
just ci
```

See [development](docs/development.md), [architecture](docs/architecture/product-contract.md),
and the [release runbook](docs/releasing-h00ligan.md).

## License

We intend to open-source h00ligan. Current component declarations are retained in
[LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE), and
[LICENSE-BSL](LICENSE-BSL); a unified licensing policy is still to be settled.
