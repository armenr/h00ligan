# h00ligan

Understand a codebase before you change it.

h00ligan turns source code into a local, queryable map of definitions, callers,
dependencies, tests, and change impact. Humans use its CLI. Coding agents use
the same CLI or its MCP tools. Both ask the same questions of the same index,
and both get told when an answer is incomplete or out of date.

One executable. No hosted service, API key, embedding model, or background daemon.

## Start here

| You want to… | Read |
| --- | --- |
| Install it and get your first useful answer | [Getting started](docs/getting-started.md) |
| Explore and change code from a terminal | [CLI workflows](docs/cli.md) |
| Connect an MCP client | [MCP setup and lifecycle](docs/mcp.md) |
| Teach an agent when and how to use it | [Agent playbook](docs/agent-integration.md) |
| Look up a verb, argument, or CLI/MCP difference | [Command reference](docs/reference.md) |
| Understand language coverage and prerequisites | [Languages and limitations](docs/languages.md) |
| Resolve an error or confusing result | [Troubleshooting](docs/troubleshooting.md) |

## Install, index, ask

[Download 0.3.0](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0)
for Linux x86_64, Linux ARM64, or Apple Silicon. Intel Mac is deferred.
The repository currently requires GitHub access. See the
[installation steps](docs/getting-started.md#install) for checksum verification
and macOS notes.

From a trusted project:

```bash
h00ligan --version
h00ligan index --scip
h00ligan status
h00ligan overview
h00ligan find '*Handler' --name --definitions-only
```

Then use a returned name or `symbol_id` with `read`, `calls`, `inspect`, or
`assess`. Don't have a project in mind? Follow the small, runnable
[guided tour](docs/getting-started.md#try-the-guided-tour).

`--scip` requests compiler-backed relationships using the providers shipped
inside h00ligan; it does **not** mean “install SCIP.” Rust and Go analysis also
need a compatible project toolchain. Python and TypeScript/JavaScript analysis
need no separately installed language runtime, but project dependencies and
configuration still matter. [Details](docs/languages.md).

Plain `h00ligan index` builds only the structural index: definitions, source,
and structural relationships. It does not establish who calls what or whether
code is dead. Complete Calls evidence is also not proof of every other
capability: **0.3.0 has no Python/TypeScript reachability classification**, so
their dead-code conclusions and aggregate health remain unavailable.

## Same product, two interfaces

Using the guided tour's `greeting` definition:

```bash
# Human-readable answer
h00ligan --root examples/quickstart calls greeting --file app.py --filter all

# The same answer as structured data
h00ligan --root examples/quickstart calls greeting --file app.py --filter all --format json

# Let an MCP host launch the same executable
h00ligan --root examples/quickstart mcp-serve
```

The equivalent MCP tool call is `calls` with
`{"symbol":"greeting","file":"app.py","filter":"all"}`.
MCP adds a transport envelope; it does not invent a different analysis model.
The [surface map](docs/reference.md#choose-a-verb-by-the-question) covers every verb and the
few intentional differences.

## Keep it current

```bash
h00ligan watch --scip
```

Leave that foreground process running and query from another terminal or MCP
client using the same root and data directory. Stop it with Ctrl-C. WATCH
publishes complete snapshots; it is not a persistent system service. See
[WATCH behavior](docs/cli.md#keep-the-index-current-with-watch) before enabling
early structural publication or strict semantic requirements.

## Contribute

This is the standalone four-crate h00ligan workspace; there is no h00.sh runtime
dependency. Use the pinned Devbox environment for development, not to run the
downloaded executable:

```bash
devbox shell
just ci
```

[Development and verification](docs/development.md),
[release runbook](docs/releasing-h00ligan.md),
[architecture](docs/architecture/product-contract.md), and
[measured performance](docs/performance/baseline.md) are separate from the
user guides. The recorded benchmarks identify their fixture and artifact;
they are not universal latency promises or new measurements of 0.3.0.

## License

The current components retain MIT/Apache-2.0 and BSL-1.1 declarations; see
[LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE), and
[LICENSE-BSL](LICENSE-BSL). The intention is to open-source h00ligan; a final
unified licensing policy is still to be settled.
