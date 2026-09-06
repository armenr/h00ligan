![h00ligan — Know the code. Then make your move.](docs/assets/h00ligan.svg)

<p align="center">
  <a href="docs/getting-started.md">Get started</a> ·
  <a href="docs/cli.md">Use the CLI</a> ·
  <a href="docs/mcp.md">Connect MCP</a> ·
  <a href="docs/agent-integration.md">For agents</a> ·
  <a href="docs/README.md">All docs</a>
</p>

# h00ligan

**Your codebase has relationships. Stop rediscovering them by hand.**

h00ligan turns source code into a local, queryable map of definitions, callers,
dependencies, tests, and change impact. Find the function. Follow its callers.
See what a change could affect. Get back to building.

One executable for your terminal and your coding agents. No hosted analysis
service, API key, embedding model, or always-on daemon. CLI and MCP ask the
same engine; neither gets a watered-down answer.

## Start with a question

| You’re thinking… | Ask h00ligan |
| --- | --- |
| “Where does this actually live?” | `find`, then `read` or `type` |
| “Give me the useful context.” | `inspect` — source, structure, callers, and tests together |
| “Who calls this, and what could I break?” | `calls`, then `assess` for the blast radius |
| “Which tests should I look at?” | `tests` — discover test-call paths, then run the tests yourself |
| “Where are the tangled boundaries?” | `deps` and `audit` for dependencies and incoming coupling |
| “Is this code doing anything?” | `dead` — review candidates where the language and evidence support it |

Start with the [CLI field guide](docs/cli.md), or jump straight to the
[complete command reference](docs/reference.md#choose-a-verb-by-the-question).

## Download. Index. Ask.

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

Use a returned name and file with `read`, `calls`, or `assess`. Prefer something
you can check in source before relying on a large investigation.
No project handy? The [guided tour](docs/getting-started.md#try-the-guided-tour)
gives you a tiny Python project and concrete answers to check.

> [!TIP]
> `--scip` means “use the semantic providers included in h00ligan,” not
> “go install SCIP.” Rust and Go also need compatible project toolchains.
> Python/TypeScript providers need no separate Python or Node executable;
> project dependencies and configuration still matter. [What’s included](docs/languages.md).

Plain `index` builds structure only. Add `--scip` for compiler-backed call
relationships. Semantic indexing can run project toolchains and build scripts;
use it on code you trust. Your index stays in `<root>/.h00ligan/code-intel`.

## What’s ready today

The distinction matters: **finding callers and proving code is dead are
different jobs.** Here’s what the released **0.3.0** does:

| Capability | Today |
| --- | --- |
| Definitions, source, types, and project structure | Rust, Go, Python, TypeScript/JavaScript, including JSX/TSX |
| Compiler-backed callers and test-call paths | All four language families, with explicit coverage and configuration limits |
| Impact and inspection | Structural/caller/test evidence; some risk facets need classification |
| Reachability and dead-code classification | Rust/Go implemented; **Python/TypeScript/JavaScript not implemented yet** |
| CLI, 18 MCP tools, and foreground WATCH | Included in one executable |
| Native downloads | Linux x86_64/ARM64 and Apple Silicon; Intel Mac parked |

[Language depth and known limits](docs/languages.md) explains the details,
including the 0.3.0 Go build-tag defect repaired on main. An incomplete answer
stays visibly incomplete. “I can’t establish that” must never become “nothing
calls it.”

## Your terminal. Your agent. Same answers.

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

[Connect your client](docs/mcp.md), then give your agent a useful job:

```text
Use h00ligan to investigate the function I’m changing. Find its definition,
trace callers and relevant tests, and read the important source. Tell me
what the index proves, what remains uncertain, and what I should test.
```

The [agent playbook](docs/agent-integration.md) includes copyable repository
guidance and task prompts. No extra hook or agent plugin required.

## Keep the map moving

```bash
h00ligan watch --scip
```

Leave WATCH in one terminal; query from another terminal or MCP using the same
root and data directory. Ctrl-C stops it. No login item, system service, or
background installation to untangle later.

WATCH publishes complete snapshots and can retain the last good one while
new semantics are pending. [Choose the refresh behavior](docs/cli.md#keep-the-index-current-with-watch)
that fits your work.

## Speed, with the receipts

A recorded four-language smoke run measured **7.7–9.0 ms CLI query medians**,
**2.3–3.4 ms long-lived MCP query medians**, and **141–251 ms WATCH edit/restore
completion**. That fixture had **48 source files / 5,161 bytes** on one host.
It is a pre-release reference, not a fresh 0.3.0 benchmark or a large-repo promise.

The [performance report](docs/performance/baseline.md) includes artifact identity,
methodology, and a separate **24,575-node / 123,984-edge** real-repository WATCH
comparison. Cold indexing, warm queries, and WATCH are measured separately.

## Find your way around

[Documentation home](docs/README.md) ·
[How it works](docs/how-it-works.md) ·
[Troubleshooting](docs/troubleshooting.md) ·
[Project status](docs/project/status.md) ·
[Work plan](docs/project/work-plan.md)

Want to build it? This is the standalone four-crate workspace, with no h00.sh
runtime dependency. Devbox is for development, not running the download:

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
