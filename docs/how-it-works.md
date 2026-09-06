# How it works

[Docs](README.md) / How it works

A text search finds occurrences of a name. h00ligan resolves source definitions
and relationships: who calls a function, which tests lead to it, and which
modules depend on it. It combines parsing and static analysis, with results
available through a CLI and MCP.

It is not an LLM, a hosted search service, or a runtime tracer. It doesn’t
execute your tests or rewrite your source.

## From files to answers

```text
Project files + configuration
             │
             ├── Structural parsers → definitions, types, source locations
             └── Semantic providers → resolved source-call relationships
                                      (requested with --scip)
             │
             ▼
      One published snapshot
             ├── CLI: text or JSON
             └── MCP: structured tool results
```

**Structure** is what can be read from the code’s syntax: a class has these
members, a function occupies this source span, a file declares these symbols.
Plain `h00ligan index` gives you this layer without running project toolchains.

**Semantic analysis** uses the included language providers to resolve meaning:
which definition a source invocation refers to, for example.
`h00ligan index --scip` requests this layer. It can cost more up front because
providers load project configuration and dependencies.

The parsers and providers are shipped inside the executable. Rust/Go analysis
also needs the project’s compatible compiler toolchain. Python/TypeScript
providers do not need an ambient Python/Node executable, but they do need
enough project configuration and dependency information to resolve the code.
[Language setup](languages.md) lists the requirements.

## A caller is not a verdict

In the [guided tour](getting-started.md#try-the-guided-tour), both `greet` and
`test_greeting` call `greeting`. That answers a useful question. It does not
tell you whether either function runs in production, whether the test passes,
or whether deleting the function is safe.

Different questions need different evidence:

| Question | What it needs |
| --- | --- |
| “Show me this definition.” | Its indexed identity and matching source bytes |
| “Who calls this?” | Resolved invocations and the analyzed caller population |
| “Which tests could exercise it?” | Call paths to recognized runnable test entries |
| “Is it unreachable?” | Language-specific entry points, reachability rules, and relevant call coverage |

That last layer is not implemented for Python/TypeScript/JavaScript in 0.3.0.
Caller queries can work while `dead` remains unavailable.

For every language, reflection, runtime registration, build variants, and
external API consumers limit what static analysis alone can conclude.

## Result labels

An answer has two separate dimensions: **what the index establishes** and
**whether the live files still match it**.

| Label or term | In plain language |
| --- | --- |
| Generation / snapshot | One published version of the index |
| Fresh | The observed current inputs match the indexed inputs |
| Stale | Inputs changed; this answer describes an older snapshot |
| Complete | The named evidence covers its specified scope and configuration |
| Qualified / partial | Useful evidence exists, with stated gaps or exclusions |
| Unavailable / unknown | This conclusion cannot be established from the available evidence |
| Authority | The evidence and scope behind a particular answer—not permission to change code |

A complete caller result is not a certificate for every language, build
configuration, or query. A qualified empty list is not proof that no callers
exist. Keep filters, page limits, and depth cutoffs with your conclusion.
[The reference](reference.md#read-the-answer-including-its-qualifications)
names the machine fields.

## What happens when you edit?

Queries use a published snapshot, so they don’t read half an index while it is
being rebuilt. A new generation replaces the old one as a complete publication.
CLI and MCP can read the same data directory; the MCP process sees external
publications on later requests.

While files are newer than the snapshot, relationship queries can still return
useful, explicitly stale answers. `read` takes a stricter approach: it refuses
to attach an old symbol identity to a changed file’s bytes. Read the live file
with your editor, compare it using `diff`, or refresh.

`watch --scip` observes source/configuration changes and refreshes the map.
Its default policy can keep a stronger last-good snapshot while new semantics
are pending. You can explicitly allow earlier structural publication if your
workflow accepts temporarily unavailable call evidence.
[WATCH’s two policies](cli.md#keep-the-index-current-with-watch) explain the choice.

## Local analysis and trust

The index and analysis run locally; h00ligan needs no hosted analysis account.
That is different from a blanket offline or sandbox guarantee. Semantic
analysis may execute project toolchains and build scripts, whose behavior and
dependency access belong to the project. Analyze trusted repositories.

By default, generated state lives in `<root>/.h00ligan/code-intel`. One
executable owns the CLI, MCP server, watcher, and private providers. Embedded
components may be materialized there; you do not install a second product or
register a persistent service.

Next: [getting started](getting-started.md), [CLI workflows](cli.md), or
[MCP setup](mcp.md).
