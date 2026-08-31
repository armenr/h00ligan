# Using h00ligan with coding agents

h00ligan gives humans and coding agents the same repository model through two surfaces: a
human-oriented CLI and bounded structured MCP tools. The words and result shapes are shared;
only presentation and MCP lifecycle envelopes differ.

## A productive agent journey

1. Call `status` before trusting an existing generation.
2. Use `overview` to understand project units, languages, topology, and coverage.
3. Use `find` to resolve a name to an exact generation-bound `symbol_id` when ambiguity matters.
4. Use `read`, `type`, or `inspect` for the selected definition and its local context.
5. Use `calls`, `assess`, `deps`, `tests`, or `audit` for relationships and prioritization.
6. Use `grep_context` for bounded current-worktree text evidence and `diff` to compare the live
   worktree with the immutable generation.
7. Reindex only when current-source conclusions require a fresh generation.

The important rule is not “always use h00ligan.” Use it when graph or symbol evidence can replace
broad file scanning, then corroborate any correctness-critical conclusion against live source.

## What each family answers

| Family | Question it helps answer |
| --- | --- |
| `status`, `overview` | What is indexed, fresh, covered, and currently trustworthy? |
| `find`, `type`, `read`, `inspect` | Which exact symbol is this, where is it, and what defines it? |
| `calls`, `assess`, `deps` | What relationships leave or reach this code, and what could a change affect? |
| `tests`, `dead_code`, `audit` | What validates this code, what is provably unreachable, and where is coupling concentrated? |
| `grep_context`, `diff` | What do current source bytes say, including work not yet indexed? |
| `reindex`, `reindex_status`, `reindex_cancel` | How is a new immutable generation built, observed, or cancelled safely? |

Run `h00ligan <command> --help` and consult `crates/h00ligan/README.md` for exact current flags,
result schemas, limits, and authority behavior.

## MCP setup

Launch the same installed executable with an explicit repository root:

```text
h00ligan --root <repository> mcp-serve
```

Configure the host to invoke that command over stdio. The MCP process remains bound to that one
repository; tool arguments cannot switch roots or data directories. `reindex` returns immediately
with an operation ID. Poll or cancel only with that exact ID, and treat only its terminal receipt
as the outcome.

MCP reindexing is structural by default. Request compiler-backed evidence explicitly when Calls
accuracy is needed. The server reports incomplete or unavailable language coverage rather than
quietly converting it to “no calls.”

## Authority and freshness

Every generation-bound result separates two questions:

- What authority does this immutable generation have?
- Do current repository inputs still match that generation?

A structurally complete result may still lack compiler-backed Calls authority. A semantically
complete generation may still be stale relative to edited source. Agents should preserve both
qualifications in their reasoning and user-facing conclusions.

## Suggested repository instruction

Repositories can add a short instruction like this to their agent guidance:

> Use h00ligan opportunistically for repository orientation, symbol resolution, relationship
> queries, and bounded source search. Start with `status`; check generation freshness and
> per-language authority before relying on negative Calls, impact, or dead-code conclusions.
> Corroborate correctness-critical findings with live source. Do not reindex or replace an
> existing bundle without authorization.

No hook, daemon, login item, or agent-specific plugin is required. A host-native skill or tool
description can improve tool selection, but it should teach this contract rather than introduce
another source of product semantics.

