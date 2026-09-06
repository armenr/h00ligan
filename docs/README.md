# The h00ligan field guide

[Project home](../README.md) · [Downloads](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0)

**Less spelunking. More understanding.**

You don’t need to learn the engine before asking your first question. Pick the
job in front of you; follow the deeper links when they become useful.
These user guides describe **0.3.0** unless a section explicitly says otherwise.

## Get your first useful answer

| Start here | You’ll leave with… |
| --- | --- |
| [Getting started](getting-started.md) | An installed binary, an index, and your first query |
| [The guided tour](getting-started.md#try-the-guided-tour) | A tiny project with a definition, two callers, and a test you can check |
| [MCP setup](mcp.md) | The same engine connected to your coding agent |

New to the idea? [How it works](how-it-works.md) explains the map, the language
providers, and what the result labels mean—without making you read an ADR.

## Put it to work

| The job | The guide |
| --- | --- |
| Understand a function or type | [Find and read a definition](cli.md#find-and-understand-a-definition) |
| Change code without overlooking callers | [Trace impact and tests](cli.md#before-changing-a-function) |
| Find a boundary worth improving | [Investigate dependencies and coupling](cli.md#understand-a-boundary-or-choose-a-refactor) |
| Review potentially unused code | [Dead-code investigations](cli.md#investigate-dead-code-candidates) |
| Compare an edit with the indexed baseline | [Structural diff and live search](cli.md#compare-the-index-with-an-edit) |
| Keep answers current while you edit | [CLI WATCH](cli.md#keep-the-index-current-with-watch) or [MCP WATCH](mcp.md#keep-the-index-current) |
| Get an agent to use the tool well | [Agent playbook and prompts](agent-integration.md) |

## Look something up

- [Command reference](reference.md): every CLI verb and MCP tool, side by side.
- [Languages and project setup](languages.md): included providers, prerequisites,
  monorepos, and the difference between breadth and depth.
- [Reading results](how-it-works.md#read-the-labels-not-the-tea-leaves): fresh,
  stale, complete, qualified, and unavailable in plain language.
- [Troubleshooting](troubleshooting.md): connection problems, confusing answers,
  and the right kind of refresh.
- [Performance](performance/baseline.md): actual measurements and their workload.

> [!IMPORTANT]
> Python/TypeScript/JavaScript have structural and compiler-backed call analysis,
> but **not reachability/dead-code classification in 0.3.0**. Complete Calls
> does not mean every capability is complete. [See the capability table](languages.md#depth-and-known-limits).

## Build, contribute, or go deeper

| Area | Start with |
| --- | --- |
| Development and verification | [Development guide](development.md) |
| Architecture and product rules | [Product contract](architecture/product-contract.md) |
| Current work and known gaps | [Status](project/status.md) and [work plan](project/work-plan.md) |
| Releases, versions, and automation | [Release runbook](releasing-h00ligan.md) |
| Writing or improving these docs | [Documentation style](documentation-style.md) |
| Historical context | [Standalone genealogy](history/h00sh-genealogy.md) |

Dated evidence describes the artifact tested at the time. It is useful history,
not a promise that your installed binary has every later repair.
