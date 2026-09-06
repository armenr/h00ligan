# Documentation

[Project home](../README.md) · [Downloads](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0)

Start with installation and a first query, or choose a workflow below.
These guides describe **0.3.0** unless a section identifies another version.

## Getting started

| Guide | Contents |
| --- | --- |
| [Getting started](getting-started.md) | An installed binary, an index, and your first query |
| [The guided tour](getting-started.md#try-the-guided-tour) | A small project with a definition, two callers, and a test |
| [MCP setup](mcp.md) | The same engine connected to your coding agent |

[How it works](how-it-works.md) explains indexing, language providers, and
result labels.

## Workflows

| The job | The guide |
| --- | --- |
| Understand a function or type | [Find and read a definition](cli.md#find-and-understand-a-definition) |
| Change code without overlooking callers | [Trace impact and tests](cli.md#before-changing-a-function) |
| Find a boundary worth improving | [Investigate dependencies and coupling](cli.md#understand-a-boundary-or-choose-a-refactor) |
| Review potentially unused code | [Dead-code investigations](cli.md#investigate-dead-code-candidates) |
| Compare an edit with the indexed baseline | [Structural diff and live search](cli.md#compare-the-index-with-an-edit) |
| Keep answers current while you edit | [CLI WATCH](cli.md#keep-the-index-current-with-watch) or [MCP WATCH](mcp.md#keep-the-index-current) |
| Configure agent workflows | [Agent instructions and prompts](agent-integration.md) |

## Reference

- [Command reference](reference.md): every CLI verb and MCP tool, side by side.
- [Languages and project setup](languages.md): included providers, prerequisites,
  monorepos, and capability coverage.
- [Reading results](how-it-works.md#result-labels): fresh,
  stale, complete, qualified, and unavailable in plain language.
- [Troubleshooting](troubleshooting.md): connection problems, confusing answers,
  and index recovery.
- [Performance](performance/baseline.md): actual measurements and their workload.

> [!IMPORTANT]
> Python/TypeScript/JavaScript have structural and compiler-backed call analysis,
> but **not reachability/dead-code classification in 0.3.0**. Complete Calls
> does not mean every capability is complete. [See the capability table](languages.md#depth-and-known-limits).

## Contributing

| Area | Start with |
| --- | --- |
| Development and verification | [Development guide](development.md) |
| Architecture and product rules | [Product contract](architecture/product-contract.md) |
| Current work and known gaps | [Status](project/status.md) and [work plan](project/work-plan.md) |
| Releases, versions, and automation | [Release runbook](releasing-h00ligan.md) |
| Writing or improving these docs | [Documentation style](documentation-style.md) |
| Historical context | [Standalone genealogy](history/h00sh-genealogy.md) |

Project status, work plans, and historical evidence describe development work.
Check the version stated in a guide against your installed binary.
