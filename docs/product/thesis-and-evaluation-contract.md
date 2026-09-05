# Product thesis and evaluation contract

Last verified: 2026-08-28

## Thesis

h00ligan is a local code-intelligence engine for humans and coding agents. It turns a repository
into an immutable, queryable model and exposes that model through one portable executable: a
human-oriented CLI, an MCP server, and a WATCH lifecycle that publishes complete
replacement generations.

Its differentiation is not that graphs, parsers, or compiler indexes are novel. The product bet
is that coding work improves when structural facts, compiler-backed relationships, current-source
freshness, and known gaps are reported together instead of being collapsed into an unjustified
yes/no answer.

The primary workflow is:

> Can I safely change or delete this code, what might it affect, and exactly what evidence supports
> that conclusion?

Orientation, symbol lookup, dependency inspection, focused source search, test discovery, and
coupling analysis are supporting workflows around that core question.

## Product contract

- One installed executable provides CLI, MCP, indexing, WATCH, and private semantic-provider
  execution. It requires no h00.sh runtime, companion h00ligan service, database server, model, or
  API key.
- Structural indexing works without a compiler for Rust, Go, Python, and
  TypeScript/JavaScript. Compiler-backed providers add Calls evidence and enumerate uncovered
  scopes rather than silently treating them as empty.
- CLI and MCP share query semantics. Human rendering and transport envelopes may differ;
  authority, freshness, ambiguity, limits, and refusal behavior may not.
- Published generations are immutable and repository-bound. Failed, cancelled, or superseded
  work leaves the last good generation intact.
- Stale or incomplete evidence remains useful when it is clearly qualified. h00ligan must never
  convert unknown, unavailable, partial, qualified, or stale evidence into confident absence.
- Compiler-specific behavior remains explicit behind a language-neutral lifecycle. Supporting
  more languages must not force a false lowest-common-denominator model.

## Evaluation contract

Evaluate h00ligan on real maintenance tasks in realistic Rust, Go, Python, TypeScript, and
polyglot repositories. Compare it with ordinary repository tools and credible code-intelligence
alternatives using the same question, source revision, operator, and stopping rule.

Representative tasks include:

1. Locate the exact definition behind an ambiguous name.
2. Estimate the blast radius of a proposed change.
3. Decide whether a function is safely removable.
4. Find the tests and callers that should constrain a patch.
5. Explain a cross-package or cross-language subsystem without broad source ingestion.
6. Continue useful work after the source changes while preserving the indexed-generation caveat.

Measure:

- correct conclusions and wrong conclusions;
- unsupported certainty and honest unknowns;
- whether the resulting patch and tests address the real relationship;
- elapsed time, tool calls, and context consumed;
- indexing, refresh, query, and startup latency;
- setup, toolchain, and recovery friction;
- reproducibility across supported platforms and repository shapes.

A fast answer is not successful when it is wrong, and a correct answer is not a compelling
product when setup or refresh costs overwhelm the saved work.

## Success and flip conditions

The thesis is supported when h00ligan materially reduces wrong or unsupported conclusions on the
core workflow while remaining fast enough to use continuously and simple enough to install as a
normal developer tool.

Revisit or narrow the product if controlled comparisons show any of the following:

- a simpler peer produces equally trustworthy answers with materially less friction;
- authority qualifications do not reduce wrong conclusions in practice;
- semantic setup or refresh costs prevent ordinary continuous use;
- agents do not select or correctly interpret the surfaces without heavy prompt scaffolding;
- another workflow produces substantially more user value than safe-change reasoning.

No comparison outcome has been ratified yet. The repository performance battery proves product
mechanics and timing, not market differentiation or task-level superiority.
