# Writing docs people will actually use

[Docs](README.md) / Contributing / Documentation

The voice: a capable teammate at the next desk. Direct, curious, practical.
A little personality is welcome. The reader should leave knowing what to do.

## Give each page one job

- **README:** explain the product, show a useful question, get the reader moving.
- **Docs home:** route by task and experience level; keep historical evidence separate.
- **Getting started:** one working path, with observable results after the commands.
- **Workflow guides:** a question, the commands, what to look for, and the next step.
- **Reference:** exact inputs, defaults, result fields, and limits. Link it; don’t duplicate it.
- **Concepts:** explain why behavior exists before exposing implementation terminology.
- **Troubleshooting:** symptom → cause or diagnostic → action. Distinguish repairable setup from missing product capability.

Use descriptive headings, short paragraphs, fenced examples with a language,
and relative links. Start guides with a link back to [Docs](README.md), then
provide useful next steps. Preserve existing heading anchors when possible.
An important warning belongs beside the affected command—not pages later.

## Keep the voice human and the claims exact

Say “who calls this function?” before “incoming invocation population.” Explain
generation, coverage, and authority once in [How it works](how-it-works.md),
then link the machine details in [Reference](reference.md).

Write “not implemented” when something is not implemented. Keep released
behavior separate from main-branch repairs. A supported parser or complete
Calls result must never stand in for full language support. Don’t frame a
missing capability as a user’s setup mistake.

Report timings with their fixture size, measurement type, and artifact/date.
Keep scope caveats next to the number. Don’t turn a tiny-fixture query median
into a large-repository promise or a competitor comparison.

## Make examples earn their place

Prefer the checked-in [quickstart](../examples/quickstart/) over invented
projects, symbols, or JSON output. Clearly mark placeholders. Use `--filter all`
for inclusive caller investigations. Explain what successful output establishes
and what it does not. Follow pagination in machine examples.

Keep secrets, real private source, machine-local absolute paths, and captured
runtime IDs out of docs. Installation examples should verify downloads before
extracting or executing them. Never solve a problem with an unexplained
destructive reset, privilege bypass, or extra tool install.

## Check the rendered result and the actual commands

Use the pinned Devbox environment. For the executable tour:

```bash
python3 scripts/test-h00ligan-docs.py --binary /absolute/path/to/released/h00ligan
```

The probe drives CLI, MCP, and WATCH in disposable state. Read
[development](development.md#quality-gates) for its scope. Also check local links
and heading anchors, code fences, JSON examples, image alternative text, and
the rendered layout at a narrow width. Keep the package’s compact README useful
without depending on images or relative links absent from a release archive.

Docs-only edits don’t need a fresh multi-platform product build. Behavior or
packaging changes still need their normal gates; a documentation probe does
not replace those.

## Design references

This 2026-09-06 facelift takes cues from [Sparkwerx](https://github.com/armenr/sparkwerx)
for its visual identity, operational voice, and candid readiness table;
[Nuxt](https://nuxt.com/docs/4.x/guide) for separating introduction, guides, and
reference; [Nuxt UI](https://ui.nuxt.com/docs/getting-started) for concise examples
and progressive detail; and [Astro](https://docs.astro.build/en/getting-started/)
for task-oriented routes and a guided first success. The result stays plain
Markdown and a local SVG, readable on GitHub and in a checkout without a site build.
