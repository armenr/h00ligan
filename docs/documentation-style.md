# Documentation style

[Docs](README.md) / Contributing / Documentation

Write for a developer trying to get something done. Use direct verbs, concrete
examples, and short explanations. A little dry humor is fine when it helps;
instructions and reference material should be straightforward.

## Give each page one job

- **README:** explain the product, its capabilities, and how to start.
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

## Tone

Use descriptive headings, not slogans. Avoid promotional superlatives, repeated
rhetorical questions, congratulating the reader, or scolding them for mistakes
they have not made. Do not introduce each page with a tagline.

Explain the behavior and its consequence. A caveat should tell the reader what
to check or do, not advertise the rigor of the development process.

## Technical claims and version scope

Say “who calls this function?” before “incoming invocation population.” Explain
generation, coverage, and authority once in [How it works](how-it-works.md),
then link the machine details in [Reference](reference.md).

Write “not implemented” when something is not implemented. Identify the affected
version and link to the relevant issue, change, or release. If support exists
only on the development branch, say so beside the affected example. A supported parser or complete
Calls result must never stand in for full language support. Don’t frame a
missing capability as a user’s setup mistake.

Public guides describe how the product works. Session narratives, review
outcomes, operator approvals, and implementation progress belong in project
status, work plans, or dated evidence—not in setup instructions or README
introductions. Keep detailed language limits in the language guide and link
to them; retain short warnings beside commands that depend on those limits.

Report timings with their fixture size, measurement type, and artifact/date.
Keep scope caveats next to the number. Don’t turn a tiny-fixture query median
into a large-repository promise or a competitor comparison.

## Examples

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

## Visual identity and references

h00ligan's mark is an owl with one crossed eye, drawn in amber and warm neutral
colors. It takes its visual identity from the
[historical h00.ligan page](https://h00.sh/hooligan/), whose product descriptions
are not a reference for the standalone tool. Keep the SVG static, accessible,
and self-contained; it should remain legible at README widths.

[Sparkwerx](https://github.com/armenr/sparkwerx),
[Nuxt](https://nuxt.com/docs/4.x/guide),
[Nuxt UI](https://ui.nuxt.com/docs/getting-started), and
[Astro](https://docs.astro.build/en/getting-started/) are references for
navigation and example structure. The direct explanations in
[The GAN Harness](https://rmnr.net/blog/gan-harness-vs-h00bert/),
[The Semantic CPU](https://rmnr.net/blog/the-semantic-cpu/), and
[Stop Talking to Your AI](https://rmnr.net/blog/stop-talking-to-your-ai/)
inform the voice, not the product claims or the intensity of the writing.

Docs use Markdown and local SVG, readable on GitHub and in a checkout without
a site build.
