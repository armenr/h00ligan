## What problem does this solve?

<!-- Describe the user, product, or maintenance problem—not only the changed files. -->

## What changed?

<!-- Summarize the owning design and call out CLI, MCP, WATCH, provider, or authority changes. -->

## Evidence

<!-- List focused falsifiers and the proportional gates you actually ran. -->

- [ ] New behavior has a right-reason regression or a concrete explanation of why one is not possible.
- [ ] CLI and MCP semantics remain aligned where both surfaces expose the behavior.
- [ ] Authority, freshness, ambiguity, cancellation, and failure behavior remain truthful.
- [ ] User-facing behavior or contributor guidance is documented where needed.
- [ ] No generated state, credentials, machine-local paths, indexes, or build products are included.

## Deeper-design check

<!-- Did this repair the owning abstraction, or does it add compensating code around a broader defect? -->

