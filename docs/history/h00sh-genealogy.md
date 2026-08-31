# h00.sh genealogy

Last reconciled: 2026-08-31

## Incubation

h00ligan was developed inside the h00.sh monorepo. That repository supplied an incubator,
development environment, shared history, and early agent workflows; it is not part of the
standalone runtime. The extracted workspace contains only the four h00ligan-owned packages and the
provider/build/release material needed to produce the one executable.

Historical h00.sh ADRs, agent handoffs, status files, and reviewer notes are genealogy and clues.
They do not bind the standalone product unless their claim is independently supported by retained
source, a current test, or a newly ratified standalone decision.

## Useful parent anchors

The parent Git history includes these independently observed anchors:

- `f2bfb1b` — repository-bound MCP work during the August 2026 product-surface campaign;
- `5e86260` — the 2026-08-12 `h00-ligan` 0.2.0 mainline release point;
- `14293e9` — 2026-08-26 portable polyglot code-intelligence product tranche;
- `b565b4e` — 2026-08-27 product-thesis and dogfood-contract ratification.

Commit subjects are provenance leads, not proof that their described behavior remains current.
The later correctness, provider-lifecycle, WATCH, performance, and isolation campaign remained
uncommitted in the parent workspace at extraction time; its authority is the accepted source and
migration receipts, not an invented historical commit graph.

## Ratified history strategy

The standalone default branch begins with a clean two-commit import:

1. the exact certified 234-file product-source layer; then
2. the exact sixteen-file standalone-native repository and durable-documentation layer.

Filtered h00.sh ancestry is deliberately excluded from `main`. The exact mapped parent paths reach
roughly 290 commits with mixed h00/Engram ownership, while current bytes for 101 of the 234 product
inputs are not represented by parent HEAD. A filtered graph would therefore carry unrelated
history and still fail to explain much of the product that was actually accepted.

Useful genealogy instead lives in this bounded document and an ignored, hash-addressed migration
archive containing source/reconciliation/assembly/acceptance receipts plus selected context and
review evidence. A mechanically filtered incubator bundle or non-default private ref may be
retained later for forensic browsing. It is not a parent of `main`, a release ref, or a development
dependency.

## Reconciled source boundary

The final parent inventory contains 339 declared inputs. Deterministic reconciliation retains 234
standalone source files and excludes 105 parent-only, obsolete, or intentionally removed paths.
The standalone-native layer contributes sixteen additional files, yielding a 250-file repository
candidate before ignored local migration context.

The removal population includes h00.sh/Engram integration, parent continuity machinery, obsolete
compatibility surfaces, and the unshipped `init`, `replace_symbol`, and `match` handlers. The
native layer—agent guidance, contribution templates, product status, architecture, performance,
review history, and this genealogy—is authored separately so it cannot be misattributed to the
source donor.

Receipts bind parent HEAD and dirty-state identity, source paths, modes, bytes, policy, generator,
sabotage tests, reconciled output, native overlay, installed-product gate, portable artifact, and
acceptance replay. Candidate and authority-receipt identities remain outside the bytes whose
identity they define, avoiding self-reference. Live indexes, caches, build products, credentials,
transcripts, session identities, and machine-local agent state are excluded.

## Cutover boundary

The clean-import strategy is ratified, but no commit, standalone remote, release lineage,
publication, parent-removal operation, or source-of-record cutover is implied by this document.
Those outward or destructive steps require explicit operator checkpoints after the exact final
candidate, manifests, and local repository state are verified.

Until cutover, h00.sh remains the working source of record. After cutover, h00.sh removal or
archival is a separate decision; the standalone repository must not be maintained by dual-writing
two evolving implementations.
