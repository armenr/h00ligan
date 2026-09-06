# Go build selection: real Switchboard verification

Verified: 2026-09-06. Product repair: `c50c8884bccbbde526bc01d41f176bdbd96fe333`.

## What this proves

The repaired one-file executable honors
`GOFLAGS='-mod=readonly -tags=persistent_session_contract_red'` on the actual
Switchboard backend. The previously omitted `readPersistentUntil` helper has
seven exact call sites from `TestPersistentSessionVerticalSlice`, and the
tests query returns that runnable test root. All seven returned byte spans
were checked against the source. No Switchboard test was executed by these
navigation queries.

The untagged control still excludes that helper and returns
`symbol_outside_provider_coverage` / `provider_document_omitted`. Native
`go list` independently includes the tagged document only with the tag.
Both generations return four call sites for the source-confirmed
`validateResponse` positive control. The historical `validRPCError` selector
had changed upstream; its unsuccessful query was retained, not mistaken for
a h00ligan defect or used to justify another index.

## Exact subjects and conditions

- Switchboard standalone source: `a6baced4bb500c7d9819648425dfaa8778d5548a`;
  tree `5fcb82a59663acd941a20a2a8b420f2f78e15bf4`.
- Analysis root: that checkout's `core/`, including its local `third_party/x-vt`
  module; not the separate client repository or dirty main checkout.
- Go 1.26.6, Linux AMD64, `GOTOOLCHAIN=local`, `GOENV=off`, `CGO_ENABLED=0`,
  `GOMAXPROCS=4`; `index --scip --jobs 4 --format json`.
- Separate fresh data directories for each selection. Dependencies came from
  a disposable copy of the existing cache with `GOPROXY=off`.
- Tested executable SHA-256:
  `01b92c4a971f2df0c374469f287ca198a5efd6a2946f03626ac6255256181511`.
  It is the exact pre-commit artifact accepted by the complete local Linux
  AMD64 `just ci-product` gate; committed product-source bytes were verified
  equal afterward. It is not a replacement for the published 0.3.0 assets.

| Observation | Untagged | With the requested tag |
| --- | ---: | ---: |
| Native packages across both modules | 68 | 68 |
| Native-selected Go documents | 556 | 557 |
| Native-excluded Go documents | 139 | 138 |
| Provider-reported omitted documents | 139 | 138 |
| Discovered files, all indexed languages | 703 | 703 |
| Graph nodes | 33,838 | 33,838 |
| Graph edges | 129,718 | 130,166 |
| Pipeline-reported index time | 19,521 ms | 18,977 ms |
| Helper call sites returned | Refused: excluded | 7 |
| Helper test roots returned | Refused: excluded | 1 |

These timings describe this real-source probe, not a controlled performance
comparison with the older adoption report or a cross-platform benchmark.

## Remaining qualifications are separate

All 138 documents excluded by native Go under the requested tag have explicit
build constraints. This explains why the omission count alone is not evidence
of 138 additional product bugs. Matching aggregate counts do not prove exact
per-document equality with the provider's exclusion set.

The tool still reports qualified Calls: unresolved dynamic regions change
from 986 to 990 when the extra test source is admitted. It does not turn
callbacks or runtime-selected targets into invented direct calls. The helper's
positive results remain useful, but neither query establishes repository-wide
absence or complete coverage. Generated bundled JavaScript also retains its
separate structural limitations.

All 727 tracked backend files, the commit and clean Git status matched before
and after. Existing indexes, global installations and Switchboard runtime
state were not changed. Index/query commands exited normally and their owned
process groups were empty afterward. Machine-local raw results and scratch
locations remain ignored, outside tracked documentation.

The earlier installed-fixture RED, resolver/adapter controls, tagged CLI/MCP
publication, changed-selection invalidation, and WATCH edit/restore/restart
regressions remain the repeatable product acceptance. This real-repository
probe supplements them; it does not replace the complete product gate.
