# Performance baseline

[Docs](../README.md) / Performance

Process startup, first index, a warm query, and an edit becoming queryable are
different costs. The tables below keep them separate and name the workload.
These are historical reference measurements, not new results for the currently
released binary. The small smoke fixture and real-repository A/B are not
interchangeable benchmarks.

Last reconciled: 2026-08-30

Performance evidence is accepted only from the installed one-file product boundary with
correctness controls active. A quick result that loses source, authority, parity, or cleanup
evidence is not a valid sample.

## Stable non-self-referential reference smoke

This run used assembled candidate
`cf4589330d1bc56a58b166662e96f48a6b0692ac41f0e81897377ac6194adb36` and portable artifact
`7bfd191f90acfafe609f284e2133635c49c302ed9e2e9fb0689363478c1086a8`
(130,010,768 bytes). The benchmark report SHA-256 is
`eb51afb2531173dab79f7d9581bfe220d4ae045a1efe4ec3bb8b94f79e65f04e`.
Logical acceptance identity
`2f1ecf8c57d6efe98ae1455980bad1ec2b697efd0d205245979c79cfb69e467f`
binds this report to the candidate, binary, build/product receipts, exact gate log, and residue
controls.

The deterministic fixture contained 48 source files and 5,161 bytes: 8 Rust, 16 Go, 8 Python,
8 TypeScript, plus project inputs. It finished with Complete Calls authority for all four
languages, exact CLI/MCP parity controls, restored source fingerprints, complete WATCH receipts,
and zero new provider or h00ligan processes.

| Installed-product boundary | Observed time |
| --- | ---: |
| Process startup median / p95 | 1.164 / 1.343 ms |
| Cold four-language semantic index | 1,854.941 ms |
| WATCH process start to ready | 1,967.578 ms |
| Rust edit / restore terminal | 250.609 / 250.394 ms |
| Go edit / restore terminal | 148.296 / 151.133 ms |
| Python edit / restore terminal | 143.196 / 140.556 ms |
| TypeScript edit / restore terminal | 144.048 / 141.835 ms |
| CLI query medians across the measured set | 7.741–8.959 ms |
| Long-lived MCP query medians across the measured set | 2.303–3.375 ms |

These are one controlled host's smoke results, not universal service-level objectives. The run
completed with 198 CI-contract sabotages, 16 installed WATCH lifecycles, nine benchmark WATCH
operations, no new product process, no Python bytecode residue, and an exact post-gate source
mirror. The exact current-candidate performance report is bound by its external acceptance
receipt rather than embedded here, which avoids changing the candidate merely to name itself.

## Real-repository WATCH A/B

A controlled edit/restore probe used a repository generation with 399 indexed files, 24,575 graph
nodes, and 123,984 edges. The summary document SHA-256 is
`9a2d179a4183a0f62ceb23804ea00542872870d0bdc1ed4b5f1c6d22681869b6`.

| Stage | Before edit / restore | After edit / restore |
| --- | ---: | ---: |
| Snapshot overlay | 637 / 675 ms | 18.694 / 18.611 ms |
| Publication | 569 / 1,689 ms | 262.841 / 316.997 ms |
| End-to-end WATCH terminal | 8,717 / 9,110 ms | 8,644 / 4,315 ms |

The snapshot-overlay change removed roughly 97% of that stage's time, and authority writes on the
restore path fell from about 1,410 ms to 87.308 ms. End-to-end edit latency remained dominated by
semantic-provider work: the measured provider RPC span varied to 4,231 ms on edit and 1,108 ms on
restore. This A/B used a changing real repository and is diagnostic evidence, not a deterministic
CI threshold.

## Battery contract

`just perf-smoke` exercises one cold index, one change/restore cycle, and five repetitions of each
CLI/MCP query. `just perf` expands that to three independent cold indexes, three cycles, and 25
query repetitions. Reports preserve raw samples, median and p95 summaries, exclusive versus
overlapping phase timings, executable/source/provider identities, host shape, fixture identity,
authority results, parity, restoration, terminal receipts, and process residue.

Machine-local reports belong under `.h00ligan/performance`. Baselines should come from repeated
quiet-host runs on each supported architecture before becoming regression thresholds.

## Next measured targets

The two largest evidenced performance opportunities are whole-generation WATCH publication and
cold semantic-provider indexing. Profile publisher serialization/synchronization, provider cold
load, source transfer, and invalidation breadth before selecting data structures. Sparse graph
projections, delta overlays, semiring algorithms, or ring buffers are candidates only when an
observed workload matches them and an installed-product A/B proves the benefit.
