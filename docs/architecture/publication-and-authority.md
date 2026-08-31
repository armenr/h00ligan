# Publication and authority

Last verified: 2026-08-28

## Immutable bundle model

The default repository-local bundle is `.h00ligan/code-intel`; `--data-dir` selects another
explicit location. A published generation binds the graph, indexed source state, project
inventory, provider payloads, capability receipts, repository identity, parent generation, source
revision, and content digests.

Internal schema identifiers currently retain `h00/code-intel/...` lineage names. They are data
contract identifiers, not an h00.sh runtime dependency.

## Write protocol

For one publication, the writer:

1. captures an open capability for the exact selected publication directory and its directory
   identity;
2. acquires the single writer lease;
3. constructs one private generation and its `generation.redb` payload;
4. closes and durably synchronizes the payload and control data;
5. moves the completed generation directory into the immutable population;
6. replaces one of two checksummed head records only after the generation is durable.

The open directory capability prevents a later rename or symlink substitution from retargeting
publication effects. A cancelled, failed, or crashed writer does not make a private partial
generation visible to readers.

## Read protocol

Readers do not scan the generation directory and do not adopt unreferenced generations. They
validate the newest head-referenced generation and may fall back to the other valid head when the
newest referenced generation is corrupt or incomplete.

A successful open returns one authenticated content object containing the graph and its coupled
source/project/capability state. Query paths share that immutable object rather than independently
reopening pieces that could describe different generations.

## Authority dimensions

h00ligan keeps these dimensions separate:

- **publication integrity** — the manifest, heads, payloads, and content digests belong together;
- **repository identity** — the generation belongs to the repository bound at process or command
  startup;
- **structural authority** — registered source was parsed and joined into the structural graph;
- **Calls authority** — compiler-backed coverage is complete, qualified, partial, or unavailable
  per language and project unit;
- **source authority** — selected indexed bytes and spans match their recorded source evidence;
- **live freshness** — current repository inputs are fresh, stale, or unknown relative to the
  immutable generation.

No single “healthy” flag substitutes for these axes. In particular, a structurally complete graph
can lack Calls authority, and a semantically complete immutable generation can be stale relative
to the worktree.

## Query behavior during drift

Generation-bound queries continue to return the explicitly identified immutable truth when live
inputs are stale or unknown, with that qualification attached. This avoids throwing away useful
evidence while preventing it from masquerading as current source.

`diff` intentionally joins the immutable generation to current files. `grep_context` searches
current registered-language bytes and attaches a graph symbol only when the whole-file content
hash still matches the generation. `read` and `inspect` refuse materialization when the selected
file's bytes have changed because returning a stale span as current source would be false.

## WATCH and recovery

WATCH coalesces relevant source, configuration, and toolchain events into supervised operations.
It may supersede obsolete work, but readers keep using the last valid generation until one
complete replacement is published. Terminal operation receipts distinguish success, failure,
cancellation, and supersession.

Publication recovery is explicit. It may replace damaged or conflicting state only through the
same repository-binding and immutable-publication checks; ordinary reads never infer ownership
from leftover files or silently adopt an orphan generation.
