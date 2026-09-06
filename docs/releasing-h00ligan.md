# Releasing h00ligan

h00ligan has one release train, one executable per target, and no crates.io
publication. Archives contain the binary, compact guide, changelog, licenses,
target-specific CycloneDX SBOM, third-party notices and build metadata.
Semantic providers are embedded; Rust/Go still need compatible project tools.
See [language prerequisites](languages.md), not the contributor Devbox, for
what a release user needs.

## Actual 0.3.0 release and current automation boundary

[0.3.0 is published](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0)
at source `0bd933483ceeef6e25a0d11c822bb0e7d03bd9d9`, with three archives:

- `h00ligan-0.3.0-linux-amd64.tar.gz`
- `h00ligan-0.3.0-linux-arm64.tar.gz`
- `h00ligan-0.3.0-macos-arm64.tar.gz`

A release-wide `SHA256SUMS` accompanies them. The repository is public as
verified on 2026-09-06. **Intel Mac is parked** under explicit operator direction.

In [run 33971941146](https://github.com/armenr/h00ligan/actions/runs/33971941146),
those three native jobs passed installed acceptance. Intel compiled but failed
its build-authority fixture readiness barrier, so the four-target aggregate
failed and automatic packaging/publication did not run. The three accepted
artifacts were packaged using the checked-in release steps with the target set
restricted to those successes, then uploaded and published. Binary bytes were
unchanged; fresh downloads passed checksums, closed archive membership and
build identity checks. Downloaded Linux CLI/MCP/WATCH behavior was exercised.

Do not describe that as a green end-to-end automatic run. The workflow still
contains the Intel lane; **reconcile its target policy before the next native
dispatch** rather than paying for another known four-target failure. Release
Please's repository permission was repaired on 2026-09-06: maintenance
[run 34012749986](https://github.com/armenr/h00ligan/actions/runs/34012749986/attempts/2)
created [the 0.3.1 preparation PR](https://github.com/armenr/h00ligan/pull/21)
without building or publishing a release.

Do not retag 0.3.0, replace its assets, or rewrite its changelog to incorporate
later documentation. Those bytes are the published historical product.

## Configured release flow

The checked-in automation is designed to:

1. Accept Conventional Commits on `main` after source CI.
2. Open/update one Release Please PR with version, changelog and lock updates.
3. After its reviewed merge and exact-source CI, create the tag and a draft release.
4. Build native products and run their installed CLI/MCP/WATCH/provider acceptance.
5. Generate deterministic archives, inventories and checksums; publish only
   after the configured target set passes.

At 0.3.0 source the configured set is four targets, while the operator-approved
shipped set is three. That mismatch is pending engineering work, not something
this documentation silently fixes. Preserve all acceptance checks for retained
targets. The existing workflow rejects using a stale green source run after
`main` advances.

### Release automation identity

Release Please uses a private GitHub App installed only on this repository.
Configure the repository Actions variable `RELEASE_APP_CLIENT_ID` and secret
`RELEASE_APP_PRIVATE_KEY`; never put the private key in source or release notes.
The App needs Contents and Pull requests read-write access, no webhooks,
administration permission, or running service. No personal access token is needed.

After current-green-main admission, the workflow mints a short-lived installation
token with exactly those two permissions for the current repository, checks its
repository population, and revokes it when the job ends. The built-in
`GITHUB_TOKEN` stays read-only in the maintenance job. Credentials are not passed
to source-PR code or distributed binaries.

The App token lets release-PR updates start normal source CI automatically.
With the built-in token, GitHub instead requires an explicit workflow-approval
click. This is distinct from reviewing or merging the release PR: the App does
neither automatically. The release PR may stay open while work accumulates;
only its intentional merge followed by green source CI starts distribution.
See [GitHub's token-trigger rules](https://docs.github.com/en/actions/concepts/security/github_token).

Before calling a credentials change accepted, observe the real maintenance
job mint/use/revoke its token and update the release PR, then verify automatic
CI at that exact PR head. A static workflow check or an existing secret's name
does not prove the installed App/key pair works. Leave the release PR unmerged
when only testing release preparation; that does not authorize publication.

Before starting a future run, inspect existing queued/running jobs, the exact
source SHA, draft/tag state and artifact availability. Reuse accepted exact-source
artifacts when legitimate; do not blindly rerun expensive successful native jobs.
Changing source invalidates the old artifact's acceptance for that new source.

## Version authority

- Public product version: `version.txt`.
- Executable package: `crates/h00ligan/Cargo.toml`.
- Release ledger: `.release-please-manifest.json`.
- Tag: `h00ligan-vX.Y.Z`.
- Changelog: `crates/h00ligan/CHANGELOG.md`.
- Root lock: `Cargo.lock`.
- Embedded product lock: `providers/rust-analyzer/h00ligan-product.Cargo.lock`.

Release Please treats `.` as one product component. Conventional changes to
the engine, interface, protocol, providers or packaging belong to that release,
not independent crate release trains. The `simple` strategy synchronizes the
public version and executable/lock coordinates. Before 1.0, features and
breaking changes advance the minor version; fixes advance the patch version.
The `+<source revision>` version suffix is provenance, not the release version.

All workspace packages remain `publish = false`. Registry publication and
repository visibility changes are separate decisions.

## Non-publishing and recovery runs

The workflow has a `publish=false` mode. After resolving the pending target
policy and selecting an intended source/version, its invocation shape is:

```text
gh workflow run h00ligan-dist.yml --ref <workflow-ref> \
  -f ref=<exact-source-sha> -f version=<X.Y.Z> \
  -f tag=<h00ligan-vX.Y.Z> -f publish=false
```

Replace the placeholders; this is not an instruction to rebuild the already
published 0.3.0. A non-publishing run does not create/edit a release. A recovery
publication must target an already-reviewed draft whose tag matches the built
commit; it must not overwrite a completed release.

## Download acceptance

For one downloaded Linux archive and the release's checksum manifest:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -tzf h00ligan-0.3.0-linux-amd64.tar.gz
```

Inspect membership before extraction. Verify the exact binary digest and
target/source metadata against the accepted native artifact, not only the
archive's self-consistency. Run installed CLI/MCP/WATCH checks on the actual
download. Do not relabel a host-development binary as the portable product.

Linux releases are static musl executables. macOS releases are thin native
binaries linked to Apple system libraries, without Developer ID signing or
notarization. Current-runner acceptance does not prove every older deployment
target works. The archive retains applicable permissive and BSL component
licenses; a final unified public license remains a later decision.

External Actions are pinned to immutable commits. Verify upstream releases
when changing tooling; preserve provider source/patch/lock identities and
native artifact receipts throughout packaging.
