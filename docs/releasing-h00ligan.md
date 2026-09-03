# Releasing h00ligan

h00ligan has one release train. A release contains one product executable for
each supported target, with all private semantic-provider implementations
embedded, plus checksums, a target-specific CycloneDX SBOM, third-party notices,
and build metadata. Compiler-backed semantic analysis of Go and Rust projects
currently resolves a compatible project Go or Cargo/Rust toolchain; users do not
install separate provider executables. Structural indexing and the Python and
TypeScript/JavaScript semantic providers do not require ambient language
toolchains. The automation does not publish any crate to crates.io.

## Normal release

1. Land Conventional Commits on `main`.
2. `Portable CI` must pass for the current `main` commit.
3. `Release h00ligan` opens or updates the Release Please pull request.
4. Review its version, changelog, root lock, and embedded-product lock.
5. Merge that pull request only when the release contents are intended.
6. CI reruns on the release commit. Release Please then creates
   `h00ligan-vX.Y.Z` and a draft GitHub Release.
7. The reusable distribution workflow builds and runs the exact one-file
   product on Linux x86-64, Linux ARM64, Intel macOS, and Apple Silicon.
8. Packaging generates deterministic archives and inventories. The release is
   published only after all four native products and their installed
   CLI/MCP/WATCH/provider acceptance pass.

The workflow refuses to spend a stale green run after `main` advances. A
failed product build therefore cannot create a complete-looking release.

## Version authority

- Package: `crates/h00ligan/Cargo.toml`
- Ledger: `.release-please-manifest.json`
- Tag: `h00ligan-vX.Y.Z`
- Changelog: `crates/h00ligan/CHANGELOG.md`
- Embedded product lock:
  `providers/rust-analyzer/h00ligan-product.Cargo.lock`

Before 1.0, `feat` advances the minor version, `fix` advances the patch
version, and a breaking-change marker advances the minor version. The
`+<source revision>` suffix printed by `h00ligan --version` is build
provenance, not part of the release version.

All workspace packages remain `publish = false`. Registry publication needs
its own design and operator authorization.

## Dry run

The distribution workflow can build without publishing:

```bash
gh workflow run h00ligan-dist.yml \
  --ref main \
  -f ref=main \
  -f version=0.2.0 \
  -f tag=h00ligan-v0.2.0 \
  -f publish=false
```

Verify the downloaded artifact:

```bash
sha256sum --check SHA256SUMS
tar -tzf h00ligan-0.2.0-linux-amd64.tar.gz
tar -tzf h00ligan-0.2.0-linux-arm64.tar.gz
tar -tzf h00ligan-0.2.0-macos-amd64.tar.gz
tar -tzf h00ligan-0.2.0-macos-arm64.tar.gz
```

`publish=false` never creates or edits a release. A recovery run may publish
only an already-reviewed draft whose tag resolves to the exact built commit.

## Trust boundary

- Linux products are static musl executables.
- macOS products are native thin binaries linked only to Apple system
  libraries. They are not Developer ID signed or notarized.
- Release archives include the repository licenses because the binary contains
  both permissive and BSL-licensed local components.
- Every external GitHub Action is pinned to a full commit SHA and carries its
  upstream version and verification date. Re-verify every pin against the
  primary upstream before adopting this extraction as a new repository.
- The exact Rust provider source commit, product lock, generated source
  receipts, and native artifact receipts are all checked before publication.
