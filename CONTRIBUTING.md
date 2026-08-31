# Contributing

`main` is the trunk. Keep changes reviewable, run the proportional local gates,
and install the tracked hooks once per clone:

```bash
just install-hooks
```

## Commit contract

Commit subjects and pull-request titles use
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>[optional scope][!]: <description>
```

Allowed types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`,
`refactor`, `revert`, `style`, and `test`. Use `!` and a `BREAKING CHANGE:`
footer when a change is incompatible. Examples:

```text
feat(ligan): add a JSON impact report
fix(index): preserve repository ownership during recovery
refactor(store)!: remove the legacy global handle
```

The local `commit-msg` hook gives fast feedback. Portable CI independently
checks every new pushed subject and, for pull requests, the PR title. The
checker intentionally starts prospectively; historical pre-policy commits are
not rewritten.

## h00ligan releases

Do not hand-edit release tags, versions, or generated changelog entries.
Release Please derives them from Conventional Commits that touch
`crates/h00ligan`. It maintains a release pull request; merging that PR is the
human release checkpoint. A successful post-merge `Portable CI` run creates a
draft GitHub Release, builds native static Linux AMD64 and ARM64 archives, adds
checksums, SBOMs, and license material, then publishes the completed release.

The current lane creates GitHub releases only. `publish = false` in the crate
manifest deliberately prevents accidental crates.io publication. See
[the release runbook](docs/releasing-h00ligan.md) for recovery and verification.
