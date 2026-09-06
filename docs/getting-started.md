# Getting started

[Docs](README.md) / Getting started

**Get it running. Ask something you can check.**

By the end of this guide, you’ll have an index and know how to find a
definition, its callers, and a relevant test. Start with your own project or
the small guided tour below. This guide uses the released **0.3.0** executable.

[Install](#install) → [Index a project](#choose-a-project-and-index-it) →
[Ask a question](#ask-your-first-question) → [Keep it current](#leave-watch-running)

You do not need Devbox, Docker, a database server, or an API key to run it.

## Install

Download the matching archive and `SHA256SUMS` from the
[0.3.0 release](https://github.com/armenr/h00ligan/releases/tag/h00ligan-v0.3.0).
The repository and release downloads are public.

| Your machine | Archive |
| --- | --- |
| Linux on Intel/AMD x86_64 | `h00ligan-0.3.0-linux-amd64.tar.gz` |
| Linux on ARM64 | `h00ligan-0.3.0-linux-arm64.tar.gz` |
| Apple Silicon Mac | `h00ligan-0.3.0-macos-arm64.tar.gz` |

Intel Mac is deferred and has no 0.3.0 download. Windows is not a release target.

<details open>
<summary><strong>Linux x86_64 / ARM64</strong></summary>

In the download directory, on Linux x86_64:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Continue only if the archive you downloaded is reported `OK`:

```bash
tar -xzf h00ligan-0.3.0-linux-amd64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 0755 h00ligan-0.3.0-linux-amd64/h00ligan "$HOME/.local/bin/h00ligan"
```

On Linux ARM64, substitute `linux-arm64` in the archive and extracted directory
names.

</details>

<details>
<summary><strong>Apple Silicon</strong></summary>

In the download directory:

```bash
grep 'h00ligan-0.3.0-macos-arm64.tar.gz$' SHA256SUMS | shasum -a 256 --check
```

Continue only if the archive is reported `OK`:

```bash
tar -xzf h00ligan-0.3.0-macos-arm64.tar.gz
mkdir -p "$HOME/.local/bin"
install -m 0755 h00ligan-0.3.0-macos-arm64/h00ligan "$HOME/.local/bin/h00ligan"
```

</details>

Put that installation directory on your shell's `PATH`. For the current Bash
or Zsh shell, `export PATH="$HOME/.local/bin:$PATH"` does that; configure your
shell's startup file if you want it to persist. Using the full binary path also
works, including in MCP configurations.

```bash
h00ligan --version
h00ligan --help
```

The 0.3.0 assets report:

```text
h00ligan 0.3.0+0bd9334
```

The suffix identifies the build’s source revision. Linux binaries are static.
The Apple Silicon binary targets
macOS 11.0+ but has only been acceptance-tested on the current native runner,
not every older OS version. It is not Developer ID signed or notarized: macOS
may require explicit approval through its normal security UI. Do not disable
system security globally to install it.

Each archive includes the executable, a compact guide, changelog, build
metadata, dependency inventory, and licenses. No companion binary or service
needs to be installed. These repository guides include corrections made after
0.3.0 was packaged; its immutable archive README may be older.

## Choose a project and index it

From a trusted Git repository:

```bash
h00ligan index --scip
h00ligan status
```

Without `--root`, h00ligan selects the nearest Git ancestor. For a non-Git
directory, a nested project, or any explicit boundary:

```bash
h00ligan --root /path/to/project index --scip
h00ligan --root /path/to/project status
```

It stores the index in `<root>/.h00ligan/code-intel` and ignores its managed
generated state. Use `--data-dir /path/to/separate-index` consistently on every
command if you want a different location. Relative data paths are relative to
the selected project root, not whichever directory you launched from.

Choose the indexing mode deliberately:

| Command | What you get |
| --- | --- |
| `index` | Structural definitions, source spans, types, and structural relationships; no compiler-backed Calls evidence. |
| `index --scip` | Structure plus the semantic evidence each provider can validate. Inspect any coverage gaps. |
| `index --scip --require-complete-calls` | Refuse to publish unless every applicable Calls scope is complete. It does not enable missing capabilities such as Python dead-code classification. |

Go needs a compatible Go toolchain; Rust needs compatible Cargo/Rust tools.
Python/TypeScript providers are included. All languages still need resolvable
project configuration and dependencies for complete semantic answers. Read
[the language guide](languages.md) if indexing reports a gap.

Semantic indexing can execute project toolchains and Rust build scripts. Use
it on trusted code. A cold semantic index may take substantially longer than
later queries; the CLI names the active phase and emits progress heartbeats.

## Ask your first question

First get the lay of the land, then find something you recognize:

```bash
h00ligan overview
h00ligan find '*Handler' --name --definitions-only
```

Replace the pattern with a name from your project. `find` shows file paths and
exact `symbol_id` selectors. Pick a result—not a guessed name—then ask:

| Next question | Command shape |
| --- | --- |
| “Show me the definition.” | `h00ligan read SYMBOL --file relative/path` |
| “Who calls it?” | `h00ligan calls SYMBOL --file relative/path --filter all` |
| “What could my change affect?” | `h00ligan assess SYMBOL --file relative/path --filter all` |

`SYMBOL` and `relative/path` above are placeholders. If multiple occurrences
share both name and file, copy a `symbol_id` from your own `find` result.
Exact selectors belong to a generation; reacquire them after the index changes.

## Try the guided tour

The repository includes a small [Python example](../examples/quickstart/app.py)
with no third-party dependencies. You need a checkout of this documentation,
but **not** Python installed to analyze it with the release executable.

If you don’t have a checkout yet:

```bash
git clone https://github.com/armenr/h00ligan.git
cd h00ligan
```

From the checkout, keep every command bound to the example directory:

```bash
h00ligan --root examples/quickstart index --scip
h00ligan --root examples/quickstart find greeting --name --definitions-only
h00ligan --root examples/quickstart read greeting --file app.py
h00ligan --root examples/quickstart type GreetingStyle --file app.py
h00ligan --root examples/quickstart calls greeting --file app.py --filter all
h00ligan --root examples/quickstart tests greeting --file app.py
```

Check the results against the example source:

| Query | Expected observation |
| --- | --- |
| `find greeting` | One definition in `app.py` |
| `read greeting` | `def greeting(name: str) -> str:` and its greeting-string return |
| `type GreetingStyle` | The class and its `prefix` member |
| `calls greeting --filter all` | Two caller occurrences: `greet` and `test_greeting` |
| `tests greeting` | One runnable test entry: `test_greeting` |

You’ve now followed a definition out to its callers and a relevant test.
That’s the everyday loop. `tests` finds the test; it does not run it or measure
runtime coverage.

> [!IMPORTANT]
> This tour also exposes unfinished work. `status` can show complete Python
> Calls with unclassified nodes, and `dead _unused --file app.py` refuses with
> `reachability_evidence_unavailable`. Python/TypeScript reachability
> classification is not implemented in 0.3.0. Repeating the index will not fix
> it; caller and test queries remain useful. [Why these are different](how-it-works.md#a-caller-is-not-a-verdict).

## Leave WATCH running

```bash
h00ligan --root examples/quickstart watch --scip
```

Use another terminal for queries or edits; Ctrl-C stops WATCH. CLI and MCP can
read the same bundle. Do not start several competing watchers for it. For an
MCP-owned watcher, use [the MCP lifecycle](mcp.md#keep-the-index-current).

## Your next move

- [Use it on real work](cli.md): callers, blast radius, tests, boundaries, and edits.
- [Connect MCP](mcp.md): let your agent query the same map.
- [Teach the workflow](agent-integration.md): copy a prompt or repository guidance.
- [Something doesn’t line up?](troubleshooting.md) Start with the symptom.
