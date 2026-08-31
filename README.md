# h00ligan

`h00ligan` is a portable code-intelligence engine for humans and coding
agents. It builds an immutable, repository-local knowledge graph and exposes
the same bounded results through a human CLI and an MCP stdio server. Its
structural index works without a compiler; embedded or locally resolved
semantic providers add compiler-backed Calls authority for Rust, Go, Python,
and TypeScript/JavaScript while reporting every uncovered scope explicitly.

The shipped product is delivered as one executable. Rust provider dispatch
re-enters that executable; the Go, Python, and TypeScript providers are
content-verified private artifacts embedded in it and materialized only inside
the selected data directory. Users install no helper product or background
service.

## Quick start

```bash
h00ligan --root /path/to/repository index
h00ligan --root /path/to/repository status
h00ligan --root /path/to/repository overview
h00ligan --root /path/to/repository find '*Handler'
h00ligan --root /path/to/repository inspect HandlerName
```

Run `index --scip` when compiler-backed relationships are required. The default
bundle lives at `<repository>/.h00ligan/code-intel`; `--data-dir` selects an
explicit alternate location. WATCH publishes complete immutable generations
after source or toolchain changes rather than exposing an in-place partial
index.

Start the repository-bound MCP server with:

```bash
h00ligan --root /path/to/repository mcp-serve
```

MCP indexing is non-blocking: `reindex` returns an operation ID, and
`reindex_status` or `reindex_cancel` accepts only that exact ID. The process is
bound to one repository for its lifetime.

See [the product guide](crates/h00ligan/README.md) for the complete CLI/MCP
contract, authority model, provider behavior, and release-shaped installation
instructions.

## Development

Enter the pinned Devbox environment and run:

```bash
just ci
```

Enable the same Conventional Commit check locally once per clone:

```bash
just install-hooks
```

`just ci-product` additionally builds and exercises the installed one-file
CLI/MCP/WATCH/provider lifecycle. `just build-portable` produces the
distribution-shaped artifact for the current platform.

## Workspace

- `h00ligan` owns the executable, CLI, MCP entrypoint, WATCH command, and
  one-file provider assembly.
- `h00ligan-engine` owns indexing, immutable publication, semantic authority,
  and query semantics.
- `h00ligan-interface` owns the bounded tool registry and MCP transport.
- `h00ligan-provider-protocol` owns the typed provider process contract.

These four packages are the complete standalone source workspace.

## License

The extracted source currently retains the licenses declared by its originating
components: the engine and provider protocol carry BSL-1.1 declarations, while
the executable and interface carry MIT OR Apache-2.0 declarations. Final
standalone-product licensing is a release decision and is intentionally not
changed by the isolation proof.
