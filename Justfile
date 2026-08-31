default:
    @just --list

# Development artifacts may depend on the active build environment. Use the
# portable recipe for anything intended for distribution.
build:
    cargo build --locked --offline --workspace --all-targets --all-features

build-portable:
    scripts/build-h00ligan-portable.sh

install:
    scripts/build-h00ligan-portable.sh --install

# Opt in once per clone; CI validates the same commit-subject contract
# independently, so local configuration is convenience rather than authority.
install-hooks:
    test "$(git rev-parse --show-toplevel)" = "$(pwd -P)"
    git config --local core.hooksPath .githooks

check:
    cargo check --locked --offline --workspace --all-targets --all-features

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --locked --offline --workspace --all-targets --all-features -- -D warnings

# Real-process integration tests are serial so every fixture owns its complete
# publication and process lifecycle deterministically.
test:
    cargo test --locked --offline --workspace --all-targets --all-features -- --test-threads=1

# Keep the standalone gate topology executable and sabotage-tested. This
# validator also checks the one-file builder, provider lifecycle, performance
# harness, distribution workflow, and exact embedded-product lock.
ci-product-preflight:
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/emit-h00ligan-ci-product-receipt.py --begin --source-preflight .h00ligan/gates/ci-product-source-preflight.json

ci-contract: perf-contract
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-ci.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/emit-h00ligan-ci-product-receipt.py --self-test

# Fast portability controls which do not build or install the product.
portability-check:
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-binary.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/publish-h00ligan-cache-directory.py --self-test

# The standalone workspace is the shipped source graph, so dependency policy
# runs at its real root. Invoke the pinned executable directly because
# `cargo deny` may rediscover a host-Cargo sibling before the Devbox PATH.
deps-check:
    @test "$(cargo-deny --version)" = 'cargo-deny 0.20.2'
    cargo-deny --offline --locked --exclude-dev -L error check

# Static release authorities. Exact installed-product acceptance remains in
# `ci-product`, where it cannot be mistaken for source-only compilation.
release-check:
    @test "$(actionlint -version | sed -n '1p')" = '1.7.12'
    shellcheck --version | grep -Fx 'version: 0.11.0'
    actionlint -color
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-conventional-commits.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-action-pins.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-action-pins.py
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/normalize-h00ligan-sbom.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-sbom.py --self-test
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-release.py
    scripts/package-h00ligan-release.sh --self-test
    shellcheck .githooks/commit-msg scripts/bench-h00ligan-product.sh scripts/build-h00-go-semantic-provider.sh scripts/build-h00-pyrefly-semantic-provider.sh scripts/build-h00-rust-semantic-provider.sh scripts/build-h00-typescript-semantic-provider.sh scripts/build-h00ligan-portable.sh scripts/package-h00ligan-release.sh scripts/resolve-h00-official-go-sdk.sh scripts/test-h00ligan-installed-product.sh

test-installed:
    scripts/test-h00ligan-installed-product.sh

perf-contract:
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/bench-h00ligan.py --self-test

perf-smoke: perf-contract
    scripts/bench-h00ligan-product.sh smoke

perf: perf-contract
    scripts/bench-h00ligan-product.sh full

ci: ci-contract portability-check fmt-check check lint test deps-check release-check
    @echo "All standalone source gates passed"

# This boundary builds and drives the one-file CLI, MCP, WATCH, and embedded
# semantic-provider product rather than certifying only Cargo's development bin.
ci-product: ci-product-preflight ci test-installed perf-smoke
    PYTHONDONTWRITEBYTECODE=1 python3 scripts/emit-h00ligan-ci-product-receipt.py --benchmark-report .h00ligan/performance/h00ligan-smoke-latest.json --source-preflight .h00ligan/gates/ci-product-source-preflight.json
