#!/usr/bin/env python3
"""Emit one typed terminal receipt for the completed h00ligan product gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile


SCHEMA = "h00ligan/ci-product-terminal/v3"
SOURCE_PREFLIGHT_SCHEMA = "h00ligan/ci-product-source-preflight/v1"
DEFAULT_SOURCE_PREFLIGHT = Path(".h00ligan/gates/ci-product-source-preflight.json")
SOURCE_TREE_VECTOR_SHA256 = (
    "b6b507c1aa27335940ae667c81f9bed92147af22165d44f9c0094ce70dfbb791"
)
BUILD_SCHEMA = "h00/h00ligan-portable-artifact/v3"
PRODUCT_SOURCE_SCHEMA = "h00/h00ligan-product-source-cache/v6"
PERFORMANCE_SCHEMA = "h00/h00ligan-performance/v4"
PREFIX = "H00LIGAN_CI_PRODUCT_RECEIPT="
COMPLETION_MARKER = "All standalone installed-product gates passed"
LANGUAGES = {"rust", "go", "python", "typescript"}
MAX_JSON_BYTES = 64 * 1024 * 1024
SOURCE_EXCLUSIONS = {
    ".agent-docs",
    ".agents",
    ".claude",
    ".codex",
    ".codex-home",
    ".devbox",
    ".git",
    ".h00",
    ".h00ligan",
    "index.scip",
    "target",
}


class ReceiptError(RuntimeError):
    """The completed gate cannot be bound to one exact product run."""


def read_regular(path: Path, label: str, maximum: int | None = None) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReceiptError(f"{label} is missing or unsafe")
    if maximum is not None and path.stat().st_size > maximum:
        raise ReceiptError(f"{label} exceeds its byte bound")
    return path.read_bytes()


def load_json(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = read_regular(path, label, MAX_JSON_BYTES)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ReceiptError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise ReceiptError(f"{label} is not a JSON object")
    return value, raw


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def frame(hasher, value: bytes) -> None:
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)


def source_tree_sha256(repo_root: Path) -> str:
    if repo_root.is_symlink() or not repo_root.is_dir():
        raise ReceiptError("gate source root is missing or unsafe")
    population: list[tuple[str, Path]] = []
    for directory, child_directories, filenames in os.walk(repo_root, followlinks=False):
        root = Path(directory)
        relative_root = root.relative_to(repo_root)
        child_directories.sort()
        filenames.sort()
        if not relative_root.parts:
            child_directories[:] = [
                name for name in child_directories if name not in SOURCE_EXCLUSIONS
            ]
            filenames = [name for name in filenames if name not in SOURCE_EXCLUSIONS]
        for name in child_directories:
            path = root / name
            if path.is_symlink() or not path.is_dir():
                raise ReceiptError(
                    "gate source contains an unsafe directory: "
                    + path.relative_to(repo_root).as_posix()
                )
        for name in filenames:
            path = root / name
            relative = path.relative_to(repo_root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ReceiptError(f"gate source contains an unsafe file: {relative}")
            population.append((relative, path))
    if not population:
        raise ReceiptError("gate source population is empty")
    hasher = hashlib.sha256()
    frame(hasher, b"h00ligan/ci-product-source-tree/v1")
    for relative, path in sorted(population):
        contents = path.read_bytes()
        frame(hasher, relative.encode())
        frame(hasher, stat.S_IMODE(path.stat().st_mode).to_bytes(4, "big"))
        frame(hasher, len(contents).to_bytes(8, "big"))
        frame(hasher, bytes.fromhex(sha256(contents)))
    return hasher.hexdigest()


def source_preflight_output(repo_root: Path, path: Path) -> Path:
    root = repo_root.resolve()
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ReceiptError("source preflight receipt escapes the repository") from error
    if not relative.parts or relative.parts[0] != ".h00ligan":
        raise ReceiptError("source preflight receipt is outside .h00ligan")
    current = root
    for part in relative.parts[:-1]:
        current /= part
        if current.exists() and (current.is_symlink() or not current.is_dir()):
            raise ReceiptError("source preflight receipt traverses an unsafe path")
        current.mkdir(exist_ok=True)
    if absolute.exists() and (absolute.is_symlink() or not absolute.is_file()):
        raise ReceiptError("source preflight receipt is unsafe")
    return absolute


def write_source_preflight(repo_root: Path, path: Path) -> bytes:
    destination = source_preflight_output(repo_root, path)
    raw = canonical_json(
        {
            "schema": SOURCE_PREFLIGHT_SCHEMA,
            "source_tree_sha256": source_tree_sha256(repo_root),
        }
    )
    staging = destination.with_name(f".{destination.name}.staging-{os.getpid()}")
    if staging.exists() or staging.is_symlink():
        raise ReceiptError("source preflight staging path already exists")
    try:
        with staging.open("xb") as handle:
            handle.write(raw)
        os.replace(staging, destination)
    finally:
        if staging.exists() and not staging.is_symlink():
            staging.unlink()
    return raw


def load_source_preflight(
    repo_root: Path,
    path: Path,
) -> tuple[dict[str, object], bytes]:
    path = bound_output(repo_root, path, ".h00ligan", "source preflight receipt")
    document, raw = load_json(path, "source preflight receipt")
    if raw != canonical_json(document):
        raise ReceiptError("source preflight receipt is not canonical")
    expected = {
        "schema": SOURCE_PREFLIGHT_SCHEMA,
        "source_tree_sha256": source_tree_sha256(repo_root),
    }
    if document != expected:
        raise ReceiptError("source changed after ci-product preflight")
    return document, raw


def bound_output(repo_root: Path, path: Path, top: str, label: str) -> Path:
    root = repo_root.resolve()
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ReceiptError(f"{label} escapes the repository") from error
    if not relative.parts or relative.parts[0] != top:
        raise ReceiptError(f"{label} is outside its admitted output root")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ReceiptError(f"{label} traverses a symlink")
    if not absolute.is_file():
        raise ReceiptError(f"{label} is missing")
    return absolute


def derive(
    repo_root: Path,
    source_preflight_path: Path,
    binary_path: Path,
    build_receipt_path: Path,
    product_source_path: Path,
    benchmark_path: Path,
) -> dict[str, object]:
    source_preflight, source_preflight_raw = load_source_preflight(
        repo_root,
        source_preflight_path,
    )
    binary_path = bound_output(repo_root, binary_path, "target", "portable binary")
    build_receipt_path = bound_output(
        repo_root, build_receipt_path, "target", "portable build receipt"
    )
    product_source_path = bound_output(
        repo_root, product_source_path, "target", "product-source receipt"
    )
    benchmark_path = bound_output(
        repo_root, benchmark_path, ".h00ligan", "smoke benchmark report"
    )

    binary_raw = read_regular(binary_path, "portable binary")
    build, build_raw = load_json(build_receipt_path, "portable build receipt")
    product_source, product_source_raw = load_json(
        product_source_path, "product-source receipt"
    )
    benchmark, benchmark_raw = load_json(benchmark_path, "smoke benchmark report")

    binary_sha256 = sha256(binary_raw)
    build_sha256 = sha256(build_raw)
    product_source_sha256 = sha256(product_source_raw)
    if build.get("schema") != BUILD_SCHEMA:
        raise ReceiptError("portable build receipt schema changed")
    if build.get("binary_sha256") != binary_sha256:
        raise ReceiptError("portable binary differs from its build receipt")
    if build.get("binary_size") != len(binary_raw):
        raise ReceiptError("portable binary size differs from its build receipt")
    if product_source.get("schema") != PRODUCT_SOURCE_SCHEMA:
        raise ReceiptError("product-source receipt schema changed")
    source_dirty = product_source.get("source_dirty")
    if not isinstance(source_dirty, bool):
        raise ReceiptError("product-source receipt has invalid Git state")
    if build.get("product_source_receipt_sha256") != product_source_sha256:
        raise ReceiptError("portable build names another product-source receipt")

    if benchmark.get("schema_version") != PERFORMANCE_SCHEMA or benchmark.get("mode") != "smoke":
        raise ReceiptError("terminal benchmark is not the exact smoke contract")
    artifact = benchmark.get("artifact")
    expected_artifact = {
        "product_source_receipt_sha256": product_source_sha256,
        "receipt_sha256": build_sha256,
        "sha256": binary_sha256,
        "target": build.get("target"),
        "version": artifact.get("version") if isinstance(artifact, dict) else None,
    }
    if not isinstance(artifact, dict) or artifact != expected_artifact:
        raise ReceiptError("terminal benchmark names another portable artifact")
    correctness = benchmark.get("correctness")
    if not isinstance(correctness, dict):
        raise ReceiptError("terminal benchmark correctness is absent")
    if correctness.get("calls_authority") != "complete":
        raise ReceiptError("terminal benchmark Calls authority is incomplete")
    if correctness.get("cli_mcp_payload_parity") is not True:
        raise ReceiptError("terminal benchmark CLI/MCP parity is not proven")
    if correctness.get("fixture_restored") is not True:
        raise ReceiptError("terminal benchmark fixture was not restored")
    if correctness.get("fingerprints_restored") != {
        language: True for language in sorted(LANGUAGES)
    }:
        raise ReceiptError("terminal benchmark fingerprints were not restored")
    if correctness.get("new_product_processes") != 0:
        raise ReceiptError("terminal benchmark left product processes")
    started = correctness.get("watch_operations_started")
    if not isinstance(started, int) or started <= 0:
        raise ReceiptError("terminal benchmark WATCH population is vacuous")
    if correctness.get("watch_operations_terminal") != started:
        raise ReceiptError("terminal benchmark WATCH operations are incomplete")

    return {
        "benchmark_report_sha256": sha256(benchmark_raw),
        "binary_sha256": binary_sha256,
        "build_receipt_sha256": build_sha256,
        "product_source_receipt_sha256": product_source_sha256,
        "schema": SCHEMA,
        "source_dirty": source_dirty,
        "source_preflight_receipt_sha256": sha256(source_preflight_raw),
        "source_tree_sha256": source_preflight["source_tree_sha256"],
    }


def resolve_product(repo_root: Path) -> tuple[Path, Path, Path]:
    builder = repo_root / "scripts/build-h00ligan-portable.sh"
    if builder.is_symlink() or not builder.is_file():
        raise ReceiptError("portable builder is missing or unsafe")
    try:
        result = subprocess.run(
            [str(builder), "--machine"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=1800,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReceiptError("portable builder could not resolve the accepted product") from error
    values: dict[str, Path] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if key not in {
            "H00LIGAN_BINARY",
            "H00LIGAN_RECEIPT",
            "H00LIGAN_PRODUCT_SOURCE_RECEIPT",
        }:
            continue
        if not separator or not value or key in values:
            raise ReceiptError(f"portable builder emitted malformed {key}")
        values[key] = Path(value)
    if set(values) != {
        "H00LIGAN_BINARY",
        "H00LIGAN_RECEIPT",
        "H00LIGAN_PRODUCT_SOURCE_RECEIPT",
    }:
        raise ReceiptError("portable builder did not emit one complete artifact identity")
    return (
        values["H00LIGAN_BINARY"],
        values["H00LIGAN_RECEIPT"],
        values["H00LIGAN_PRODUCT_SOURCE_RECEIPT"],
    )


class Fixture:
    def __init__(self, *, source_dirty: bool = False) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "Cargo.toml").write_text(
            "[workspace]\nmembers = []\n", encoding="utf-8"
        )
        artifact = self.root / "target/artifacts/native/key"
        artifact.mkdir(parents=True)
        self.binary = artifact / "h00ligan"
        self.binary.write_bytes(b"fixture-binary")
        self.product_source = self.root / "target/product/source.json"
        self.product_source.parent.mkdir(parents=True)
        self.product_source.write_text(
            json.dumps(
                {
                    "schema": PRODUCT_SOURCE_SCHEMA,
                    "source_dirty": source_dirty,
                    "source_key": "11" * 32,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        product_source_sha256 = sha256(self.product_source.read_bytes())
        self.build = artifact / "h00ligan.build.json"
        self.build.write_text(
            json.dumps(
                {
                    "binary_sha256": sha256(self.binary.read_bytes()),
                    "binary_size": self.binary.stat().st_size,
                    "product_source_receipt_sha256": product_source_sha256,
                    "schema": BUILD_SCHEMA,
                    "target": "x86_64-unknown-linux-musl",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.benchmark = self.root / ".h00ligan/performance/h00ligan-smoke-latest.json"
        self.benchmark.parent.mkdir(parents=True)
        self.benchmark.write_text(
            json.dumps(
                {
                    "artifact": {
                        "product_source_receipt_sha256": product_source_sha256,
                        "receipt_sha256": sha256(self.build.read_bytes()),
                        "sha256": sha256(self.binary.read_bytes()),
                        "target": "x86_64-unknown-linux-musl",
                        "version": "h00ligan 0.2.0+fixture",
                    },
                    "correctness": {
                        "calls_authority": "complete",
                        "cli_mcp_payload_parity": True,
                        "fingerprints_restored": {
                            language: True for language in sorted(LANGUAGES)
                        },
                        "fixture_restored": True,
                        "new_product_processes": 0,
                        "watch_operations_started": 9,
                        "watch_operations_terminal": 9,
                    },
                    "mode": "smoke",
                    "schema_version": PERFORMANCE_SCHEMA,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.source_preflight = self.root / DEFAULT_SOURCE_PREFLIGHT
        write_source_preflight(self.root, self.source_preflight)

    def rebind_product_source(self) -> None:
        product_source_sha256 = sha256(self.product_source.read_bytes())
        build = json.loads(self.build.read_text(encoding="utf-8"))
        build["product_source_receipt_sha256"] = product_source_sha256
        self.build.write_text(
            json.dumps(build, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        benchmark = json.loads(self.benchmark.read_text(encoding="utf-8"))
        benchmark["artifact"]["product_source_receipt_sha256"] = (
            product_source_sha256
        )
        benchmark["artifact"]["receipt_sha256"] = sha256(self.build.read_bytes())
        self.benchmark.write_text(
            json.dumps(benchmark, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def derive(self) -> dict[str, object]:
        return derive(
            self.root,
            self.source_preflight,
            self.binary,
            self.build,
            self.product_source,
            self.benchmark,
        )

    def close(self) -> None:
        self.temporary.cleanup()


def self_test() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        vector_root = Path(temporary)
        vector = vector_root / "fixture.txt"
        vector.write_bytes(b"alpha\n")
        vector.chmod(0o644)
        if source_tree_sha256(vector_root) != SOURCE_TREE_VECTOR_SHA256:
            raise AssertionError("source-tree framing vector changed")

    known = Fixture()
    try:
        receipt = known.derive()
        if (
            receipt.get("schema") != SCHEMA
            or receipt.get("source_dirty") is not False
            or len(str(receipt.get("binary_sha256"))) != 64
        ):
            raise AssertionError("known-positive terminal receipt is vacuous")
    finally:
        known.close()

    # RIGHT-REASON REGRESSION: an uncommitted tree is still a closed product
    # snapshot when the immutable product-source receipt and the start/end
    # source-tree digest bind its exact bytes. Git cleanliness is release
    # policy, not content identity.
    dirty = Fixture(source_dirty=True)
    try:
        receipt = dirty.derive()
        if receipt.get("source_dirty") is not True:
            raise AssertionError("dirty exact-snapshot positive control is vacuous")
    finally:
        dirty.close()

    cases = (
        "binary",
        "build",
        "source",
        "source_state",
        "source_tree",
        "preflight",
        "benchmark",
        "correctness",
        "symlink",
    )
    for case in cases:
        fixture = Fixture()
        try:
            if case == "binary":
                fixture.binary.write_bytes(b"substituted")
            elif case == "build":
                document = json.loads(fixture.build.read_text(encoding="utf-8"))
                document["binary_size"] += 1
                fixture.build.write_text(json.dumps(document), encoding="utf-8")
            elif case == "source":
                fixture.product_source.write_bytes(fixture.product_source.read_bytes() + b" ")
            elif case == "source_state":
                document = json.loads(fixture.product_source.read_text(encoding="utf-8"))
                document["source_dirty"] = "unknown"
                fixture.product_source.write_text(
                    json.dumps(document, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                fixture.rebind_product_source()
            elif case == "source_tree":
                source = fixture.root / "Cargo.toml"
                source.write_bytes(source.read_bytes() + b"# post-preflight drift\n")
            elif case == "preflight":
                fixture.source_preflight.write_bytes(
                    fixture.source_preflight.read_bytes() + b" "
                )
            elif case == "benchmark":
                document = json.loads(fixture.benchmark.read_text(encoding="utf-8"))
                document["artifact"]["sha256"] = "ff" * 32
                fixture.benchmark.write_text(json.dumps(document), encoding="utf-8")
            elif case == "correctness":
                document = json.loads(fixture.benchmark.read_text(encoding="utf-8"))
                document["correctness"]["calls_authority"] = "partial"
                fixture.benchmark.write_text(json.dumps(document), encoding="utf-8")
            else:
                actual = fixture.binary.with_name("actual-h00ligan")
                fixture.binary.rename(actual)
                fixture.binary.symlink_to(actual)
            try:
                fixture.derive()
            except ReceiptError:
                pass
            else:
                raise AssertionError(f"terminal receipt {case} sabotage did not fire")
        finally:
            fixture.close()
    return len(cases)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--benchmark-report",
        type=Path,
        default=Path(".h00ligan/performance/h00ligan-smoke-latest.json"),
    )
    parser.add_argument(
        "--source-preflight",
        type=Path,
        default=DEFAULT_SOURCE_PREFLIGHT,
    )
    parser.add_argument("--begin", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        count = self_test()
        print(f"h00ligan-ci-product-receipt: self-test OK ({count} sabotage controls fired)")
        return 0

    repo_root = args.root.resolve()
    source_preflight = args.source_preflight
    if not source_preflight.is_absolute():
        source_preflight = repo_root / source_preflight
    if args.begin:
        raw = write_source_preflight(repo_root, source_preflight)
        print(
            "H00LIGAN_CI_PRODUCT_PREFLIGHT="
            + json.dumps(
                {
                    "receipt_sha256": sha256(raw),
                    "schema": SOURCE_PREFLIGHT_SCHEMA,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    benchmark = args.benchmark_report
    if not benchmark.is_absolute():
        benchmark = repo_root / benchmark
    binary, build_receipt, product_source = resolve_product(repo_root)
    receipt = derive(
        repo_root,
        source_preflight,
        binary,
        build_receipt,
        product_source,
        benchmark,
    )
    print(COMPLETION_MARKER)
    print(PREFIX + json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
