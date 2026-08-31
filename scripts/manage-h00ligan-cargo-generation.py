#!/usr/bin/env python3
"""Bind h00ligan's mutable Cargo output to one receipted build generation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time


SCHEMA = "h00/h00ligan-cargo-generation/v1"
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
LOCAL_CARGO_ROOTS = ("source", "product", "rust-provider")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def require_digest(value: str, label: str) -> str:
    if HEX_DIGEST.fullmatch(value) is None:
        raise SystemExit(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def require_real_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"{label} must be a real directory: {path}")
    return path


def load_generation(path: Path) -> dict[str, object] | None:
    if path.is_symlink():
        raise SystemExit(f"Cargo generation receipt must not be a symlink: {path}")
    if not path.exists():
        return None
    if not path.is_file():
        raise SystemExit(f"Cargo generation receipt must be a regular file: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        return None
    for name in ("build_key", "source_key", "binary_sha256"):
        value = payload.get(name)
        if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
            return None
    if not isinstance(payload.get("target"), str):
        return None
    if not isinstance(payload.get("binary_size"), int) or payload["binary_size"] < 0:
        return None
    return payload


def freshness_floor_ns(roots: list[Path], mutable_binary: Path) -> int:
    floor = time.time_ns()
    candidates: list[Path] = []
    for root in roots:
        if root.is_symlink():
            raise SystemExit(f"Cargo freshness root must not be a symlink: {root}")
        if not root.exists():
            continue
        if not root.is_dir():
            raise SystemExit(f"Cargo freshness root must be a directory: {root}")
        candidates.extend(root.glob(".fingerprint/*/invoked.timestamp"))
    if mutable_binary.exists():
        candidates.append(mutable_binary)
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        floor = max(floor, candidate.stat().st_mtime_ns + 1)
    return floor


def cargo_inputs(candidate: Path) -> list[Path]:
    inputs: list[Path] = []
    for relative in LOCAL_CARGO_ROOTS:
        root = require_real_directory(candidate / relative, f"candidate {relative} root")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise SystemExit(f"candidate Cargo input must not be a symlink: {path}")
            if path.is_file():
                inputs.append(path)
            elif not path.is_dir():
                raise SystemExit(f"unsupported candidate Cargo input: {path}")
    if not inputs:
        raise SystemExit("candidate Cargo input population is empty")
    return sorted(inputs, key=lambda path: path.relative_to(candidate).as_posix())


def generation_matches(
    payload: dict[str, object] | None,
    *,
    target: str,
    build_key: str,
    source_key: str,
    mutable_binary: Path,
) -> bool:
    if payload is None:
        return False
    if (
        payload.get("target") != target
        or payload.get("build_key") != build_key
        or payload.get("source_key") != source_key
        or mutable_binary.is_symlink()
        or not mutable_binary.is_file()
    ):
        return False
    return (
        payload.get("binary_size") == mutable_binary.stat().st_size
        and payload.get("binary_sha256") == digest(mutable_binary)
    )


def prepare(args: argparse.Namespace) -> int:
    candidate = require_real_directory(args.candidate, "candidate workspace")
    if args.previous.exists():
        require_real_directory(args.previous, "previous workspace")
    build_key = require_digest(args.build_key, "build key")
    source_key = require_digest(args.source_key, "source key")
    payload = load_generation(args.receipt)
    if generation_matches(
        payload,
        target=args.target,
        build_key=build_key,
        source_key=source_key,
        mutable_binary=args.mutable_binary,
    ):
        print("Cargo generation unchanged; verified mutable output may be reused", file=sys.stderr)
        return 0

    floor = freshness_floor_ns(args.freshness_root, args.mutable_binary)
    inputs = cargo_inputs(candidate)
    for path in inputs:
        os.utime(path, ns=(floor, floor))
    print(
        f"Cargo generation changed or unproven; invalidated {len(inputs)} product-local inputs",
        file=sys.stderr,
    )
    return 0


def record(args: argparse.Namespace) -> int:
    build_key = require_digest(args.build_key, "build key")
    source_key = require_digest(args.source_key, "source key")
    binary = args.binary
    if binary.is_symlink() or not binary.is_file():
        raise SystemExit(f"Cargo generation binary must be a regular file: {binary}")
    receipt = args.receipt
    require_real_directory(receipt.parent, "Cargo generation receipt parent")
    if receipt.is_symlink() or (receipt.exists() and not receipt.is_file()):
        raise SystemExit(f"Cargo generation receipt path is unsafe: {receipt}")
    payload = {
        "schema": SCHEMA,
        "target": args.target,
        "build_key": build_key,
        "source_key": source_key,
        "binary_sha256": digest(binary),
        "binary_size": binary.stat().st_size,
    }
    temporary = receipt.parent / f".{receipt.name}.{os.getpid()}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise SystemExit(f"Cargo generation receipt temporary path is occupied: {temporary}")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, receipt)
        directory = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--candidate", type=Path, required=True)
    prepare_parser.add_argument("--previous", type=Path, required=True)
    prepare_parser.add_argument("--receipt", type=Path, required=True)
    prepare_parser.add_argument("--target", required=True)
    prepare_parser.add_argument("--build-key", required=True)
    prepare_parser.add_argument("--source-key", required=True)
    prepare_parser.add_argument("--mutable-binary", type=Path, required=True)
    prepare_parser.add_argument(
        "--freshness-root", type=Path, action="append", default=[], required=True
    )
    prepare_parser.set_defaults(run=prepare)

    record_parser = commands.add_parser("record")
    record_parser.add_argument("--receipt", type=Path, required=True)
    record_parser.add_argument("--target", required=True)
    record_parser.add_argument("--build-key", required=True)
    record_parser.add_argument("--source-key", required=True)
    record_parser.add_argument("--binary", type=Path, required=True)
    record_parser.set_defaults(run=record)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
