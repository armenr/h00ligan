#!/usr/bin/env python3
"""Atomically publish or replay one immutable h00ligan cache directory."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


REPLAY_ERRNOS = {errno.EEXIST, errno.ENOTEMPTY}


def require_real_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise SystemExit(f"{label} must be a real directory: {path}")
    return path


def require_owned_path(path: Path, owner: Path, label: str) -> None:
    try:
        relative = path.absolute().relative_to(owner.absolute())
    except ValueError as error:
        raise SystemExit(f"{label} escapes its owner root: {path}") from error
    if not relative.parts:
        raise SystemExit(f"{label} must not equal its owner root")
    current = owner
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise SystemExit(f"{label} traverses a symlink: {current}")


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish(candidate: Path, destination: Path, owner: Path) -> str:
    require_real_directory(owner, "cache owner root")
    require_real_directory(candidate, "cache publication candidate")
    require_real_directory(candidate.parent, "candidate parent")
    require_real_directory(destination.parent, "destination parent")
    require_owned_path(candidate, owner, "candidate")
    require_owned_path(destination, owner, "destination")
    if candidate.stat().st_dev != destination.parent.stat().st_dev:
        raise SystemExit("cache publication candidate and destination are not co-filesystem")
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise SystemExit(f"cache publication destination is unsafe: {destination}")

    try:
        os.rename(candidate, destination)
        outcome = "published"
    except OSError as error:
        if error.errno not in REPLAY_ERRNOS:
            raise
        require_real_directory(destination, "winning cache publication")
        shutil.rmtree(candidate)
        outcome = "replayed"
    fsync_directory(destination.parent)
    return outcome


def run_publish(args: argparse.Namespace) -> int:
    print(publish(args.candidate, args.destination, args.owner_root))
    return 0


def self_test() -> int:
    repository_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="h00ligan-cache-publication.") as raw:
        root = Path(raw)
        try:
            root.resolve().relative_to(repository_root.resolve())
        except ValueError:
            pass
        else:
            raise AssertionError(
                "cache-publication self-test scratch must remain outside the repository"
            )

        # Positive control for the former shell `mv source existing-directory`
        # behavior: it nests the loser and pollutes the immutable winner.
        naive_destination = root / "naive-destination"
        naive_destination.mkdir()
        (naive_destination / "winner").write_text("winner", encoding="utf-8")
        naive_candidate = root / "artifact.naive"
        naive_candidate.mkdir()
        (naive_candidate / "loser").write_text("loser", encoding="utf-8")
        shutil.move(str(naive_candidate), str(naive_destination))
        if not (naive_destination / "artifact.naive/loser").is_file():
            raise AssertionError("nested-directory publication hazard did not fire")

        sequential = root / "sequential"
        sequential.mkdir()
        first = sequential / "artifact.first"
        second = sequential / "artifact.second"
        destination = sequential / "immutable"
        first.mkdir()
        second.mkdir()
        (first / "winner").write_text("first", encoding="utf-8")
        (second / "loser").write_text("second", encoding="utf-8")
        if publish(first, destination, root) != "published":
            raise AssertionError("first cache publication did not win")
        if publish(second, destination, root) != "replayed":
            raise AssertionError("second cache publication did not become replay")
        if (destination / "winner").read_text(encoding="utf-8") != "first":
            raise AssertionError("replay changed the immutable winner")
        if second.exists() or any(path.name.startswith("artifact.") for path in destination.iterdir()):
            raise AssertionError("replay nested or retained its publication candidate")

        concurrent = root / "concurrent"
        concurrent.mkdir()
        candidates = [concurrent / "artifact.a", concurrent / "artifact.b"]
        for index, candidate in enumerate(candidates):
            candidate.mkdir()
            (candidate / "marker").write_text(str(index), encoding="utf-8")
        concurrent_destination = concurrent / "immutable"
        commands = [
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "publish",
                "--owner-root",
                str(root),
                "--candidate",
                str(candidate),
                "--destination",
                str(concurrent_destination),
            ]
            for candidate in candidates
        ]
        processes = [
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for command in commands
        ]
        results = [process.communicate(timeout=10) for process in processes]
        if any(process.returncode != 0 for process in processes):
            raise AssertionError(f"concurrent cache publishers failed: {results!r}")
        outcomes = sorted(stdout.strip() for stdout, _ in results)
        if outcomes != ["published", "replayed"]:
            raise AssertionError(f"concurrent publication outcomes were {outcomes!r}")
        population = sorted(path.name for path in concurrent_destination.iterdir())
        if population != ["marker"] or concurrent_destination.joinpath("marker").read_text() not in {"0", "1"}:
            raise AssertionError(
                f"concurrent publication produced a mixed population: {population!r}"
            )
        if any(candidate.exists() for candidate in candidates):
            raise AssertionError("concurrent publication retained a losing candidate")
    return 3


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--self-test", action="store_true")
    commands = root.add_subparsers(dest="command")
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--owner-root", type=Path, required=True)
    publish_parser.add_argument("--candidate", type=Path, required=True)
    publish_parser.add_argument("--destination", type=Path, required=True)
    publish_parser.set_defaults(run=run_publish)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.self_test:
        count = self_test()
        print(f"h00ligan-cache-publication: self-test OK ({count} controls)")
        return 0
    if not hasattr(args, "run"):
        parser().error("a command or --self-test is required")
    return args.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
