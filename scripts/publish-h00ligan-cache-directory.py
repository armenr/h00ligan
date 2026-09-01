#!/usr/bin/env python3
"""Atomically publish or replay one immutable h00ligan cache directory."""

from __future__ import annotations

import argparse
import errno
import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time


REPLAY_ERRNOS = {errno.EEXIST, errno.ENOTEMPTY}
LOCK_DESCRIPTOR_ENV = "H00LIGAN_CACHE_LOCK_FD"


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


def validate_lock_path(lock_file: Path, owner: Path) -> None:
    require_real_directory(owner, "cache owner root")
    require_real_directory(lock_file.parent, "cache lock parent")
    require_owned_path(lock_file, owner, "cache lock")
    if lock_file.is_symlink():
        raise SystemExit(f"cache lock must not be a symlink: {lock_file}")


def validate_lock_descriptor(
    lock_file: Path,
    owner: Path,
    descriptor: int,
    *,
    blocking: bool,
) -> None:
    validate_lock_path(lock_file, owner)
    try:
        descriptor_status = os.fstat(descriptor)
    except OSError as error:
        raise SystemExit("cache lock descriptor is not open") from error
    try:
        path_status = os.stat(lock_file, follow_symlinks=False)
    except OSError as error:
        raise SystemExit(f"cache lock is missing: {lock_file}") from error
    if not stat.S_ISREG(descriptor_status.st_mode) or not stat.S_ISREG(path_status.st_mode):
        raise SystemExit(f"cache lock must be a regular file: {lock_file}")
    if (descriptor_status.st_dev, descriptor_status.st_ino) != (
        path_status.st_dev,
        path_status.st_ino,
    ):
        raise SystemExit("cache lock descriptor names another file")
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(descriptor, operation)
    except BlockingIOError as error:
        raise SystemExit("cache lock descriptor does not own the active lock") from error


def locked_exec(lock_file: Path, owner: Path, command: list[str]) -> None:
    """Replace this process while retaining one crash-released cache lock."""
    validate_lock_path(lock_file, owner)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("locked cache execution requires a command")

    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_file, flags, 0o600)
    try:
        validate_lock_descriptor(
            lock_file,
            owner,
            descriptor,
            blocking=True,
        )
    except BaseException:
        os.close(descriptor)
        raise
    os.set_inheritable(descriptor, True)
    environment = os.environ.copy()
    environment[LOCK_DESCRIPTOR_ENV] = str(descriptor)
    os.execvpe(command[0], command, environment)


def run_locked_exec(args: argparse.Namespace) -> int:
    locked_exec(args.lock_file, args.owner_root, args.command)
    raise AssertionError("locked exec unexpectedly returned")


def run_verify_lock(args: argparse.Namespace) -> int:
    validate_lock_descriptor(
        args.lock_file,
        args.owner_root,
        args.descriptor,
        blocking=False,
    )
    return 0


def self_test() -> int:
    repository_root = Path(__file__).resolve().parent.parent
    controls = 0
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
        controls += 1

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
        controls += 1

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
        controls += 1

        lock_root = root / "locked-exec"
        lock_root.mkdir()
        lock_file = lock_root / "compiler.lock"
        log = lock_root / "order.log"
        probe = (
            "from pathlib import Path; import fcntl,os,sys,time; "
            f"fd=int(os.environ[{LOCK_DESCRIPTOR_ENV!r}]); "
            "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB); "
            "path=Path(sys.argv[1]); token=sys.argv[2]; "
            "stream=path.open('a'); stream.write(token+':start\\n'); stream.flush(); "
            "time.sleep(0.2); stream.write(token+':end\\n'); stream.close()"
        )

        def locked_command(token: str) -> list[str]:
            return [
                sys.executable,
                str(Path(__file__).resolve()),
                "locked-exec",
                "--owner-root",
                str(lock_root),
                "--lock-file",
                str(lock_file),
                "--",
                sys.executable,
                "-c",
                probe,
                str(log),
                token,
            ]

        first = subprocess.Popen(locked_command("first"))
        deadline = time.monotonic() + 5
        while (not log.exists() or "first:start" not in log.read_text()) and time.monotonic() < deadline:
            time.sleep(0.01)
        if not log.exists() or "first:start" not in log.read_text():
            first.kill()
            raise AssertionError("locked-exec positive control never acquired its lock")
        second = subprocess.Popen(locked_command("second"))
        if first.wait(timeout=5) != 0 or second.wait(timeout=5) != 0:
            raise AssertionError("locked-exec serialization probes failed")
        if log.read_text().splitlines() != [
            "first:start",
            "first:end",
            "second:start",
            "second:end",
        ]:
            raise AssertionError(f"locked-exec did not serialize: {log.read_text()!r}")
        controls += 1

        forged = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "verify-lock",
                "--owner-root",
                str(lock_root),
                "--lock-file",
                str(lock_file),
                "--descriptor",
                "999999",
            ],
            capture_output=True,
            text=True,
        )
        if forged.returncode == 0 or "descriptor is not open" not in forged.stderr:
            raise AssertionError("verify-lock accepted a forged inherited descriptor")
        controls += 1

        unsafe_lock = lock_root / "unsafe.lock"
        unsafe_lock.symlink_to(root / "outside.lock")
        rejected = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "locked-exec",
                "--owner-root",
                str(lock_root),
                "--lock-file",
                str(unsafe_lock),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(99)",
            ],
            capture_output=True,
            text=True,
        )
        if rejected.returncode == 0 or "must not be a symlink" not in rejected.stderr:
            raise AssertionError("locked-exec accepted a symlinked lock")
        controls += 1
    return controls


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--self-test", action="store_true")
    commands = root.add_subparsers(dest="command")
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--owner-root", type=Path, required=True)
    publish_parser.add_argument("--candidate", type=Path, required=True)
    publish_parser.add_argument("--destination", type=Path, required=True)
    publish_parser.set_defaults(run=run_publish)
    locked_parser = commands.add_parser("locked-exec")
    locked_parser.add_argument("--owner-root", type=Path, required=True)
    locked_parser.add_argument("--lock-file", type=Path, required=True)
    locked_parser.add_argument("command", nargs=argparse.REMAINDER)
    locked_parser.set_defaults(run=run_locked_exec)
    verify_parser = commands.add_parser("verify-lock")
    verify_parser.add_argument("--owner-root", type=Path, required=True)
    verify_parser.add_argument("--lock-file", type=Path, required=True)
    verify_parser.add_argument("--descriptor", type=int, required=True)
    verify_parser.set_defaults(run=run_verify_lock)
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
