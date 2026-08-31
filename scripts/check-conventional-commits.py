#!/usr/bin/env python3
"""Validate h00ligan commit subjects against one release contract."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "revert",
    "style",
    "test",
)
HEADER = re.compile(
    rf"^(?:{'|'.join(TYPES)})(?:\([a-z0-9][a-z0-9._/-]*\))?!?: \S.*$"
)
MAX_HEADER_CHARS = 120
ZERO_SHA = "0" * 40


def validate(subject: str, *, allow_fixup: bool = False) -> str | None:
    subject = subject.strip()
    if allow_fixup and subject.startswith(("fixup! ", "squash! ")):
        subject = subject.split("! ", 1)[1]
    if not subject:
        return "subject is empty"
    if len(subject) > MAX_HEADER_CHARS:
        return f"subject is {len(subject)} characters; maximum is {MAX_HEADER_CHARS}"
    if not HEADER.fullmatch(subject):
        return (
            "expected <type>[optional scope][!]: <description>; allowed types: "
            + ", ".join(TYPES)
        )
    return None


def git_subjects(revision_range: str) -> list[str]:
    result = subprocess.run(
        ["git", "log", "--reverse", "--format=%s", revision_range],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [line for line in result.stdout.splitlines() if line]


def event_subjects(event_path: Path) -> tuple[str, list[str]]:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if "pull_request" in event:
        return "pull request title", [event["pull_request"]["title"]]

    before = event.get("before")
    after = event.get("after")
    if not after:
        raise ValueError("event contains neither pull_request nor after SHA")
    if not before or before == ZERO_SHA:
        parents = subprocess.run(
            ["git", "rev-list", "--parents", "-n", "1", after],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.split()
        revision_range = after if len(parents) == 1 else f"{parents[1]}..{after}"
    else:
        revision_range = f"{before}..{after}"
    return f"push range {revision_range}", git_subjects(revision_range)


def self_test() -> None:
    accepted = [
        "feat(cli): add ARM64 release archives",
        "fix!: remove obsolete store compatibility",
        "chore(main): release h00ligan 0.2.0",
        "docs(release/guide): explain checksums",
    ]
    rejected = [
        "historical non-conventional subject",
        "feat missing colon",
        "fix: ",
        "Feat(cli): uppercase types are not canonical",
    ]
    for subject in accepted:
        error = validate(subject)
        if error:
            raise AssertionError(f"accepted control rejected: {subject!r}: {error}")
    for subject in rejected:
        if validate(subject) is None:
            raise AssertionError(f"rejected control accepted: {subject!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--message-file", type=Path)
    source.add_argument("--range", dest="revision_range")
    source.add_argument("--github-event", type=Path)
    parser.add_argument("--allow-fixup", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("conventional-commits: self-test OK (accepted and rejected canaries fired)")
    if args.message_file:
        lines = args.message_file.read_text(encoding="utf-8").splitlines()
        subjects = lines[:1]
        population = str(args.message_file)
    elif args.revision_range:
        subjects = git_subjects(args.revision_range)
        population = f"range {args.revision_range}"
    elif args.github_event:
        population, subjects = event_subjects(args.github_event)
    elif args.self_test:
        return 0
    else:
        parser.error("choose an input source or --self-test")

    if not subjects:
        print(
            f"conventional-commits: ERROR: {population} contains zero subjects",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []
    for subject in subjects:
        if error := validate(subject, allow_fixup=args.allow_fixup):
            failures.append(f"{subject!r}: {error}")
    if failures:
        print(f"conventional-commits: FAIL ({population})", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"conventional-commits: OK ({len(subjects)} subject(s), {population})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
