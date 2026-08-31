#!/usr/bin/env python3
"""Reject mutable third-party GitHub Action references."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


USE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)(?:\s+#\s*(.*))?\s*$")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
CHECKED = re.compile(r"\bchecked 20\d{2}-\d{2}-\d{2}\b")
DIGEST = re.compile(r"docker://[^@]+@sha256:[0-9a-f]{64}")


def validate_use(reference: str, comment: str | None) -> str | None:
    if reference.startswith("./"):
        return None
    if reference.startswith("docker://"):
        if not DIGEST.fullmatch(reference):
            return "container action must use an immutable sha256 digest"
    else:
        action, separator, revision = reference.rpartition("@")
        if not separator or "/" not in action or not COMMIT_SHA.fullmatch(revision):
            return "third-party action must use a full 40-character commit SHA"
    if not comment or not CHECKED.search(comment):
        return "pin must record its upstream release and YYYY-MM-DD check date"
    return None


def self_test() -> None:
    accepted = [
        ("actions/checkout@" + "a" * 40, "v7.0.1 (checked 2026-08-12)"),
        ("./.github/workflows/local.yml", None),
        (
            "docker://example.test/tool@sha256:" + "b" * 64,
            "v2 (checked 2026-08-12)",
        ),
    ]
    rejected = [
        ("actions/checkout@v7", "checked 2026-08-12"),
        ("actions/checkout@" + "a" * 40, None),
        ("docker://example.test/tool:latest", "checked 2026-08-12"),
    ]
    for reference, comment in accepted:
        error = validate_use(reference, comment)
        if error:
            raise AssertionError(f"accepted canary rejected: {reference}: {error}")
    for reference, comment in rejected:
        if validate_use(reference, comment) is None:
            raise AssertionError(f"rejected canary accepted: {reference}")


def workflow_files(root: Path) -> list[Path]:
    workflow_root = root / ".github" / "workflows"
    return sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("action-pins: self-test OK (accepted and rejected canaries fired)")

    files = workflow_files(args.root)
    if not files:
        print("action-pins: ERROR: no workflow files found", file=sys.stderr)
        return 1

    population = 0
    failures: list[str] = []
    for path in files:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            match = USE.match(line)
            if not match:
                continue
            population += 1
            reference, comment = match.groups()
            if error := validate_use(reference, comment):
                relative = path.relative_to(args.root)
                failures.append(f"{relative}:{line_number}: {reference}: {error}")

    if population == 0:
        print(
            "action-pins: ERROR: zero `uses:` sites found; census is vacuous",
            file=sys.stderr,
        )
        return 1
    if failures:
        print("action-pins: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"action-pins: OK ({population} `uses:` site(s) "
        f"across {len(files)} workflow(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
