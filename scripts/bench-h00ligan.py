#!/usr/bin/env python3
"""Correctness-coupled installed-product performance battery for h00ligan.

The benchmark intentionally drives the distribution-shaped executable through
its public CLI, MCP, and WATCH boundaries.  It never imports h00ligan internals
and always uses a fresh explicit data directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import queue
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "h00/h00ligan-performance/v4"
DEFAULT_ABSOLUTE_TOLERANCE_MS = 5.0
MAX_ERROR_TEXT = 4_000
POLL_SECONDS = 0.025
RUST_PROVIDER_ID = "h00-rust-analyzer-scip"
GO_PROVIDER_ID = "h00-gopls-scip"
PYTHON_PROVIDER_ID = "h00-pyrefly-scip"
TYPESCRIPT_PROVIDER_ID = "h00-typescript-native-scip"
LANGUAGE_PROVIDER_IDS = {
    "rust": RUST_PROVIDER_ID,
    "go": GO_PROVIDER_ID,
    "python": PYTHON_PROVIDER_ID,
    "typescript": TYPESCRIPT_PROVIDER_ID,
}
EMBEDDED_PROVIDER_EXECUTABLE_BY_LANGUAGE = {
    "go": "h00-go-semantic-provider",
    "python": "h00-pyrefly-semantic-provider",
    "typescript": "h00-typescript-semantic-provider",
}
EMBEDDED_PROVIDER_EXECUTABLES = set(
    EMBEDDED_PROVIDER_EXECUTABLE_BY_LANGUAGE.values()
)


class HarnessError(RuntimeError):
    """A product, authority, lifecycle, or benchmark-contract failure."""


def bounded(text: str, limit: int = MAX_ERROR_TEXT) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256_bytes(payload)


def percentile_nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise HarnessError("cannot summarize an empty sample population")
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def summarize(values: Iterable[float]) -> dict[str, Any]:
    samples = [float(value) for value in values]
    if not samples:
        raise HarnessError("cannot summarize an empty sample population")
    return {
        "count": len(samples),
        "min_ms": round(min(samples), 3),
        "median_ms": round(statistics.median(samples), 3),
        "mean_ms": round(statistics.fmean(samples), 3),
        "p95_ms": round(percentile_nearest_rank(samples, 0.95), 3),
        "max_ms": round(max(samples), 3),
        "samples_ms": [round(value, 3) for value in samples],
    }


def run_process(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=environment,
    )
    elapsed_ms = (time.perf_counter() - started) * 1_000
    return completed, elapsed_ms


def run_json(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: float = 120,
) -> tuple[dict[str, Any], float, str]:
    completed, elapsed_ms = run_process(
        command, environment=environment, timeout=timeout
    )
    if completed.returncode != 0:
        raise HarnessError(
            f"command exited {completed.returncode}: {command!r}\n"
            f"stderr={bounded(completed.stderr)!r}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise HarnessError(
            f"command did not emit one JSON value: {command!r}: {error}; "
            f"stdout={bounded(completed.stdout)!r}"
        ) from error
    if not isinstance(payload, dict):
        raise HarnessError(f"command emitted a non-object JSON value: {command!r}")
    return payload, elapsed_ms, completed.stderr


def benchmark_process_startup(
    binary: Path,
    *,
    environment: dict[str, str],
    repetitions: int,
) -> tuple[str, dict[str, Any]]:
    command = [str(binary), "--version"]
    warmup, _ = run_process(command, environment=environment, timeout=10)
    if warmup.returncode != 0 or not warmup.stdout.startswith("h00ligan "):
        raise HarnessError(
            "h00ligan startup positive control failed: "
            f"exit={warmup.returncode} stdout={bounded(warmup.stdout)!r} "
            f"stderr={bounded(warmup.stderr)!r}"
        )
    samples: list[float] = []
    for _ in range(repetitions):
        completed, elapsed_ms = run_process(
            command,
            environment=environment,
            timeout=10,
        )
        if (
            completed.returncode != warmup.returncode
            or completed.stdout != warmup.stdout
            or completed.stderr != warmup.stderr
        ):
            raise HarnessError("h00ligan startup output changed across one artifact")
        samples.append(elapsed_ms)
    return warmup.stdout.strip(), summarize(samples)


def tool_version(command: list[str], environment: dict[str, str]) -> str:
    try:
        completed, _ = run_process(command, environment=environment, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"unavailable:{type(error).__name__}"
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return bounded(text[0] if text else f"exit:{completed.returncode}", 240)


def fixture_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix().encode()
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        file_count += 1
        byte_count += len(payload)
    if file_count == 0:
        raise HarnessError("fixture digest population is empty")
    return digest.hexdigest(), file_count, byte_count


@dataclass(frozen=True)
class LanguageFixture:
    language: str
    provider_id: str
    watch_path: Path
    marker_template: str
    query_symbol: str
    query_file: str
    source_files: int

    def marker(self, revision: int) -> str:
        return self.marker_template.format(revision=revision)


@dataclass(frozen=True)
class Fixture:
    root: Path
    digest: str
    file_count: int
    byte_count: int
    languages: tuple[LanguageFixture, ...]

    def language(self, language: str) -> LanguageFixture:
        matches = [item for item in self.languages if item.language == language]
        if len(matches) != 1:
            raise HarnessError(
                f"fixture has {len(matches)} entries for language {language!r}"
            )
        return matches[0]


def build_fixture(
    root: Path,
    *,
    rust_files: int,
    go_files: int,
    python_files: int,
    typescript_files: int,
) -> Fixture:
    populations = {
        "rust": rust_files,
        "go": go_files,
        "python": python_files,
        "typescript": typescript_files,
    }
    if any(count < 1 for count in populations.values()):
        raise HarnessError(
            "four-language fixture requires positive source-file populations"
        )
    (root / ".git").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "Cargo.toml").write_text(
        "[package]\n"
        'name = "h00ligan-perf-fixture"\n'
        'version = "0.0.0"\n'
        'edition = "2024"\n\n'
        '[workspace]\n',
        encoding="utf-8",
    )
    modules = "".join(f"pub mod r{index:03d};\n" for index in range(rust_files))
    (root / "src/lib.rs").write_text(
        modules
        + "\npub fn rust_entry() -> usize { r000::rust_caller_000() }\n",
        encoding="utf-8",
    )
    for index in range(rust_files):
        suffix = f"{index:03d}"
        target_value = "1000 + 0" if index == 0 else str(index + 1)
        (root / f"src/r{suffix}.rs").write_text(
            f"pub fn rust_target_{suffix}() -> usize {{ {target_value} }}\n"
            + f"pub fn rust_caller_{suffix}() -> usize {{ rust_target_{suffix}() }}\n",
            encoding="utf-8",
        )

    (root / "go.mod").write_text(
        "module example.com/h00ligan/perf\n\ngo 1.23\n", encoding="utf-8"
    )
    for index in range(go_files):
        suffix = f"{index:03d}"
        target_value = "1000 + 0" if index == 0 else str(index + 1)
        (root / f"g{suffix}.go").write_text(
            "package perfbench\n\n"
            + f"func GoTarget{suffix}() int {{ return {target_value} }}\n"
            + f"func GoCaller{suffix}() int {{ return GoTarget{suffix}() }}\n",
            encoding="utf-8",
        )
    (root / "entry.go").write_text(
        "package perfbench\n\nfunc GoEntry() int { return GoCaller000() }\n",
        encoding="utf-8",
    )

    python_root = root / "python/fixture"
    python_root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[project]\n"
        'name = "h00ligan-perf-fixture"\n'
        'version = "0.0.0"\n\n'
        "[tool.pyrefly]\n"
        'project_includes = ["python"]\n',
        encoding="utf-8",
    )
    (python_root / "__init__.py").write_text("", encoding="utf-8")
    for index in range(python_files):
        suffix = f"{index:03d}"
        target_value = "1000 + 0" if index == 0 else str(index + 1)
        (python_root / f"p{suffix}.py").write_text(
            f"def python_target_{suffix}() -> int:\n    return {target_value}\n\n"
            + f"def python_caller_{suffix}() -> int:\n    return python_target_{suffix}()\n",
            encoding="utf-8",
        )

    typescript_root = root / "typescript"
    typescript_root.mkdir()
    (root / "package.json").write_text(
        '{"name":"h00ligan-perf-fixture","private":true,"type":"module"}\n',
        encoding="utf-8",
    )
    (root / "tsconfig.json").write_text(
        '{"compilerOptions":{"target":"ES2022","module":"NodeNext",'
        '"moduleResolution":"NodeNext","strict":true},'
        '"include":["typescript/**/*.ts"]}\n',
        encoding="utf-8",
    )
    for index in range(typescript_files):
        suffix = f"{index:03d}"
        target_value = "1000 + 0" if index == 0 else str(index + 1)
        (typescript_root / f"t{suffix}.ts").write_text(
            f"export function typescript_target_{suffix}(): number {{ return {target_value}; }}\n"
            + f"export function typescript_caller_{suffix}(): number {{ return typescript_target_{suffix}(); }}\n",
            encoding="utf-8",
        )

    digest, file_count, byte_count = fixture_digest(root)
    return Fixture(
        root=root,
        digest=digest,
        file_count=file_count,
        byte_count=byte_count,
        languages=(
            LanguageFixture(
                language="rust",
                provider_id=RUST_PROVIDER_ID,
                watch_path=root / "src/r000.rs",
                marker_template="1000 + {revision}",
                query_symbol="rust_target_000",
                query_file="src/r000.rs",
                source_files=rust_files,
            ),
            LanguageFixture(
                language="go",
                provider_id=GO_PROVIDER_ID,
                watch_path=root / "g000.go",
                marker_template="1000 + {revision}",
                query_symbol="GoTarget000",
                query_file="g000.go",
                source_files=go_files,
            ),
            LanguageFixture(
                language="python",
                provider_id=PYTHON_PROVIDER_ID,
                watch_path=python_root / "p000.py",
                marker_template="1000 + {revision}",
                query_symbol="python_target_000",
                query_file="python/fixture/p000.py",
                source_files=python_files,
            ),
            LanguageFixture(
                language="typescript",
                provider_id=TYPESCRIPT_PROVIDER_ID,
                watch_path=typescript_root / "t000.ts",
                marker_template="1000 + {revision}",
                query_symbol="typescript_target_000",
                query_file="typescript/t000.ts",
                source_files=typescript_files,
            ),
        ),
    )


def replace_marker(path: Path, original: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    if text.count(original) != 1:
        raise HarnessError(f"fixture marker population is not exactly one: {path.name}")
    path.write_text(text.replace(original, replacement), encoding="utf-8")


def status_command(binary: Path, root: Path, data_dir: Path) -> list[str]:
    return [
        str(binary),
        "status",
        "--root",
        str(root),
        "--data-dir",
        str(data_dir),
        "--format",
        "json",
    ]


def calls_command(
    binary: Path,
    root: Path,
    data_dir: Path,
    *,
    symbol: str,
    file: str,
) -> list[str]:
    return [
        str(binary),
        "calls",
        symbol,
        "--file",
        file,
        "--root",
        str(root),
        "--data-dir",
        str(data_dir),
        "--filter",
        "all",
        "--limit",
        "100",
        "--format",
        "json",
    ]


def validate_complete_status(payload: dict[str, Any]) -> str:
    if payload.get("publication_state") != "published":
        raise HarnessError(f"status is not published: {payload!r}")
    if payload.get("freshness") != "fresh":
        raise HarnessError(f"status is not source-fresh: {payload!r}")
    generation = payload.get("generation_id")
    if not isinstance(generation, str) or not generation:
        raise HarnessError("status lacks a nonempty generation identity")
    calls = payload.get("capabilities", {}).get("calls", {})
    if calls.get("status") != "complete":
        raise HarnessError(f"fixture Calls authority is not Complete: {calls!r}")
    languages = {
        item.get("language_id"): item
        for item in calls.get("languages", [])
        if isinstance(item, dict)
    }
    for language, provider in LANGUAGE_PROVIDER_IDS.items():
        evidence = languages.get(language)
        if not evidence or evidence.get("status") != "complete":
            raise HarnessError(f"{language} Calls authority is not Complete: {calls!r}")
        if evidence.get("provider_id") != provider:
            raise HarnessError(
                f"{language} provider mismatch: {evidence.get('provider_id')!r}"
            )
    return generation


def validate_calls(payload: dict[str, Any], *, language: str) -> str:
    authority = payload.get("authority", {})
    if authority.get("status") != "complete":
        raise HarnessError(f"{language} query lacks Complete authority: {authority!r}")
    scopes = authority.get("scopes", [])
    if not any(
        isinstance(scope, dict) and scope.get("language_id") == language
        for scope in scopes
    ):
        raise HarnessError(f"{language} query lacks a matching authority scope")
    fingerprints = authority.get("input_fingerprints")
    if (
        not isinstance(fingerprints, list)
        or len(fingerprints) != 1
        or not isinstance(fingerprints[0], str)
        or not fingerprints[0]
    ):
        raise HarnessError(f"{language} query has invalid fingerprints: {fingerprints!r}")
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise HarnessError(f"{language} positive caller population is empty")
    return fingerprints[0]


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def wait_for_terminal_count(
    path: Path,
    process: subprocess.Popen[str],
    minimum: int,
    *,
    timeout_seconds: float = 120,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        events = read_events(path)
        terminals = [
            event for event in events if event.get("event") == "reconciliation_terminal"
        ]
        if len(terminals) >= minimum:
            return events
        if process.poll() is not None:
            raise HarnessError(
                f"WATCH exited early with {process.returncode}: {events!r}"
            )
        time.sleep(POLL_SECONDS)
    raise HarnessError(f"WATCH emitted fewer than {minimum} terminal receipts")


def wait_for_generation(
    binary: Path,
    root: Path,
    data_dir: Path,
    process: subprocess.Popen[str],
    previous: str,
    *,
    environment: dict[str, str],
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HarnessError(f"WATCH exited early with {process.returncode}")
        status, _, _ = run_json(
            status_command(binary, root, data_dir),
            environment=environment,
            timeout=30,
        )
        generation = status.get("generation_id")
        if isinstance(generation, str) and generation and generation != previous:
            validate_complete_status(status)
            return status, (time.perf_counter() - started) * 1_000
        time.sleep(POLL_SECONDS)
    raise HarnessError(f"WATCH generation did not advance from {previous}")


def wait_for_generation_terminal(
    path: Path,
    process: subprocess.Popen[str],
    generation: str,
) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for event in read_events(path):
            if (
                event.get("event") == "reconciliation_terminal"
                and event.get("generation") == generation
                and event.get("state") == "succeeded"
            ):
                return event
        if process.poll() is not None:
            raise HarnessError(f"WATCH exited before receipting {generation}")
        time.sleep(POLL_SECONDS)
    raise HarnessError(f"WATCH did not emit a terminal receipt for {generation}")


def summarize_work_items(values: Iterable[int]) -> dict[str, Any]:
    samples = list(values)
    if not samples:
        raise HarnessError("cannot summarize an empty work-item population")
    return {
        "count": len(samples),
        "min": min(samples),
        "median": statistics.median(samples),
        "mean": round(statistics.fmean(samples), 3),
        "p95": percentile_nearest_rank([float(value) for value in samples], 0.95),
        "max": max(samples),
        "samples": samples,
    }


def timing_population(
    records: list[dict[str, Any]],
    *,
    field: str = "phase_timings",
    require_work: bool = False,
) -> dict[str, dict[str, Any]]:
    timings: dict[str, dict[str, Any]] = {}
    for record_index, record in enumerate(records):
        rows = record.get(field)
        if not isinstance(rows, list) or not rows:
            raise HarnessError(
                f"timing record {record_index} lacks a non-empty {field!r} population"
            )
        for timing in rows:
            if not isinstance(timing, dict):
                raise HarnessError(f"{field} contains a non-object timing row")
            label = timing.get("label")
            duration = timing.get("duration_ms")
            aggregation = timing.get("aggregation")
            if not isinstance(label, str) or not label:
                raise HarnessError(f"{field} contains a timing row without a label")
            if (
                not isinstance(duration, (int, float))
                or isinstance(duration, bool)
                or duration < 0
            ):
                raise HarnessError(f"timing {label!r} lacks a valid duration")
            if aggregation not in ("exclusive", "concurrent_span"):
                raise HarnessError(
                    f"timing {label!r} lacks a valid aggregation contract"
                )
            bucket = timings.setdefault(
                label,
                {
                    "aggregation": aggregation,
                    "samples": [],
                    "work_items": [],
                    "work_unit": None,
                },
            )
            if bucket["aggregation"] != aggregation:
                raise HarnessError(
                    f"timing {label!r} changed aggregation within one population"
                )
            bucket["samples"].append(float(duration))
            if require_work:
                work_items = timing.get("work_items")
                work_unit = timing.get("work_unit")
                if (
                    not isinstance(work_items, int)
                    or isinstance(work_items, bool)
                    or work_items < 0
                    or not isinstance(work_unit, str)
                    or not work_unit
                ):
                    raise HarnessError(
                        f"publication timing {label!r} lacks valid work evidence"
                    )
                if bucket["work_unit"] not in (None, work_unit):
                    raise HarnessError(
                        f"publication timing {label!r} changed work unit within one population"
                    )
                bucket["work_unit"] = work_unit
                bucket["work_items"].append(work_items)

    population: dict[str, dict[str, Any]] = {}
    for label, bucket in sorted(timings.items()):
        summary = {
            "aggregation": bucket["aggregation"],
            **summarize(bucket["samples"]),
        }
        if require_work:
            summary["work_unit"] = bucket["work_unit"]
            summary["work_items"] = summarize_work_items(bucket["work_items"])
        population[label] = summary
    return population


def stop_process_group(process: subprocess.Popen[str], *, graceful: bool) -> int:
    if process.poll() is not None:
        return int(process.returncode)
    try:
        if graceful:
            process.send_signal(signal.SIGTERM)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        return process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait(timeout=10)


def process_population(executables: set[str]) -> tuple[int, list[dict[str, Any]]]:
    completed = subprocess.run(
        ["ps", "-ww", "-axo", "pid=,ppid=,pgid=,lstart=,args="],
        check=True,
        capture_output=True,
        text=True,
    )
    population = 0
    selected: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=8)
        if len(fields) != 9:
            continue
        population += 1
        command = fields[8]
        try:
            executable = __import__("shlex").split(command)[0]
        except (ValueError, IndexError):
            continue
        if os.path.realpath(executable) not in executables:
            continue
        selected.append(
            {
                "pid": int(fields[0]),
                "parent_pid": int(fields[1]),
                "process_group": int(fields[2]),
                "started": " ".join(fields[3:8]),
                "command": command,
            }
        )
    selected.sort(
        key=lambda item: (
            item["pid"],
            item["parent_pid"],
            item["process_group"],
            item["started"],
            item["command"],
        )
    )
    if population == 0:
        raise HarnessError("process census known-positive population is empty")
    return population, selected


def embedded_provider_paths(root: Path) -> set[str]:
    """Return the exact materialized provider population under one scratch root."""
    return {
        os.path.realpath(path)
        for executable in EMBEDDED_PROVIDER_EXECUTABLES
        for path in root.rglob(executable)
        if path.is_file() and os.access(path, os.X_OK)
    }


def process_identity(value: dict[str, Any]) -> tuple[Any, ...]:
    return (
        value["pid"],
        value["parent_pid"],
        value["process_group"],
        value["started"],
        value["command"],
    )


def new_processes(
    baseline: list[dict[str, Any]], current: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    known = {process_identity(value) for value in baseline}
    return [value for value in current if process_identity(value) not in known]


def direct_provider_identity(
    language: str,
    *,
    binary: Path,
    materialized_providers: set[str],
    watch_pid: int,
    live_processes: list[dict[str, Any]],
) -> tuple[Any, ...]:
    if language == "rust":
        executable = os.path.realpath(binary)
    else:
        executable_name = EMBEDDED_PROVIDER_EXECUTABLE_BY_LANGUAGE[language]
        matches = [
            path for path in materialized_providers if Path(path).name == executable_name
        ]
        if len(matches) != 1:
            raise HarnessError(
                f"{language} has {len(matches)} materialized provider executables"
            )
        executable = matches[0]
    matches = []
    for process in live_processes:
        try:
            process_executable = os.path.realpath(
                __import__("shlex").split(process["command"])[0]
            )
        except (ValueError, IndexError):
            continue
        if process["parent_pid"] == watch_pid and process_executable == executable:
            matches.append(process)
    if len(matches) != 1:
        raise HarnessError(
            f"{language} has {len(matches)} live direct provider children: "
            f"{live_processes!r}"
        )
    return process_identity(matches[0])


def wait_for_no_new_processes(
    executables: set[str],
    baseline: list[dict[str, Any]],
    *,
    timeout_seconds: float = 5.0,
) -> tuple[int, list[dict[str, Any]]]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        population, current = process_population(executables)
        leaked = new_processes(baseline, current)
        if not leaked or time.monotonic() >= deadline:
            return population, leaked
        time.sleep(POLL_SECONDS)


class McpSession:
    def __init__(
        self,
        binary: Path,
        root: Path,
        data_dir: Path,
        environment: dict[str, str],
    ) -> None:
        self.process = subprocess.Popen(
            [
                str(binary),
                "--root",
                str(root),
                "--data-dir",
                str(data_dir),
                "mcp-serve",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=True,
            env=environment,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise HarnessError("MCP stdio pipes were not created")
        self.next_id = 1
        self.stdout: queue.Queue[str | None] = queue.Queue()
        self.stderr: list[str] = []
        assert self.process.stdout is not None
        assert self.process.stderr is not None
        self.stdout_thread = threading.Thread(
            target=self._read_stdout,
            daemon=True,
        )
        self.stderr_thread = threading.Thread(
            target=lambda: self.stderr.extend(self.process.stderr.readlines()), daemon=True
        )
        self.stdout_thread.start()
        self.stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            for line in self.process.stdout:
                self.stdout.put(line)
        finally:
            self.stdout.put(None)

    def request(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], float]:
        request_id = self.next_id
        self.next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        started = time.perf_counter()
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 30.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError(f"MCP did not respond to {method} within 30 seconds")
            try:
                line = self.stdout.get(timeout=remaining)
            except queue.Empty as error:
                raise HarnessError(
                    f"MCP did not respond to {method} within 30 seconds"
                ) from error
            if line is None:
                raise HarnessError(
                    f"MCP closed before responding: {bounded(''.join(self.stderr))}"
                )
            response = json.loads(line)
            if response.get("id") == request_id:
                return response, (time.perf_counter() - started) * 1_000

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], float]:
        response, elapsed_ms = self.request(
            "tools/call", {"name": name, "arguments": arguments}
        )
        result = response.get("result")
        if not isinstance(result, dict) or result.get("isError") is True:
            raise HarnessError(f"MCP {name} failed: {response!r}")
        payload = result.get("structuredContent")
        if payload is None:
            try:
                payload = json.loads(result["content"][0]["text"])
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
                raise HarnessError(f"MCP {name} lacks a structured result") from error
        if not isinstance(payload, dict):
            raise HarnessError(f"MCP {name} result is not an object")
        return payload, elapsed_ms

    def initialize(self) -> None:
        response, _ = self.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "h00ligan-performance", "version": "1"},
            },
        )
        if response.get("result", {}).get("serverInfo", {}).get("name") != "h00ligan":
            raise HarnessError(f"unexpected MCP initialization result: {response!r}")

    def finish(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            return_code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            return_code = stop_process_group(self.process, graceful=False)
        self.stdout_thread.join(timeout=2)
        self.stderr_thread.join(timeout=2)
        if return_code != 0:
            raise HarnessError(
                f"MCP exited {return_code}: {bounded(''.join(self.stderr))}"
            )

    def abort(self) -> None:
        if self.process.poll() is None:
            stop_process_group(self.process, graceful=False)
        self.stdout_thread.join(timeout=2)
        self.stderr_thread.join(timeout=2)


def metric_at(payload: dict[str, Any], path: str) -> dict[str, Any]:
    value: Any = payload
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            raise HarnessError(f"baseline lacks performance metric {path}")
        value = value[segment]
    if not isinstance(value, dict):
        raise HarnessError(f"performance metric {path} is not an object")
    return value


COMPARISON_METRICS = (
    "metrics.process_startup",
    "metrics.cold_index",
    "metrics.watch.restart_reuse",
    "metrics.cli.status",
    "metrics.cli.overview",
    "metrics.mcp.status",
    "metrics.mcp.overview",
    *(
        f"metrics.watch.{language}_{operation}"
        for language in LANGUAGE_PROVIDER_IDS
        for operation in ("change", "restore")
    ),
    *(
        f"metrics.{surface}.{verb}_{language}"
        for surface in ("cli", "mcp")
        for language in LANGUAGE_PROVIDER_IDS
        for verb in ("find", "calls")
    ),
)


def compare_report(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    relative_tolerance: float,
    absolute_tolerance_ms: float,
) -> dict[str, Any]:
    if baseline.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError("baseline schema does not match the current harness")
    if baseline.get("mode") != current.get("mode"):
        raise HarnessError("baseline mode does not match the current mode")
    if baseline.get("fixture") != current.get("fixture"):
        raise HarnessError("baseline fixture identity does not match")
    regressions: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    for path in COMPARISON_METRICS:
        current_metric = metric_at(current, path)
        baseline_metric = metric_at(baseline, path)
        for statistic in ("median_ms", "p95_ms"):
            measured = float(current_metric[statistic])
            reference = float(baseline_metric[statistic])
            ceiling = max(
                reference * (1.0 + relative_tolerance),
                reference + absolute_tolerance_ms,
            )
            item = {
                "metric": path,
                "statistic": statistic,
                "baseline_ms": round(reference, 3),
                "measured_ms": round(measured, 3),
                "ceiling_ms": round(ceiling, 3),
                "passed": measured <= ceiling,
            }
            comparisons.append(item)
            if not item["passed"]:
                regressions.append(item)
    return {
        "relative_tolerance": relative_tolerance,
        "absolute_tolerance_ms": absolute_tolerance_ms,
        "comparisons": comparisons,
        "regressions": regressions,
        "passed": not regressions,
    }


def render_summary(report: dict[str, Any], output: Path | None) -> str:
    metrics = report["metrics"]
    watch = metrics["watch"]
    verdict = "PASS"
    comparison = report.get("comparison")
    if isinstance(comparison, dict) and not comparison.get("passed", False):
        verdict = "REGRESSION"

    def median(metric: dict[str, Any]) -> str:
        return f"{float(metric['median_ms']):.3f} ms"

    cli = ", ".join(
        f"{name}={median(metric)}" for name, metric in metrics["cli"].items()
    )
    mcp = ", ".join(
        f"{name}={median(metric)}" for name, metric in metrics["mcp"].items()
    )
    correctness = report["correctness"]
    lines = [
        f"h00ligan performance: {verdict} ({report['mode']})",
        f"  artifact: {report['artifact']['sha256'][:16]}…",
        f"  process startup: median={median(metrics['process_startup'])}, "
        f"p95={float(metrics['process_startup']['p95_ms']):.3f} ms",
        f"  cold index: median={median(metrics['cold_index'])}, "
        f"p95={float(metrics['cold_index']['p95_ms']):.3f} ms",
        "  WATCH: "
        f"restart={median(watch['restart_reuse'])}, "
        + ", ".join(
            f"{language} change/restore="
            f"{median(watch[f'{language}_change'])}/"
            f"{median(watch[f'{language}_restore'])}"
            for language in LANGUAGE_PROVIDER_IDS
        ),
        f"  CLI medians: {cli}",
        f"  MCP medians: {mcp}",
        "  correctness: Calls=Complete(rust,go,python,typescript), CLI/MCP=exact, "
        f"WATCH receipts={correctness['watch_operations_terminal']}, "
        f"new processes={correctness['new_product_processes']}",
    ]
    if isinstance(comparison, dict):
        lines.append(f"  regressions: {len(comparison['regressions'])}")
    if output is not None:
        lines.append(f"  report: {output}")
    return "\n".join(lines)


def benchmark_queries(
    binary: Path,
    fixture: Fixture,
    data_dir: Path,
    *,
    environment: dict[str, str],
    repetitions: int,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], bool]:
    root = fixture.root
    cli_commands = {
        "status": status_command(binary, root, data_dir),
        "overview": [
            str(binary),
            "overview",
            "--root",
            str(root),
            "--data-dir",
            str(data_dir),
            "--format",
            "json",
        ],
    }
    cli_arguments = {
        "status": {},
        "overview": {},
    }
    mcp_names = {
        "status": "status",
        "overview": "overview",
    }
    for target in fixture.languages:
        find_name = f"find_{target.language}"
        calls_name = f"calls_{target.language}"
        cli_commands[find_name] = [
            str(binary),
            "find",
            target.query_symbol,
            "--name",
            "--definitions-only",
            "--limit",
            "50",
            "--root",
            str(root),
            "--data-dir",
            str(data_dir),
            "--format",
            "json",
        ]
        cli_commands[calls_name] = calls_command(
            binary,
            root,
            data_dir,
            symbol=target.query_symbol,
            file=target.query_file,
        )
        cli_arguments[find_name] = {
            "query": target.query_symbol,
            "mode": "name",
            "definitions_only": True,
            "limit": 50,
        }
        cli_arguments[calls_name] = {
            "symbol": target.query_symbol,
            "file": target.query_file,
            "filter": "all",
            "limit": 100,
        }
        mcp_names[find_name] = "find"
        mcp_names[calls_name] = "calls"

    cli_samples: dict[str, list[float]] = {name: [] for name in cli_commands}
    cli_payloads: dict[str, dict[str, Any]] = {}
    for name, command in cli_commands.items():
        warmup, _, _ = run_json(command, environment=environment)
        cli_payloads[name] = warmup
        for _ in range(repetitions):
            payload, elapsed_ms, _ = run_json(command, environment=environment)
            if canonical_sha256(payload) != canonical_sha256(warmup):
                raise HarnessError(f"CLI {name} changed across an immutable query population")
            cli_samples[name].append(elapsed_ms)

    validate_complete_status(cli_payloads["status"])
    for target in fixture.languages:
        validate_calls(
            cli_payloads[f"calls_{target.language}"], language=target.language
        )
        if not cli_payloads[f"find_{target.language}"].get("items"):
            raise HarnessError(
                f"CLI {target.language} find positive control is empty"
            )

    session = McpSession(binary, root, data_dir, environment)
    mcp_samples: dict[str, list[float]] = {name: [] for name in cli_commands}
    parity = True
    try:
        session.initialize()
        for name in cli_commands:
            warmup, _ = session.call(mcp_names[name], cli_arguments[name])
            parity = parity and canonical_sha256(warmup) == canonical_sha256(
                cli_payloads[name]
            )
            for _ in range(repetitions):
                payload, elapsed_ms = session.call(
                    mcp_names[name], cli_arguments[name]
                )
                if canonical_sha256(payload) != canonical_sha256(warmup):
                    raise HarnessError(
                        f"MCP {name} changed across an immutable query population"
                    )
                mcp_samples[name].append(elapsed_ms)
        session.finish()
    except BaseException:
        session.abort()
        raise
    if not parity:
        raise HarnessError("CLI JSON and MCP structuredContent diverged")
    return (
        {name: summarize(values) for name, values in cli_samples.items()},
        {name: summarize(values) for name, values in mcp_samples.items()},
        parity,
    )


def run_battery(args: argparse.Namespace) -> dict[str, Any]:
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise HarnessError("--binary must name an executable regular file")
    settings = {
        "smoke": {
            "rust_files": 8,
            "go_files": 16,
            "python_files": 8,
            "typescript_files": 8,
            "cold_runs": 1,
            "cycles": 1,
            "queries": 5,
        },
        "full": {
            "rust_files": 32,
            "go_files": 64,
            "python_files": 32,
            "typescript_files": 32,
            "cold_runs": 3,
            "cycles": 3,
            "queries": 25,
        },
    }[args.mode]
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "RUST_BACKTRACE": "0",
        }
    )

    executables = {os.path.realpath(binary)}
    process_population_before, processes_before = process_population(executables)

    scratch = Path(tempfile.mkdtemp(prefix="h00ligan-performance."))
    watch_process: subprocess.Popen[str] | None = None
    stdout_file: Any = None
    stderr_file: Any = None
    fixture: Fixture | None = None
    report: dict[str, Any] | None = None
    failure: BaseException | None = None
    cleanup_failures: list[str] = []
    process_population_after: int | None = None
    leaked: list[dict[str, Any]] = []
    try:
        fixture = build_fixture(
            scratch / "main/repo",
            rust_files=settings["rust_files"],
            go_files=settings["go_files"],
            python_files=settings["python_files"],
            typescript_files=settings["typescript_files"],
        )
        original_sources = {
            target.language: target.watch_path.read_bytes()
            for target in fixture.languages
        }
        data_dir = scratch / "main/data"
        data_dir.mkdir(parents=True)

        version, process_startup = benchmark_process_startup(
            binary,
            environment=environment,
            repetitions=settings["queries"],
        )

        cold_samples: list[float] = []
        cold_results: list[dict[str, Any]] = []
        for run in range(settings["cold_runs"]):
            if run == 0:
                cold_fixture = fixture
                cold_data = data_dir
            else:
                cold_fixture = build_fixture(
                    scratch / f"cold-{run}/repo",
                    rust_files=settings["rust_files"],
                    go_files=settings["go_files"],
                    python_files=settings["python_files"],
                    typescript_files=settings["typescript_files"],
                )
                if cold_fixture.digest != fixture.digest:
                    raise HarnessError("generated fixture identity is nondeterministic")
                cold_data = scratch / f"cold-{run}/data"
                cold_data.mkdir(parents=True)
            result, elapsed_ms, _ = run_json(
                [
                    str(binary),
                    "index",
                    "--root",
                    str(cold_fixture.root),
                    "--data-dir",
                    str(cold_data),
                    "--scip",
                    "--require-complete-calls",
                    "--profile",
                    "--format",
                    "json",
                ],
                environment=environment,
                timeout=240,
            )
            if result.get("reused_generation") is not False:
                raise HarnessError("cold index unexpectedly reused a generation")
            status, _, _ = run_json(
                status_command(binary, cold_fixture.root, cold_data),
                environment=environment,
            )
            validate_complete_status(status)
            cold_samples.append(elapsed_ms)
            cold_results.append(result)

        def baseline_calls(language: str) -> dict[str, Any]:
            target = fixture.language(language)
            payload, _, _ = run_json(
                calls_command(
                    binary,
                    fixture.root,
                    data_dir,
                    symbol=target.query_symbol,
                    file=target.query_file,
                ),
                environment=environment,
            )
            return payload

        baseline_rust = baseline_calls("rust")
        baseline_go = baseline_calls("go")
        baseline_python = baseline_calls("python")
        baseline_typescript = baseline_calls("typescript")
        fingerprints = {
            "rust": validate_calls(baseline_rust, language="rust"),
            "go": validate_calls(baseline_go, language="go"),
            "python": validate_calls(baseline_python, language="python"),
            "typescript": validate_calls(baseline_typescript, language="typescript"),
        }

        watch_stdout = scratch / "watch-events.jsonl"
        watch_stderr = scratch / "watch-profile.stderr"
        stdout_file = watch_stdout.open("w", encoding="utf-8")
        stderr_file = watch_stderr.open("w", encoding="utf-8")
        started = time.perf_counter()
        watch_process = subprocess.Popen(
            [
                str(binary),
                "watch",
                "--root",
                str(fixture.root),
                "--data-dir",
                str(data_dir),
                "--scip",
                "--require-complete-calls",
                "--format",
                "json",
                "--profile",
                "--debounce-ms",
                "25",
                "--publication-probe-ms",
                "100",
                "--reconcile-secs",
                "3600",
            ],
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            start_new_session=True,
            env=environment,
        )
        events = wait_for_terminal_count(watch_stdout, watch_process, 1)
        restart_ms = (time.perf_counter() - started) * 1_000
        initial_terminal = [
            event for event in events if event.get("event") == "reconciliation_terminal"
        ][-1]
        if (
            initial_terminal.get("state") != "succeeded"
            or initial_terminal.get("reused_generation") is not True
        ):
            raise HarnessError(
                f"WATCH restart did not exactly reuse the certified generation: {initial_terminal!r}"
            )
        materialized_providers = embedded_provider_paths(data_dir)
        materialized_names = {Path(path).name for path in materialized_providers}
        if (
            materialized_names != EMBEDDED_PROVIDER_EXECUTABLES
            or len(materialized_providers) != len(EMBEDDED_PROVIDER_EXECUTABLES)
        ):
            raise HarnessError(
                "WATCH did not materialize exactly one helper for every embedded "
                f"provider: {sorted(materialized_providers)!r}"
            )
        executables.update(materialized_providers)
        _, live_product_processes = process_population(executables)
        if (
            watch_process.pid not in {item["pid"] for item in live_product_processes}
            or len(live_product_processes) < 2
        ):
            raise HarnessError(
                "product-process census failed its live WATCH/provider known-positive: "
                f"{live_product_processes!r}"
            )
        current_status, _, _ = run_json(
            status_command(binary, fixture.root, data_dir), environment=environment
        )
        current_generation = validate_complete_status(current_status)

        visible_samples: dict[str, list[float]] = {
            f"{target.language}_{operation}": []
            for target in fixture.languages
            for operation in ("change", "restore")
        }
        terminal_records: dict[str, list[dict[str, Any]]] = {
            name: [] for name in visible_samples
        }
        retained_provider_identities: dict[str, tuple[Any, ...]] = {}
        for cycle in range(settings["cycles"]):
            for target in fixture.languages:
                change_metric = f"{target.language}_change"
                restore_metric = f"{target.language}_restore"
                replace_marker(
                    target.watch_path,
                    target.marker(0),
                    target.marker(cycle + 1),
                )
                changed_status, elapsed_ms = wait_for_generation(
                    binary,
                    fixture.root,
                    data_dir,
                    watch_process,
                    current_generation,
                    environment=environment,
                )
                current_generation = validate_complete_status(changed_status)
                terminal = wait_for_generation_terminal(
                    watch_stdout, watch_process, current_generation
                )
                visible_samples[change_metric].append(elapsed_ms)
                terminal_records[change_metric].append(terminal)
                changed_calls, _, _ = run_json(
                    calls_command(
                        binary,
                        fixture.root,
                        data_dir,
                        symbol=target.query_symbol,
                        file=target.query_file,
                    ),
                    environment=environment,
                )
                if (
                    validate_calls(changed_calls, language=target.language)
                    == fingerprints[target.language]
                ):
                    raise HarnessError(
                        f"{target.language} edit did not recertify authority"
                    )
                _, changed_processes = process_population(executables)
                changed_provider = direct_provider_identity(
                    target.language,
                    binary=binary,
                    materialized_providers=materialized_providers,
                    watch_pid=watch_process.pid,
                    live_processes=changed_processes,
                )
                previous_provider = retained_provider_identities.setdefault(
                    target.language, changed_provider
                )
                if changed_provider != previous_provider:
                    raise HarnessError(
                        f"{target.language} WATCH replaced its retained provider "
                        "between benchmark cycles"
                    )

                target.watch_path.write_bytes(original_sources[target.language])
                restored_status, elapsed_ms = wait_for_generation(
                    binary,
                    fixture.root,
                    data_dir,
                    watch_process,
                    current_generation,
                    environment=environment,
                )
                current_generation = validate_complete_status(restored_status)
                terminal = wait_for_generation_terminal(
                    watch_stdout, watch_process, current_generation
                )
                visible_samples[restore_metric].append(elapsed_ms)
                terminal_records[restore_metric].append(terminal)
                restored_calls, _, _ = run_json(
                    calls_command(
                        binary,
                        fixture.root,
                        data_dir,
                        symbol=target.query_symbol,
                        file=target.query_file,
                    ),
                    environment=environment,
                )
                if (
                    validate_calls(restored_calls, language=target.language)
                    != fingerprints[target.language]
                ):
                    raise HarnessError(
                        f"{target.language} restore did not restore exact authority"
                    )
                _, restored_processes = process_population(executables)
                restored_provider = direct_provider_identity(
                    target.language,
                    binary=binary,
                    materialized_providers=materialized_providers,
                    watch_pid=watch_process.pid,
                    live_processes=restored_processes,
                )
                if restored_provider != retained_provider_identities[target.language]:
                    raise HarnessError(
                        f"{target.language} restore replaced its retained provider process"
                    )

        return_code = stop_process_group(watch_process, graceful=True)
        if return_code != 0:
            raise HarnessError(f"WATCH graceful shutdown exited {return_code}")
        watch_process = None
        stdout_file.close()
        stderr_file.close()
        stdout_file = None
        stderr_file = None
        events = read_events(watch_stdout)
        starts = {
            event.get("operation_id")
            for event in events
            if event.get("event") == "reconciliation_started"
        }
        terminals = {
            event.get("operation_id")
            for event in events
            if event.get("event") == "reconciliation_terminal"
        }
        if not starts or starts != terminals:
            raise HarnessError(
                f"WATCH operation receipts are incomplete: {starts=} {terminals=}"
            )
        if any(event.get("state") == "superseded" for event in events):
            raise HarnessError("controlled WATCH benchmark unexpectedly superseded work")

        cli_metrics, mcp_metrics, parity = benchmark_queries(
            binary,
            fixture,
            data_dir,
            environment=environment,
            repetitions=settings["queries"],
        )

        final_digest, final_files, final_bytes = fixture_digest(fixture.root)
        if (final_digest, final_files, final_bytes) != (
            fixture.digest,
            fixture.file_count,
            fixture.byte_count,
        ):
            raise HarnessError("benchmark fixture was not restored byte-exactly")
        for unexpected in (fixture.root / "Cargo.lock", fixture.root / "go.sum"):
            if unexpected.exists():
                raise HarnessError(f"benchmark created project-root residue: {unexpected.name}")

        receipt = args.receipt.resolve(strict=True) if args.receipt else None
        source_receipt = (
            args.source_receipt.resolve(strict=True) if args.source_receipt else None
        )
        artifact: dict[str, Any] = {
            "sha256": sha256_file(binary),
            "version": version,
        }
        if receipt is not None:
            artifact["receipt_sha256"] = sha256_file(receipt)
            receipt_json = json.loads(receipt.read_text(encoding="utf-8"))
            artifact["target"] = receipt_json.get("target")
        if source_receipt is not None:
            artifact["product_source_receipt_sha256"] = sha256_file(source_receipt)

        cold_phase_records = [
            {"phase_timings": result.get("phase_timings", [])}
            for result in cold_results
        ]
        cold_publication_records = [
            {"publication_timings": result.get("publication_timings", [])}
            for result in cold_results
        ]
        report = {
            "schema_version": SCHEMA_VERSION,
            "mode": args.mode,
            "artifact": artifact,
            "environment": {
                "system": platform.system().lower(),
                "machine": platform.machine().lower(),
                "logical_cpus": os.cpu_count(),
                "load_average": [round(value, 3) for value in os.getloadavg()],
                "rustc": tool_version(["rustc", "--version"], environment),
                "cargo": tool_version(["cargo", "--version"], environment),
                "go": tool_version(["go", "version"], environment),
                "python": tool_version(["python3", "--version"], environment),
                "embedded_providers": dict(LANGUAGE_PROVIDER_IDS),
            },
            "fixture": {
                "digest": fixture.digest,
                "file_count": fixture.file_count,
                "byte_count": fixture.byte_count,
                "language_files": {
                    target.language: target.source_files
                    for target in fixture.languages
                },
            },
            "metrics": {
                "process_startup": process_startup,
                "cold_index": summarize(cold_samples),
                "cold_index_phases": timing_population(cold_phase_records),
                "cold_publication_phases": timing_population(
                    cold_publication_records,
                    field="publication_timings",
                    require_work=True,
                ),
                "watch": {
                    "restart_reuse": summarize([restart_ms]),
                    **{
                        name: summarize(samples)
                        for name, samples in visible_samples.items()
                    },
                    "phase_timings": {
                        name: timing_population(records)
                        for name, records in terminal_records.items()
                    },
                    "publication_timings": {
                        name: timing_population(
                            records,
                            field="publication_timings",
                            require_work=True,
                        )
                        for name, records in terminal_records.items()
                    },
                },
                "cli": cli_metrics,
                "mcp": mcp_metrics,
            },
            "correctness": {
                "calls_authority": "complete",
                "providers": dict(LANGUAGE_PROVIDER_IDS),
                "fingerprints_restored": {
                    language: True for language in LANGUAGE_PROVIDER_IDS
                },
                "fixture_restored": True,
                "cli_mcp_payload_parity": parity,
                "watch_operations_started": len(starts),
                "watch_operations_terminal": len(terminals),
                "process_census_population": process_population_before,
                "process_selector_known_positive": len(live_product_processes),
            },
        }
    except BaseException as error:
        failure = error
    finally:
        if watch_process is not None:
            try:
                stop_process_group(watch_process, graceful=True)
            except BaseException as error:
                cleanup_failures.append(f"WATCH cleanup failed: {error}")
        if stdout_file is not None:
            try:
                stdout_file.close()
            except BaseException as error:
                cleanup_failures.append(f"WATCH stdout cleanup failed: {error}")
        if stderr_file is not None:
            try:
                stderr_file.close()
            except BaseException as error:
                cleanup_failures.append(f"WATCH stderr cleanup failed: {error}")
        if fixture is not None:
            try:
                # Byte restoration precedes every error report and residue check.
                if "original_sources" in locals():
                    for target in fixture.languages:
                        target.watch_path.write_bytes(
                            original_sources[target.language]
                        )
            except BaseException as error:
                cleanup_failures.append(f"fixture restoration failed: {error}")
        try:
            executables.update(embedded_provider_paths(scratch))
            process_population_after, leaked = wait_for_no_new_processes(
                executables, processes_before
            )
            if leaked:
                cleanup_failures.append(
                    f"performance battery left process residue: {leaked!r}"
                )
        except BaseException as error:
            cleanup_failures.append(f"process residue census failed: {error}")
        if args.keep_scratch:
            print(f"h00ligan-performance scratch retained: {scratch}", file=sys.stderr)
        else:
            try:
                shutil.rmtree(scratch)
            except BaseException as error:
                cleanup_failures.append(f"scratch cleanup failed: {error}")

    if failure is not None:
        if cleanup_failures:
            raise HarnessError(
                f"benchmark failed ({failure}); cleanup also failed: "
                + "; ".join(cleanup_failures)
            ) from failure
        raise failure
    if cleanup_failures:
        raise HarnessError("; ".join(cleanup_failures))
    if report is None or process_population_after is None:
        raise HarnessError("performance battery produced no report")
    report["correctness"]["process_population_after"] = process_population_after
    report["correctness"]["new_product_processes"] = 0

    if args.baseline:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        report["comparison"] = compare_report(
            report,
            baseline,
            relative_tolerance=args.relative_tolerance,
            absolute_tolerance_ms=args.absolute_tolerance_ms,
        )
    else:
        report["comparison"] = None
    return report


def self_test() -> None:
    controls = 0
    summary = summarize([1, 2, 3, 100])
    if summary["median_ms"] != 2.5 or summary["p95_ms"] != 100:
        raise HarnessError(f"summary positive control failed: {summary!r}")
    controls += 1
    try:
        summarize([])
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("empty sample sabotage did not fire")

    timing_rows = timing_population(
        [
            {
                "phase_timings": [
                    {
                        "label": "provider pool wall",
                        "duration_ms": 10,
                        "aggregation": "exclusive",
                    },
                    {
                        "label": "provider root alpha",
                        "duration_ms": 8,
                        "aggregation": "concurrent_span",
                    },
                ]
            }
        ]
    )
    if (
        timing_rows["provider pool wall"]["aggregation"] != "exclusive"
        or timing_rows["provider root alpha"]["aggregation"] != "concurrent_span"
    ):
        raise HarnessError("timing aggregation positive control failed")
    controls += 1

    publication_rows = timing_population(
        [
            {
                "publication_timings": [
                    {
                        "label": "graph table writes",
                        "duration_ms": 7,
                        "aggregation": "exclusive",
                        "work_items": 42,
                        "work_unit": "rows",
                    },
                    {
                        "label": "graph table writes",
                        "duration_ms": 9,
                        "aggregation": "exclusive",
                        "work_items": 44,
                        "work_unit": "rows",
                    },
                ]
            }
        ],
        field="publication_timings",
        require_work=True,
    )
    publication_write = publication_rows["graph table writes"]
    if (
        publication_write["count"] != 2
        or publication_write["median_ms"] != 8
        or publication_write["work_unit"] != "rows"
        or publication_write["work_items"]["samples"] != [42, 44]
    ):
        raise HarnessError(
            f"publication timing population positive control failed: {publication_rows!r}"
        )
    controls += 1
    try:
        timing_population(
            [
                {
                    "publication_timings": [
                        {
                            "label": "graph table writes",
                            "duration_ms": 7,
                            "aggregation": "exclusive",
                        }
                    ]
                }
            ],
            field="publication_timings",
            require_work=True,
        )
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("missing publication work population sabotage did not fire")

    try:
        timing_population(
            [{"phase_timings": [{"label": "ambiguous", "duration_ms": 1}]}]
        )
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("missing timing aggregation sabotage did not fire")

    with tempfile.TemporaryDirectory(prefix="h00ligan-performance-self-test.") as temp:
        first = build_fixture(
            Path(temp) / "first",
            rust_files=2,
            go_files=3,
            python_files=2,
            typescript_files=2,
        )
        second = build_fixture(
            Path(temp) / "second",
            rust_files=2,
            go_files=3,
            python_files=2,
            typescript_files=2,
        )
        if first.digest != second.digest or first.file_count == 0:
            raise HarnessError("fixture determinism positive control failed")
        controls += 1
        rust_target = second.language("rust")
        replace_marker(rust_target.watch_path, rust_target.marker(0), rust_target.marker(1))
        if fixture_digest(second.root)[0] == first.digest:
            raise HarnessError("fixture mutation sabotage did not fire")
        controls += 1
        try:
            replace_marker(rust_target.watch_path, "missing marker", "replacement")
        except HarnessError:
            controls += 1
        else:
            raise HarnessError("missing marker sabotage did not fire")

    process = {
        "pid": 1,
        "parent_pid": 0,
        "process_group": 1,
        "started": "now",
        "command": "h00ligan watch",
    }
    second_process = {
        **process,
        "pid": 2,
        "command": "h00-go-semantic-provider --stdio",
    }
    if new_processes([process], [process]):
        raise HarnessError("process identity positive control failed")
    controls += 1
    if new_processes([process], [process, second_process]) != [second_process]:
        raise HarnessError("process residue sabotage did not fire")
    controls += 1
    rust_child = {
        **process,
        "pid": 3,
        "parent_pid": 1,
        "process_group": 3,
        "command": "/product/h00ligan __h00-internal-rust-provider",
    }
    rust_identity = direct_provider_identity(
        "rust",
        binary=Path("/product/h00ligan"),
        materialized_providers=set(),
        watch_pid=1,
        live_processes=[rust_child],
    )
    if rust_identity != process_identity(rust_child):
        raise HarnessError("direct provider identity positive control failed")
    controls += 1
    try:
        direct_provider_identity(
            "rust",
            binary=Path("/product/h00ligan"),
            materialized_providers=set(),
            watch_pid=1,
            live_processes=[],
        )
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("missing retained provider sabotage did not fire")

    complete_status = {
        "publication_state": "published",
        "freshness": "fresh",
        "generation_id": "generation-positive-control",
        "capabilities": {
            "calls": {
                "status": "complete",
                "languages": [
                    {
                        "language_id": language,
                        "status": "complete",
                        "provider_id": provider,
                    }
                    for language, provider in LANGUAGE_PROVIDER_IDS.items()
                ],
            }
        },
    }
    if validate_complete_status(complete_status) != "generation-positive-control":
        raise HarnessError("provider identity positive control failed")
    controls += 1
    wrong_provider = json.loads(json.dumps(complete_status))
    wrong_provider["capabilities"]["calls"]["languages"][1]["provider_id"] = (
        "obsolete-go-provider"
    )
    try:
        validate_complete_status(wrong_provider)
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("obsolete Go provider sabotage did not fire")
    missing_python = json.loads(json.dumps(complete_status))
    missing_python["capabilities"]["calls"]["languages"] = [
        item
        for item in missing_python["capabilities"]["calls"]["languages"]
        if item["language_id"] != "python"
    ]
    try:
        validate_complete_status(missing_python)
    except HarnessError:
        controls += 1
    else:
        raise HarnessError("missing Python authority sabotage did not fire")

    fixture_identity = {
        "digest": "fixture",
        "file_count": 1,
        "byte_count": 1,
        "language_files": {language: 1 for language in LANGUAGE_PROVIDER_IDS},
    }
    metric = summarize([100])
    metrics: dict[str, Any] = {
        "process_startup": metric,
        "cold_index": metric,
        "watch": {
            "restart_reuse": metric,
            **{
                f"{language}_{operation}": metric
                for language in LANGUAGE_PROVIDER_IDS
                for operation in ("change", "restore")
            },
        },
        "cli": {
            "status": metric,
            "overview": metric,
            **{
                f"{verb}_{language}": metric
                for language in LANGUAGE_PROVIDER_IDS
                for verb in ("find", "calls")
            },
        },
        "mcp": {
            "status": metric,
            "overview": metric,
            **{
                f"{verb}_{language}": metric
                for language in LANGUAGE_PROVIDER_IDS
                for verb in ("find", "calls")
            },
        },
    }
    baseline = {
        "schema_version": SCHEMA_VERSION,
        "mode": "smoke",
        "fixture": fixture_identity,
        "metrics": metrics,
    }
    current = json.loads(json.dumps(baseline))
    comparison = compare_report(
        current, baseline, relative_tolerance=0.10, absolute_tolerance_ms=5
    )
    if not comparison["passed"]:
        raise HarnessError("baseline equality positive control failed")
    controls += 1
    current["metrics"]["watch"]["rust_change"] = summarize([200])
    comparison = compare_report(
        current, baseline, relative_tolerance=0.10, absolute_tolerance_ms=5
    )
    if len(comparison["regressions"]) != 2:
        raise HarnessError(
            f"performance regression sabotage did not fire exactly: {comparison!r}"
        )
    controls += 1

    fast_baseline = json.loads(json.dumps(baseline))
    fast_current = json.loads(json.dumps(baseline))
    fast_baseline["metrics"]["cli"]["status"] = summarize([4])
    fast_current["metrics"]["cli"]["status"] = summarize([40])
    comparison = compare_report(
        fast_current,
        fast_baseline,
        relative_tolerance=0.20,
        absolute_tolerance_ms=DEFAULT_ABSOLUTE_TOLERANCE_MS,
    )
    if len(comparison["regressions"]) != 2:
        raise HarnessError(
            "fast fixed-cost regression sabotage did not fire exactly: "
            f"{comparison!r}"
        )
    controls += 1

    report = json.loads(json.dumps(current))
    report["artifact"] = {"sha256": "a" * 64}
    report["correctness"] = {
        "watch_operations_terminal": 5,
        "new_product_processes": 0,
    }
    report["comparison"] = None
    rendered = render_summary(report, Path("report.json"))
    if "h00ligan performance: PASS (smoke)" not in rendered or not rendered.endswith(
        "report: report.json"
    ):
        raise HarnessError(f"human summary positive control failed: {rendered!r}")
    controls += 1

    print(f"h00ligan-performance: self-test OK ({controls} controls fired)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--relative-tolerance", type=float, default=0.20)
    parser.add_argument(
        "--absolute-tolerance-ms",
        type=float,
        default=DEFAULT_ABSOLUTE_TOLERANCE_MS,
    )
    parser.add_argument("--keep-scratch", action="store_true")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="print a compact human receipt instead of the full JSON report",
    )
    args = parser.parse_args()
    if not args.self_test and args.binary is None:
        parser.error("--binary is required unless --self-test is used")
    if args.relative_tolerance < 0 or args.absolute_tolerance_ms < 0:
        parser.error("performance tolerances must be non-negative")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        report = run_battery(args)
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(serialized, encoding="utf-8")
        if args.summary:
            print(render_summary(report, args.output))
        else:
            sys.stdout.write(serialized)
        comparison = report.get("comparison")
        if isinstance(comparison, dict) and not comparison.get("passed", False):
            return 2
        return 0
    except (HarnessError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"h00ligan-performance: ERROR: {bounded(str(error))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
