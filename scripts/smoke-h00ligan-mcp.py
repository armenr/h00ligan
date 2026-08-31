#!/usr/bin/env python3
"""Exercise MCP framing and protocol identity through a built h00ligan binary."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


CURRENT_PROTOCOL_VERSION = "2026-07-28"
EXPECTED_TOOLS = {
    "assess",
    "audit",
    "calls",
    "dead_code",
    "deps",
    "diff",
    "find",
    "grep_context",
    "inspect",
    "overview",
    "read",
    "reindex",
    "reindex_cancel",
    "reindex_status",
    "status",
    "tests",
    "type",
    "watch",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"h00ligan MCP smoke: FAIL: {message}")


def released_version(binary: Path) -> str:
    completed = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    require(
        completed.returncode == 0,
        f"binary --version exited {completed.returncode}: {completed.stderr.strip()}",
    )
    prefix = "h00ligan "
    identity = completed.stdout.strip()
    require(identity.startswith(prefix), f"unexpected binary identity: {identity!r}")
    version = identity.removeprefix(prefix).split("+", 1)[0]
    require(bool(version), f"binary identity has no release version: {identity!r}")
    return version


def tool_payload(response: dict[str, object], operation: str) -> dict[str, object]:
    require("error" not in response, f"{operation} returned {response.get('error')}")
    result = response.get("result")
    require(isinstance(result, dict), f"{operation} result is not an object")
    require(result.get("isError") is not True, f"{operation} returned a tool error: {result}")
    payload = result.get("structuredContent")
    require(isinstance(payload, dict), f"{operation} has no structured content")
    return payload


def exercise_reindex_lifecycle(
    binary: Path,
    scratch: Path | None,
    metadata: dict[str, object],
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="h00ligan-mcp-lifecycle.", dir=scratch
    ) as temporary:
        temporary_root = Path(temporary)
        project_root = temporary_root / "repo"
        data_dir = temporary_root / "data"
        (project_root / ".git").mkdir(parents=True)
        (project_root / "src").mkdir()
        (project_root / "Cargo.toml").write_text(
            '[package]\nname = "h00ligan_mcp_smoke"\nversion = "0.1.0"\n'
            'edition = "2024"\n\n[workspace]\n',
            encoding="utf-8",
        )
        (project_root / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")

        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as stderr_log:
            child = subprocess.Popen(
                [
                    str(binary),
                    "--root",
                    str(project_root),
                    "--data-dir",
                    str(data_dir),
                    "mcp-serve",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_log,
                text=True,
                bufsize=1,
            )
            require(child.stdin is not None, "lifecycle MCP stdin is unavailable")
            require(child.stdout is not None, "lifecycle MCP stdout is unavailable")

            next_id = 10

            def call(name: str, arguments: dict[str, object]) -> dict[str, object]:
                nonlocal next_id
                request_id = next_id
                next_id += 1
                request = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": {
                        "name": name,
                        "arguments": arguments,
                        "_meta": metadata,
                    },
                }
                child.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
                child.stdin.flush()
                line = child.stdout.readline()
                require(bool(line), f"MCP closed before responding to {name}")
                try:
                    response = json.loads(line)
                except json.JSONDecodeError as error:
                    raise SystemExit(
                        f"h00ligan MCP smoke: FAIL: {name} response is not JSON-RPC: {error}"
                    ) from error
                require(response.get("jsonrpc") == "2.0", f"{name} is not JSON-RPC 2.0")
                require(response.get("id") == request_id, f"{name} response has the wrong id")
                return response

            try:
                started = tool_payload(call("reindex", {}), "reindex")
                require(started.get("terminal") is False, "reindex did not return a start receipt")
                operation_id = started.get("operation_id")
                require(
                    isinstance(operation_id, str) and operation_id.startswith("index-"),
                    "reindex returned no operation authority",
                )

                deadline = time.monotonic() + 30
                while True:
                    terminal = tool_payload(
                        call("reindex_status", {"operation_id": operation_id}),
                        "reindex_status",
                    )
                    if terminal.get("terminal") is True:
                        break
                    require(
                        time.monotonic() < deadline,
                        f"reindex did not become terminal: {terminal}",
                    )
                    time.sleep(0.01)

                require(
                    terminal.get("operation_id") == operation_id,
                    "terminal receipt changed operation identity",
                )
                require(terminal.get("state") == "succeeded", f"reindex failed: {terminal}")
                result = terminal.get("result")
                require(isinstance(result, dict), "terminal receipt has no publication result")
                generation = result.get("generation")
                require(isinstance(generation, dict), "terminal receipt has no generation")
                require(isinstance(generation.get("id"), str), "generation has no identity")

                replay = tool_payload(
                    call("reindex_cancel", {"operation_id": operation_id}),
                    "reindex_cancel",
                )
                cancellation = replay.get("cancellation")
                require(
                    isinstance(cancellation, dict)
                    and cancellation.get("accepted") is False
                    and cancellation.get("reason") == "already_terminal",
                    "terminal cancellation replay was not inert",
                )

                watch_started = tool_payload(
                    call(
                        "watch",
                        {
                            "action": "start",
                            "debounce_ms": 25,
                            "reconcile_secs": 60,
                        },
                    ),
                    "watch start",
                )
                watch = watch_started.get("watch")
                require(
                    isinstance(watch, dict) and watch.get("running") is True,
                    f"WATCH did not start: {watch_started}",
                )
                initial_desired = watch.get("desired_epoch")
                require(
                    isinstance(initial_desired, int) and initial_desired > 0,
                    f"WATCH start returned no desired epoch: {watch_started}",
                )

                deadline = time.monotonic() + 30
                while True:
                    watch_status = tool_payload(
                        call("watch", {"action": "status"}), "watch status"
                    )
                    watch = watch_status.get("watch")
                    require(isinstance(watch, dict), "WATCH status has no watch object")
                    published_epoch = watch.get("published_epoch")
                    if (
                        isinstance(published_epoch, int)
                        and published_epoch >= initial_desired
                    ):
                        break
                    require(
                        time.monotonic() < deadline,
                        f"WATCH initial reconciliation did not publish: {watch_status}",
                    )
                    time.sleep(0.01)

                (project_root / "src/main.rs").write_text(
                    "fn main() {}\npub fn watched_release_smoke() {}\n",
                    encoding="utf-8",
                )
                initial_published = published_epoch
                deadline = time.monotonic() + 30
                while True:
                    watch_status = tool_payload(
                        call("watch", {"action": "status"}), "watch status"
                    )
                    watch = watch_status.get("watch")
                    require(isinstance(watch, dict), "WATCH status has no watch object")
                    published_epoch = watch.get("published_epoch")
                    if (
                        isinstance(published_epoch, int)
                        and published_epoch > initial_published
                    ):
                        break
                    require(
                        time.monotonic() < deadline,
                        f"WATCH changed-source reconciliation did not publish: {watch_status}",
                    )
                    time.sleep(0.01)

                found = tool_payload(
                    call(
                        "find",
                        {
                            "query": "watched_release_smoke",
                            "mode": "name",
                            "definitions_only": True,
                        },
                    ),
                    "find watched_release_smoke",
                )
                items = found.get("items")
                require(isinstance(items, list), f"Find returned no items: {found}")
                require(
                    any(
                        isinstance(item, dict)
                        and (
                            item.get("name") == "watched_release_smoke"
                            or (
                                isinstance(item.get("symbol"), dict)
                                and item["symbol"].get("name")
                                == "watched_release_smoke"
                            )
                        )
                        for item in items
                    ),
                    f"same-session query did not observe WATCH publication: {found}",
                )

                stopped = tool_payload(
                    call("watch", {"action": "stop"}), "watch stop"
                )
                stopped_watch = stopped.get("watch")
                require(
                    stopped.get("changed") is True
                    and isinstance(stopped_watch, dict)
                    and stopped_watch.get("running") is False,
                    f"WATCH did not stop cleanly: {stopped}",
                )
                stop_replay = tool_payload(
                    call("watch", {"action": "stop"}), "watch stop replay"
                )
                require(
                    stop_replay.get("changed") is False,
                    f"WATCH stop replay was not inert: {stop_replay}",
                )
            finally:
                child.stdin.close()
                try:
                    return_code = child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill()
                    return_code = child.wait(timeout=10)
                    require(False, "lifecycle MCP did not exit after stdin closed")
                stderr_log.seek(0)
                stderr = stderr_log.read().strip()
                require(return_code == 0, f"lifecycle MCP exited {return_code}: {stderr}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--version",
        help="expected release version (defaults to the binary's package version)",
    )
    parser.add_argument("--scratch", type=Path)
    args = parser.parse_args()

    binary = args.binary.resolve(strict=True)
    scratch = args.scratch.resolve(strict=True) if args.scratch is not None else None
    require(binary.is_file(), f"binary is not a file: {binary}")
    version = args.version or released_version(binary)

    metadata = {
        "io.modelcontextprotocol/protocolVersion": CURRENT_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "h00ligan-release-smoke",
            "version": "1.0.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {"_meta": metadata},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"_meta": metadata},
        },
    ]
    payload = "".join(
        json.dumps(request, separators=(",", ":")) + "\n" for request in requests
    )

    with tempfile.TemporaryDirectory(prefix="h00ligan-mcp-smoke.", dir=scratch) as temporary:
        temporary_root = Path(temporary)
        project_root = temporary_root / "repo"
        data_dir = temporary_root / "data"
        (project_root / ".git").mkdir(parents=True)
        completed = subprocess.run(
            [
                str(binary),
                "--root",
                str(project_root),
                "--data-dir",
                str(data_dir),
                "mcp-serve",
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    require(
        completed.returncode == 0,
        f"binary exited {completed.returncode}: {completed.stderr.strip()}",
    )
    lines = completed.stdout.splitlines()
    require(len(lines) == 2, f"expected 2 stdout frames, got {len(lines)}")
    try:
        responses = [json.loads(line) for line in lines]
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"h00ligan MCP smoke: FAIL: stdout is not pure JSON-RPC: {error}"
        ) from error

    for expected_id, response in enumerate(responses, start=1):
        require(response.get("jsonrpc") == "2.0", f"response {expected_id} is not JSON-RPC 2.0")
        require(response.get("id") == expected_id, f"response {expected_id} has the wrong id")
        require("error" not in response, f"response {expected_id} returned {response.get('error')}")

    expected_identity = {"name": "h00ligan", "version": version}
    discover = responses[0].get("result", {})
    require(discover.get("resultType") == "complete", "discovery resultType is not complete")
    require(discover.get("ttlMs") == 0, "discovery must be immediately stale")
    require(discover.get("cacheScope") == "private", "discovery cache scope is not private")
    require(
        discover.get("supportedVersions", [None])[0] == CURRENT_PROTOCOL_VERSION,
        "current protocol is not the preferred discovery version",
    )
    require(discover.get("capabilities", {}).get("tools") == {}, "tools capability is absent")
    require(
        discover.get("_meta", {}).get("io.modelcontextprotocol/serverInfo")
        == expected_identity,
        "discovery identity does not match the released binary",
    )

    listed = responses[1].get("result", {})
    require(listed.get("resultType") == "complete", "tools/list resultType is not complete")
    require(listed.get("ttlMs") == 0, "tools/list must be immediately stale")
    require(listed.get("cacheScope") == "private", "tools/list cache scope is not private")
    require(
        listed.get("_meta", {}).get("io.modelcontextprotocol/serverInfo")
        == expected_identity,
        "tools/list identity does not match the released binary",
    )
    tools = listed.get("tools")
    require(isinstance(tools, list), "tools/list did not return an array")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    require(names == EXPECTED_TOOLS, f"tool population mismatch: {sorted(names)}")
    require(len(tools) == len(EXPECTED_TOOLS), "tool names are duplicated")

    exercise_reindex_lifecycle(binary, scratch, metadata)

    print(
        "h00ligan MCP smoke: OK "
        f"(protocol {CURRENT_PROTOCOL_VERSION}, version {version}, tools {len(tools)}, "
        "async reindex + WATCH lifecycles)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
