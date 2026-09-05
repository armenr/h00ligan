#!/usr/bin/env python3
"""Exercise the documented 0.3.0 tour against an explicit one-file executable.

No build, install, network request, or existing project-index mutation. Every
source edit and generated file belongs to one automatically removed temp root.
This is documentation acceptance, not a replacement for ci-product.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
TOOLS = {
    "reindex", "reindex_status", "reindex_cancel", "watch", "type", "read",
    "calls", "assess", "inspect", "dead_code", "status", "find", "tests",
    "overview", "audit", "deps", "grep_context", "diff",
}
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "h00ligan-docs", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def cli(base: list[str], args: list[str], *, error: bool = False) -> dict:
    result = subprocess.run(
        [*base, *args, "--format", "json"], capture_output=True, text=True, timeout=120
    )
    require((result.returncode != 0) == error, f"CLI {args}: {result.stderr}")
    value = json.loads(result.stdout)
    require(("error" in value) == error, f"CLI error envelope mismatch: {args}")
    return value


class Mcp:
    def __init__(self, base: list[str], log):
        self.process = subprocess.Popen(
            [*base, "mcp-serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=log, text=True, bufsize=1,
        )
        self.sequence = 0

    def request(self, method: str, params: dict, *, error_code: int | None = None) -> dict:
        self.sequence += 1
        request = {
            "jsonrpc": "2.0", "id": self.sequence, "method": method,
            "params": {**params, "_meta": META},
        }
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 30)
        require(bool(ready), f"MCP response timeout: {method}")
        response = json.loads(self.process.stdout.readline())
        require(response.get("id") == self.sequence, "MCP response identity mismatch")
        if error_code is not None:
            require(response.get("error", {}).get("code") == error_code,
                    f"Expected MCP protocol refusal {error_code}: {response}")
            return response["error"]
        require("error" not in response, f"MCP transport error: {response}")
        return response["result"]

    def call(self, name: str, args: dict, *, error: bool = False) -> dict:
        result = self.request("tools/call", {"name": name, "arguments": args})
        require(bool(result.get("isError")) == error, f"MCP {name}: {result}")
        return result["structuredContent"]

    def terminal(self, operation_id: str) -> dict:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            operation = self.call("reindex_status", {"operation_id": operation_id})
            if operation["terminal"]:
                require(operation["state"] == "succeeded", f"Reindex failed: {operation}")
                require(operation["result"] is not None, "No terminal publication receipt")
                return operation
            time.sleep(0.1)
        raise RuntimeError("Reindex never became terminal")

    def watch_ready(self, previous_generation: str | None = None) -> str:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = self.call("watch", {"action": "status"})
            require(status["watch"]["running"], "WATCH stopped unexpectedly")
            require(not status["watch"]["last_error"], f"WATCH error: {status}")
            operation = status.get("latest_operation")
            if operation and operation["terminal"] and operation["trigger"] == "watch":
                receipt = self.terminal(operation["operation_id"])
                generation = receipt["result"]["generation"]["id"]
                if previous_generation is None or generation != previous_generation:
                    return generation
            time.sleep(0.1)
        raise RuntimeError("WATCH did not publish the expected generation")

    def close(self) -> None:
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
            raise RuntimeError("MCP failed graceful shutdown")
        finally:
            self.process.stdout.close()
        require(code == 0, f"MCP shutdown exit {code}")


def exercise(binary: Path, temporary: Path) -> None:
    repo = temporary / "quickstart"
    shutil.copytree(ROOT / "examples/quickstart", repo)
    base = [str(binary), "--root", str(repo), "--data-dir", str(temporary / "data")]
    publication = cli(base, ["index", "--scip", "--require-complete-calls"])
    require(publication["capabilities"]["calls"]["status"] == "complete", "Calls not complete")

    with (temporary / "mcp.stderr").open("w+") as log:
        mcp = Mcp(base, log)
        try:
            catalog = mcp.request("tools/list", {})["tools"]
            require(len(catalog) == 18 and {t["name"] for t in catalog} == TOOLS,
                    "Documented MCP tool population changed")
            selectors = {"symbol": "greeting", "file": "app.py"}
            symbol_cli = ["greeting", "--file", "app.py"]
            cases = [
                ("status", ["status"], {}),
                ("overview", ["overview"], {}),
                ("find", ["find", "greeting", "--name", "--definitions-only"],
                 {"query": "greeting", "mode": "name", "definitions_only": True}),
                ("type", ["type", "GreetingStyle", "--file", "app.py"],
                 {"symbol": "GreetingStyle", "file": "app.py"}),
                ("read", ["read", *symbol_cli], selectors),
                ("calls", ["calls", *symbol_cli, "--filter", "all"], {**selectors, "filter": "all"}),
                ("tests", ["tests", *symbol_cli], selectors),
                ("inspect", ["inspect", *symbol_cli], selectors),
                ("assess", ["assess", *symbol_cli, "--filter", "all", "--depth", "3"],
                 {**selectors, "filter": "all", "depth": 3}),
                ("deps", ["deps", "app.py"], {"path": "app.py"}),
                ("audit", ["audit", "--scope", "all", "--min-fan-in", "1"],
                 {"scope": "all", "min_fan_in": 1}),
                ("diff", ["diff", "app.py"], {"path": "app.py"}),
                ("grep_context", ["grep-context", "Hello", "--path", "app.py", "-C", "1"],
                 {"pattern": "Hello", "path": "app.py", "context_lines": 1}),
            ]
            results = {}
            for name, args, arguments in cases:
                results[name] = cli(base, args)
                require(results[name] == mcp.call(name, arguments), f"CLI/MCP parity: {name}")
            require(len(results["find"]["items"]) == 1, "Expected exactly one greeting definition")
            require(any(item["symbol"]["name"].endswith("prefix")
                        for item in results["type"]["items"]), "Type member positive control")
            require("def greeting(name: str) -> str:" in results["read"]["source"],
                    "Read source positive control")
            require({i["origin"]["identity"]["name"] for i in results["calls"]["items"]}
                    == {"greet", "test_greeting"}, "Caller positive control changed")
            require([i["test"]["name"] for i in results["tests"]["items"]] == ["test_greeting"],
                    "Test-entry positive control changed")
            dead = cli(base, ["dead", "_unused", "--file", "app.py"], error=True)
            require(dead == mcp.call("dead_code", {"symbol": "_unused", "file": "app.py"}, error=True),
                    "Dead-code error parity")
            require(dead["error"]["evidence"][0]["reason_code"] == "reachability_evidence_unavailable",
                    "Documented Python classification limit changed; reconcile the guides")

            page_args = {**selectors, "filter": "all", "limit": 1}
            first = mcp.call("calls", page_args)
            require(first["page"]["returned"] == 1 and first["page"]["has_more"], "Paging positive")
            second = mcp.call("calls", {**page_args, "cursor": first["page"]["next_cursor"]})
            require(not second["page"]["has_more"], "Expected terminal second page")
            require(first["items"] + second["items"] == results["calls"]["items"], "Paging lost rows")
            mcp.request("tools/call", {"name": "calls", "arguments": {**page_args, "limit": 101}},
                        error_code=-32602)

            source = repo / "app.py"
            original = source.read_bytes()
            source.write_bytes(original.replace(b"Hello,", b"Welcome,"))
            require(mcp.call("calls", {**selectors, "filter": "all"})["repository"]["live_inputs"]
                    ["freshness"] == "stale", "Stale graph must be labeled")
            changed_read = cli(base, ["read", *symbol_cli], error=True)
            require(changed_read["error"]["code"] == "source_changed_since_indexing",
                    "Changed source must refuse for its actual byte mismatch")
            require(changed_read == mcp.call("read", selectors, error=True),
                    "Changed-source refusal must agree across CLI/MCP")
            source.write_bytes(original)
            require(mcp.call("read", selectors)["source"] == results["read"]["source"],
                    "Exact restored source must be readable")

            started = mcp.call("reindex", {"scip": True})
            terminal = mcp.terminal(started["operation_id"])
            require(terminal["result"]["reused_generation"], "Unchanged reindex must reuse")
            cancelled = mcp.call("reindex_cancel", {"operation_id": started["operation_id"]})
            require(not cancelled["cancellation"]["accepted"], "Terminal cancellation must be inert")

            mcp.call("watch", {"action": "start", "scip": True})
            try:
                generation = mcp.watch_ready()
                source.write_bytes(original.replace(b"Hello,", b"Welcome,"))
                changed = mcp.watch_ready(generation)
                require("Welcome," in mcp.call("read", selectors)["source"], "WATCH changed source")
                source.write_bytes(original)
                mcp.watch_ready(changed)
                require(mcp.call("read", selectors)["source"] == results["read"]["source"],
                        "WATCH restored source")
            finally:
                stopped = mcp.call("watch", {"action": "stop"})
                require(not stopped["watch"]["running"], "WATCH stop failed")
                source.write_bytes(original)
            require(source.read_bytes() == original, "Fixture restoration")
            print("PASS: 18 tools; 14 CLI/MCP query/error pairs; callers/test positives; "
                  "pagination/bounds; stale/refused/restored source; reindex/reuse/terminal "
                  "cancel; semantic WATCH edit/restore/stop", flush=True)
        finally:
            mcp.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="Explicit built one-file h00ligan")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), "--version"], text=True, timeout=10).strip()
    print(version, flush=True)
    with tempfile.TemporaryDirectory(prefix="h00ligan-docs-") as directory:
        exercise(binary, Path(directory))
    require(not Path(directory).exists(), "Temporary root survived cleanup")
    print("PASS: server exited; temporary source/index/log root removed", flush=True)


if __name__ == "__main__":
    main()
