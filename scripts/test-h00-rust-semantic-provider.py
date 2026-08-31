#!/usr/bin/env python3
"""Independent installed-boundary test for h00ligan's Rust semantic provider."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import time

from h00_semantic_provider_test_harness import (
    FRAME_MAGIC,
    Provider as FramedProvider,
    error_code,
    population_sha256,
    scip_document_occurrence_symbols,
    scip_document_symbols,
    sha256,
)


PROTOCOL = "h00/semantic-provider/v13"
UPSTREAM_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
RESOLVED_TOOLCHAIN_SHA256 = sha256(b"installed-test-toolchain")
RUST_SEMANTIC_PROFILE = json.dumps(
    {
        "schema_version": "h00/rust-semantic-profile/v1",
        "cargo_features": "workspace_default",
        "target": None,
    },
    separators=(",", ":"),
)
def resolved_program(environment_name: str, default: str) -> Path:
    requested = os.environ.get(environment_name, default)
    located = shutil.which(requested)
    if located is None:
        raise AssertionError(f"required provider test program is unavailable: {requested}")
    # Preserve the invoked basename for rustup-style proxy executables. A
    # canonicalized `.../rustup` path no longer dispatches as `rustc`/`cargo`.
    return Path(located).absolute()


RUSTC = resolved_program("RUSTC", "rustc")
CARGO = resolved_program("CARGO", "cargo")
RUNTIME_TOOLCHAIN_ENVIRONMENT = {
    "RUSTC": str(RUSTC),
    "CARGO": str(CARGO),
    "H00_RESOLVED_RUSTC_SHA256": sha256(RUSTC.read_bytes()),
    "H00_RESOLVED_CARGO_SHA256": sha256(CARGO.read_bytes()),
}


class Provider(FramedProvider):
    def __init__(
        self,
        binary: Path,
        binary_arguments: list[str],
        identity: dict[str, object],
        session_id: str,
        working_directory: Path,
        runtime_environment: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            binary,
            binary_arguments,
            identity,
            session_id,
            working_directory,
            {
                **os.environ,
                "H00_RESOLVED_TOOLCHAIN_SHA256": RESOLVED_TOOLCHAIN_SHA256,
                "H00_RUST_SEMANTIC_PROFILE": RUST_SEMANTIC_PROFILE,
                **(
                    RUNTIME_TOOLCHAIN_ENVIRONMENT
                    if runtime_environment is None
                    else runtime_environment
                ),
            },
        )


def run_same_path_toolchain_drift(
    binary: Path,
    binary_arguments: list[str],
    identity: dict[str, str],
    scratch_root: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix="h00-ra-provider-toolchain-drift.", dir=scratch_root
    ) as directory:
        root = Path(directory).resolve()
        rustc_wrapper = root / "rustc"
        original = f'#!/bin/sh\nexec {shlex.quote(str(RUSTC))} "$@"\n'
        rustc_wrapper.write_text(original)
        rustc_wrapper.chmod(0o755)
        runtime_environment = {
            **RUNTIME_TOOLCHAIN_ENVIRONMENT,
            "RUSTC": str(rustc_wrapper),
            "H00_RESOLVED_RUSTC_SHA256": sha256(rustc_wrapper.read_bytes()),
        }
        provider = Provider(
            binary,
            binary_arguments,
            identity,
            "toolchain-drift",
            root,
            runtime_environment,
        )
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            if hello["body"].get("result") != "hello":
                raise AssertionError("provider toolchain-drift positive Hello control failed")
            rustc_wrapper.write_text(original + "# same-path identity drift\n")
            rustc_wrapper.chmod(0o755)
            changed, _ = provider.call(2, {"operation": "hello"})
            changed_body = changed["body"]
            if (
                changed_body.get("result") != "error"
                or changed_body.get("code") != "request_failed"
                or "changed after product resolution"
                not in str(changed_body.get("message"))
            ):
                raise AssertionError(
                    "same-path rustc byte drift did not fail for the intended authority reason: "
                    f"{changed_body}"
                )
            return {
                "same_path_toolchain_drift_error": changed_body["code"],
                "same_path_toolchain_drift_failed_closed": True,
            }
        finally:
            provider.terminate()


def run_parent_death_guard(
    binary: Path,
    binary_arguments: list[str],
) -> dict[str, object]:
    def parse_group_members(
        population: str, process_group: int
    ) -> list[tuple[int, str]]:
        members = []
        for line in population.splitlines():
            fields = line.split()
            if len(fields) != 3:
                continue
            try:
                pid = int(fields[0])
                pgid = int(fields[1])
            except ValueError:
                continue
            if pgid == process_group:
                members.append((pid, fields[2]))
        return members

    def group_members(process_group: int) -> list[tuple[int, str]]:
        population = subprocess.run(
            ["ps", "-axo", "pid=,pgid=,stat="],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout
        return parse_group_members(population, process_group)

    # Non-vacuity and sabotage controls for the lifecycle oracle. A zombie is
    # terminal and cannot execute, but a live descendant in the same group must
    # still fail the parent-death contract.
    oracle_fixture = "101 101 Z\n102 101 S\n103 103 R\n"
    if parse_group_members(oracle_fixture, 101) != [(101, "Z"), (102, "S")]:
        raise AssertionError("parent-death process-group oracle is not selective")
    if not any(
        not state.startswith("Z")
        for _, state in parse_group_members(oracle_fixture, 101)
    ):
        raise AssertionError("parent-death process-group oracle missed a live member")
    zombie_fixture = "101 101 Z\n103 103 R\n"
    if any(
        not state.startswith("Z")
        for _, state in parse_group_members(zombie_fixture, 101)
    ):
        raise AssertionError("parent-death process-group oracle treated a zombie as live")

    environment = {
        **os.environ,
        "H00_RESOLVED_TOOLCHAIN_SHA256": RESOLVED_TOOLCHAIN_SHA256,
        "H00_RUST_SEMANTIC_PROFILE": RUST_SEMANTIC_PROFILE,
        **RUNTIME_TOOLCHAIN_ENVIRONMENT,
    }

    def run_case(*, delayed_start: bool) -> tuple[int, bool]:
        provider_stdin, held_writer = os.pipe()
        launch_reader, launch_writer = os.pipe()
        os.set_inheritable(provider_stdin, True)
        os.set_inheritable(launch_reader, True)
        helper_source = (
            "import json,os,subprocess,sys,time\n"
            "binary=json.loads(sys.argv[1])\n"
            "arguments=json.loads(sys.argv[2])\n"
            "environment=json.loads(sys.argv[3])\n"
            "stdin_fd=int(sys.argv[4])\n"
            "delayed=json.loads(sys.argv[5])\n"
            "gate_fd=int(sys.argv[6])\n"
            "environment['H00_PROVIDER_PARENT_PID']=str(os.getpid())\n"
            "if delayed:\n"
            " child=os.fork()\n"
            " if child == 0:\n"
            "  os.setsid()\n"
            "  os.read(gate_fd,1)\n"
            "  devnull=os.open(os.devnull,os.O_RDWR)\n"
            "  os.dup2(stdin_fd,0)\n"
            "  os.dup2(devnull,1)\n"
            "  os.dup2(devnull,2)\n"
            "  os.execve(binary,[binary,*arguments],environment)\n"
            "else:\n"
            " child=subprocess.Popen([binary,*arguments],stdin=stdin_fd,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL,start_new_session=True,env=environment,pass_fds=(stdin_fd,))\n"
            " child=child.pid\n"
            "print(child,flush=True)\n"
            "time.sleep(60)\n"
        )
        helper = subprocess.Popen(
            [
                sys.executable,
                "-c",
                helper_source,
                json.dumps(str(binary)),
                json.dumps(binary_arguments),
                json.dumps(environment),
                str(provider_stdin),
                json.dumps(delayed_start),
                str(launch_reader),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=(provider_stdin, launch_reader),
        )
        os.close(provider_stdin)
        os.close(launch_reader)
        provider_pid: int | None = None
        try:
            line = helper.stdout.readline().strip()
            if not line.isdigit():
                raise AssertionError(
                    f"parent-death helper did not report provider PID: {line!r}"
                )
            provider_pid = int(line)
            os.kill(provider_pid, 0)
            if not delayed_start:
                time.sleep(0.25)
            os.kill(helper.pid, signal.SIGKILL)
            helper.wait(timeout=5)
            if delayed_start:
                os.write(launch_writer, b"1")
            os.close(launch_writer)
            launch_writer = -1

            label = "pre-arm" if delayed_start else "armed"
            deadline = time.monotonic() + 5.0
            terminal_zombie_observed = False
            observed_members: list[tuple[int, str]] = []
            while time.monotonic() < deadline:
                observed_members = group_members(provider_pid)
                live_members = [
                    (pid, state)
                    for pid, state in observed_members
                    if not state.startswith("Z")
                ]
                if not live_members:
                    terminal_zombie_observed = bool(observed_members)
                    break
                time.sleep(0.05)
            else:
                try:
                    os.killpg(provider_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raise AssertionError(
                    f"live {label} provider process-group members survived abrupt "
                    f"exact-parent death: {observed_members!r}"
                )
            return provider_pid, terminal_zombie_observed
        finally:
            os.close(held_writer)
            if launch_writer >= 0:
                os.close(launch_writer)
            if helper.poll() is None:
                helper.kill()
                helper.wait(timeout=5)
            if provider_pid is not None:
                live_members = [
                    (pid, state)
                    for pid, state in group_members(provider_pid)
                    if not state.startswith("Z")
                ]
                if live_members:
                    try:
                        os.killpg(provider_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    armed_pid, armed_zombie = run_case(delayed_start=False)
    prearm_pid, prearm_zombie = run_case(delayed_start=True)
    return {
        "parent_death_armed_provider_pid": armed_pid,
        "parent_death_armed_group_terminated": True,
        "parent_death_armed_terminal_zombie_observed": armed_zombie,
        "parent_death_prearm_provider_pid": prearm_pid,
        "parent_death_prearm_group_terminated": True,
        "parent_death_prearm_terminal_zombie_observed": prearm_zombie,
        "parent_death_stdin_writer_remained_open": True,
    }


def run_workspace_input_drift(
    binary: Path,
    binary_arguments: list[str],
    identity: dict[str, str],
    scratch_root: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix="h00-ra-provider-workspace-input.", dir=scratch_root
    ) as directory:
        root = Path(directory).resolve()
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="workspace-input-contract"\nversion="0.1.0"\n'
            'edition="2024"\nbuild="build.rs"\n\n[workspace]\n'
        )
        build_script = (
            b'fn main() {\n'
            b'    println!("cargo:rerun-if-changed=selector.txt");\n'
            b'    let selected = std::fs::read_to_string("selector.txt").unwrap();\n'
            b'    let out = std::env::var_os("OUT_DIR").unwrap();\n'
            b'    std::fs::write(std::path::Path::new(&out).join("generated.rs"), '
            b'format!("pub use crate::{} as selected;\\n", selected.trim())).unwrap();\n'
            b'}\n'
        )
        source = (
            b"pub fn target_a() {}\n"
            b"pub fn target_b() {}\n"
            b'include!(concat!(env!("OUT_DIR"), "/generated.rs"));\n'
            b"pub fn caller() { selected(); }\n"
        )
        (root / "build.rs").write_bytes(build_script)
        (root / "selector.txt").write_text("target_a\n")
        (root / "src/lib.rs").write_bytes(source)
        sources = [
            {
                "document_path": "build.rs",
                "language": "rust",
                "content_identity": "build-script-v1",
                "content_sha256": sha256(build_script),
            },
            {
                "document_path": "src/lib.rs",
                "language": "rust",
                "content_identity": "source-v1",
                "content_sha256": sha256(source),
            },
        ]
        authority = {
            "session_id": "workspace-input-drift",
            "root_sha256": sha256(str(root).encode()),
            "root_topology_sha256": sha256(b"workspace-input-topology"),
            "configuration_sha256": "0" * 64,
            "workspace_resolution_sha256": None,
            "semantic_inputs_sha256": None,
            "population_sha256": population_sha256(sources),
            "source_epoch": 1,
        }
        provider = Provider(
            binary,
            binary_arguments,
            identity,
            "workspace-input-drift",
            root,
            {**RUNTIME_TOOLCHAIN_ENVIRONMENT, "CARGO_TARGET_DIR": str(root / "cargo-target")},
        )
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            authority["configuration_sha256"] = hello["body"]["runtime_configuration"][
                "configuration_sha256"
            ]
            opened, _ = provider.call(
                2,
                {
                    "operation": "open_session",
                    "repository_root": str(root),
                    "execution_root": str(root),
                    "execution_prefix": "",
                    "authority": authority,
                    "sources": sources,
                },
            )
            if opened["body"].get("result") != "session_opened":
                raise AssertionError(f"workspace-input session did not open: {opened}")
            semantic_paths = opened["body"]["semantic_inputs"]["paths"]
            if [item["path"] for item in semantic_paths] != ["selector.txt"]:
                raise AssertionError(
                    "provider did not publish the exact durable build-input population: "
                    f"{semantic_paths}"
                )
            (root / "selector.txt").write_text("target_b\n")
            drift, _ = provider.call(3, {"operation": "hello"})
            body = drift["body"]
            if (
                body.get("result") != "error"
                or body.get("code") != "request_failed"
                or "workspace build inputs changed" not in str(body.get("message"))
            ):
                raise AssertionError(
                    "Cargo-declared workspace input drift did not fail for the intended reason: "
                    f"{body}"
                )
            closed, _ = provider.call(4, {"operation": "close_session"})
            code, stderr, owned = provider.finish()
        finally:
            provider.terminate()
        if closed["body"].get("result") != "session_closed" or code != 0 or stderr:
            raise AssertionError(
                f"workspace-input provider close was not clean: exit={code}, stderr={stderr!r}"
            )
        return {
            "workspace_input_drift_error": body["code"],
            "workspace_input_drift_failed_closed": True,
            "workspace_input_owned_descendants_reaped": len(owned),
        }


def run_lifecycle(
    binary: Path,
    binary_arguments: list[str],
    identity: dict[str, str],
    scratch_root: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="h00-ra-provider-test.", dir=scratch_root) as directory:
        root = Path(directory).resolve()
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="provider-contract"\nversion="0.1.0"\nedition="2024"\n'
            '\n[workspace]\n'
        )
        before = (
            b"pub fn alpha() -> usize { 1 }\n"
            b"pub fn beta() -> usize { 2 }\n"
            b"pub fn caller() -> usize { alpha() }\n"
        )
        after = before.replace(b"alpha() }", b"beta() }")
        source_path = root / "src/lib.rs"
        source_path.write_bytes(before)

        source_v1 = {
            "document_path": "src/lib.rs",
            "language": "rust",
            "content_identity": "source-v1",
            "content_sha256": sha256(before),
        }
        authority_v1 = {
            "session_id": "installed-contract",
            "root_sha256": sha256(str(root).encode()),
            "root_topology_sha256": sha256(b"topology-v1"),
            "configuration_sha256": "0" * 64,
            "workspace_resolution_sha256": None,
            "semantic_inputs_sha256": None,
            "population_sha256": population_sha256([source_v1]),
            "source_epoch": 1,
        }
        source_v2 = {
            **source_v1,
            "content_identity": "source-v2",
            "content_sha256": sha256(after),
        }
        authority_v2 = {
            **authority_v1,
            "population_sha256": population_sha256([source_v2]),
            "source_epoch": 2,
        }
        parent_snapshot_sha256 = sha256(b"canonical-parent-v1")
        provider = Provider(binary, binary_arguments, identity, "installed-contract", root)
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            runtime_configuration = hello["body"]["runtime_configuration"]
            authority_v1["configuration_sha256"] = runtime_configuration[
                "configuration_sha256"
            ]
            authority_v2["configuration_sha256"] = runtime_configuration[
                "configuration_sha256"
            ]
            replay, _ = provider.call(1, {"operation": "hello"})
            wrong_identity = {**identity, "executable_sha256": "0" * 64}
            wrong_provider, _ = provider.call(
                2, {"operation": "hello"}, expected_provider=wrong_identity
            )
            opened, _ = provider.call(
                3,
                {
                    "operation": "open_session",
                    "repository_root": str(root),
                    "execution_root": str(root),
                    "execution_prefix": "",
                    "authority": authority_v1,
                    "sources": [source_v1],
                },
            )
            resolved_authority = opened["body"]["authority"]
            if not resolved_authority.get("workspace_resolution_sha256"):
                raise AssertionError("provider did not bind the resolved Cargo workspace graph")
            if not resolved_authority.get("semantic_inputs_sha256"):
                raise AssertionError("provider did not bind durable semantic inputs")
            authority_v1 = resolved_authority
            authority_v2 = {
                **authority_v1,
                "population_sha256": population_sha256([source_v2]),
                "source_epoch": 2,
            }
            foreign_authority = {**authority_v1, "session_id": "foreign-session"}
            foreign, _ = provider.call(
                4,
                {
                    "operation": "certify_full",
                    "authority": foreign_authority,
                    "analyses": [],
                },
                session_id="foreign-session",
            )
            first, first_attachments = provider.call(
                5,
                {
                    "operation": "certify_full",
                    "authority": authority_v1,
                    "analyses": [],
                },
            )
            stale, _ = provider.call(
                6,
                {
                    "operation": "apply_epoch",
                    "previous_authority": authority_v1,
                    "next_authority": {**authority_v2, "source_epoch": 1},
                    "changes": [
                        {
                            "outcome": "replace",
                            "document_path": "src/lib.rs",
                            "language": "rust",
                            "previous_content_identity": "source-v1",
                            "previous_content_sha256": sha256(before),
                            "content_identity": "source-v2",
                            "content_sha256": sha256(after),
                            "attachment_index": 0,
                        }
                    ],
                },
                [after],
            )
            second, second_attachments = provider.call(
                7,
                {
                    "operation": "refresh_affected",
                    "previous_authority": authority_v1,
                    "next_authority": authority_v2,
                    "changes": [
                        {
                            "outcome": "replace",
                            "document_path": "src/lib.rs",
                            "language": "rust",
                            "previous_content_identity": "source-v1",
                            "previous_content_sha256": sha256(before),
                            "content_identity": "source-v2",
                            "content_sha256": sha256(after),
                            "attachment_index": 0,
                        }
                    ],
                    "parent_snapshot_sha256": parent_snapshot_sha256,
                    "documents": ["src/lib.rs"],
                    "analyses": [],
                },
                [after],
            )
            old_epoch, _ = provider.call(
                8,
                {
                    "operation": "certify_full",
                    "authority": authority_v1,
                    "analyses": [],
                },
            )
            full, full_attachments = provider.call(
                10,
                {
                    "operation": "certify_full",
                    "authority": authority_v2,
                    "analyses": [],
                },
            )
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text(
                '[build]\ntarget-dir = "changed-after-admission"\n'
            )
            workspace_drift, _ = provider.call(
                11,
                {
                    "operation": "certify_full",
                    "authority": authority_v2,
                    "analyses": [],
                },
            )
            closed, _ = provider.call(12, {"operation": "close_session"})
            code, stderr, owned = provider.finish()
        finally:
            provider.terminate()

        health = opened["body"]["health"]
        if not (
            health == second["body"]["health"]
            and health["components"]
            == {
                "build_scripts": "healthy",
                "proc_macros": "healthy",
                "workspace_model": "healthy",
            }
            and health["diagnostics_complete"] is True
            and not health["degradation_reasons"]
        ):
            raise AssertionError(f"provider did not establish Complete health: {health}")
        if first["body"]["result"] != "full_certification":
            raise AssertionError("initial full certification did not succeed")
        if second["body"]["result"] != "affected_refreshed":
            raise AssertionError("updated affected refresh did not succeed")
        if second["body"].get("runtime_configuration") != hello["body"].get(
            "runtime_configuration"
        ):
            raise AssertionError("updated affected refresh omitted its runtime witness")
        if full["body"]["result"] != "full_certification":
            raise AssertionError("full certification did not succeed")
        if error_code(workspace_drift) != "request_failed":
            raise AssertionError("workspace-control drift did not invalidate the warm session")
        if len(first_attachments) != 1 or len(second_attachments) != 1:
            raise AssertionError("provider did not produce one canonical document")
        if first_attachments == second_attachments:
            raise AssertionError("in-memory source epoch did not change canonical provider output")
        if second_attachments != full_attachments:
            raise AssertionError("affected refresh differs from full certification after the epoch")
        if source_path.read_bytes() != before:
            raise AssertionError("provider mutated repository source bytes")
        if (root / "Cargo.lock").exists():
            raise AssertionError("provider created a Cargo.lock in a lockfile-free library")
        if code != 0 or stderr:
            raise AssertionError(f"provider close was not clean: exit={code}, stderr={stderr!r}")
        if closed["body"]["result"] != "session_closed":
            raise AssertionError("provider did not return terminal close receipt")
        return {
            "hello": hello["body"]["result"],
            "replay_error": error_code(replay),
            "wrong_provider_error": error_code(wrong_provider),
            "foreign_session_error": error_code(foreign),
            "stale_epoch_error": error_code(stale),
            "old_authority_error": error_code(old_epoch),
            "workspace_configuration_drift_error": error_code(workspace_drift),
            "affected_changed": True,
            "affected_equals_full": True,
            "source_bytes_unchanged": True,
            "lockfile_free_root_unchanged": True,
            "owned_descendants_reaped": len(owned),
            "terminal_exit": code,
        }


def run_parallel_certification_equivalence(
    binary: Path,
    binary_arguments: list[str],
    identity: dict[str, str],
    scratch_root: Path,
) -> dict[str, object]:
    """Prove parallel exact-file export is deterministic at the installed boundary."""
    with tempfile.TemporaryDirectory(
        prefix="h00-ra-provider-parallel-certification.", dir=scratch_root
    ) as directory:
        root = Path(directory).resolve()
        (root / "Cargo.toml").write_text(
            '[workspace]\nmembers=["dep","main","other"]\nresolver="3"\n'
        )
        for member in ("dep", "main", "other"):
            member_root = root / member
            (member_root / "src").mkdir(parents=True)
            dependency = (
                '\n[dependencies]\ndep={path="../dep"}\n'
                if member != "dep"
                else ""
            )
            (member_root / "Cargo.toml").write_text(
                f'[package]\nname="{member}"\nversion="0.1.0"\nedition="2024"\n'
                f"{dependency}"
            )
        fixture = {
            "dep/src/lib.rs": (
                b"pub struct Thing;\n"
                b"impl Thing { pub fn value(&self) -> usize { 7 } }\n"
                b"pub fn make() -> Thing { Thing }\n"
            ),
            "main/src/lib.rs": (
                b"use dep::{make, Thing};\n"
                b"pub fn consume(value: &Thing) -> usize { value.value() }\n"
                b"pub fn drive() -> usize { let value = make(); consume(&value) }\n"
            ),
            "other/src/lib.rs": (
                b"use dep::{make, Thing};\n"
                b"pub fn inspect(value: &Thing) -> usize { value.value() }\n"
                b"pub fn run() -> usize { let value = make(); inspect(&value) }\n"
            ),
        }
        sources = []
        for ordinal, (document_path, contents) in enumerate(sorted(fixture.items()), start=1):
            (root / document_path).write_bytes(contents)
            sources.append(
                {
                    "document_path": document_path,
                    "language": "rust",
                    "content_identity": f"parallel-source-{ordinal}",
                    "content_sha256": sha256(contents),
                }
            )
        authority = {
            "session_id": "parallel-certification-contract",
            "root_sha256": sha256(str(root).encode()),
            "root_topology_sha256": sha256(b"parallel-certification-topology"),
            "configuration_sha256": "0" * 64,
            "workspace_resolution_sha256": None,
            "semantic_inputs_sha256": None,
            "population_sha256": population_sha256(sources),
            "source_epoch": 1,
        }
        documents = sorted(fixture)
        provider = Provider(
            binary,
            binary_arguments,
            identity,
            "parallel-certification-contract",
            root,
        )
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            authority["configuration_sha256"] = hello["body"]["runtime_configuration"][
                "configuration_sha256"
            ]
            opened, _ = provider.call(
                2,
                {
                    "operation": "open_session",
                    "repository_root": str(root),
                    "execution_root": str(root),
                    "execution_prefix": "",
                    "authority": authority,
                    "sources": sources,
                },
            )
            if opened["body"].get("result") != "session_opened":
                raise AssertionError(f"parallel export session did not open: {opened}")
            authority = opened["body"]["authority"]

            baseline: list[bytes] | None = None
            aggregate_sha256: str | None = None
            for repetition in range(8):
                first, first_attachments = provider.call(
                    3 + repetition * 2,
                    {
                        "operation": "certify_full",
                        "authority": authority,
                        "analyses": [],
                    },
                )
                second, second_attachments = provider.call(
                    4 + repetition * 2,
                    {
                        "operation": "certify_full",
                        "authority": authority,
                        "analyses": [],
                    },
                )
                if first["body"].get("result") != "full_certification":
                    raise AssertionError("first parallel full certification did not succeed")
                if second["body"].get("result") != "full_certification":
                    raise AssertionError("second parallel full certification did not succeed")
                if first_attachments != second_attachments:
                    raise AssertionError(
                        "repeated parallel full certifications produced different bytes"
                    )
                if len(first_attachments) != len(documents):
                    raise AssertionError(
                        "parallel certification did not produce the complete document population"
                    )
                outcomes = first["body"].get("outcomes")
                if not isinstance(outcomes, list) or [
                    outcome.get("document_path") for outcome in outcomes
                ] != documents:
                    raise AssertionError(
                        f"parallel certification outcome ordering is not canonical: {outcomes}"
                    )
                for outcome, attachment in zip(outcomes, first_attachments, strict=True):
                    if outcome.get("outcome") != "present":
                        raise AssertionError(f"parallel certification omitted a control: {outcome}")
                    if outcome.get("canonical_document_sha256") != sha256(attachment):
                        raise AssertionError(
                            "parallel certification receipt does not bind its attachment bytes"
                        )
                current_sha256 = sha256(b"".join(first_attachments))
                if baseline is None:
                    baseline = first_attachments
                    aggregate_sha256 = current_sha256
                elif first_attachments != baseline or current_sha256 != aggregate_sha256:
                    raise AssertionError(
                        "parallel full certification is nondeterministic across repetitions"
                    )

            closed, _ = provider.call(19, {"operation": "close_session"})
            code, stderr, owned = provider.finish()
        finally:
            provider.terminate()
        if closed["body"].get("result") != "session_closed" or code != 0 or stderr:
            raise AssertionError(
                f"parallel export provider close was not clean: exit={code}, stderr={stderr!r}"
            )
        return {
            "parallel_certification_documents": len(documents),
            "parallel_certification_repetitions": 8,
            "parallel_certification_aggregate_sha256": aggregate_sha256,
            "parallel_certification_repeated_equal": True,
            "parallel_certification_owned_descendants_reaped": len(owned),
        }


def run_subset_inherent_impl_equivalence(
    binary: Path,
    binary_arguments: list[str],
    identity: dict[str, str],
    scratch_root: Path,
) -> dict[str, object]:
    """Require exact documents to be independent of the requested population."""
    with tempfile.TemporaryDirectory(
        prefix="h00-ra-provider-inherent-impl.", dir=scratch_root
    ) as directory:
        root = Path(directory).resolve()
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="inherent-impl-contract"\nversion="0.1.0"\n'
            'edition="2024"\n\n[workspace]\n'
        )
        fixture = {
            "src/lib.rs": b"mod a;\nmod b;\npub struct Shared;\n",
            "src/a.rs": (
                b"impl crate::Shared {\n"
                b"    pub fn from_a(&self) -> Self { Self }\n"
                b"}\n"
                b"impl crate::Shared {\n"
                b"    pub fn also_a(&self) -> Self { Self }\n"
                b"}\n"
            ),
            "src/b.rs": (
                b"impl crate::Shared {\n"
                b"    pub fn from_b(&self) -> Self { Self }\n"
                b"}\n"
            ),
        }
        sources = []
        for ordinal, (document_path, contents) in enumerate(
            sorted(fixture.items()), start=1
        ):
            (root / document_path).write_bytes(contents)
            sources.append(
                {
                    "document_path": document_path,
                    "language": "rust",
                    "content_identity": f"inherent-impl-source-{ordinal}",
                    "content_sha256": sha256(contents),
                }
            )
        authority = {
            "session_id": "inherent-impl-contract",
            "root_sha256": sha256(str(root).encode()),
            "root_topology_sha256": sha256(b"inherent-impl-topology"),
            "configuration_sha256": "0" * 64,
            "workspace_resolution_sha256": None,
            "semantic_inputs_sha256": None,
            "population_sha256": population_sha256(sources),
            "source_epoch": 1,
        }
        provider = Provider(
            binary,
            binary_arguments,
            identity,
            "inherent-impl-contract",
            root,
        )
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            authority["configuration_sha256"] = hello["body"][
                "runtime_configuration"
            ]["configuration_sha256"]
            opened, _ = provider.call(
                2,
                {
                    "operation": "open_session",
                    "repository_root": str(root),
                    "execution_root": str(root),
                    "execution_prefix": "",
                    "authority": authority,
                    "sources": sources,
                },
            )
            authority = opened["body"]["authority"]
            full, _ = provider.call(
                3,
                {
                    "operation": "certify_full",
                    "authority": authority,
                    "analyses": [],
                },
            )
            comparisons: dict[str, bool] = {}
            subset_documents: dict[str, bytes] = {}
            source_by_path = {source["document_path"]: source for source in sources}
            for ordinal, document_path in enumerate(("src/a.rs", "src/b.rs")):
                request_id = 4 + ordinal * 2
                previous_source = source_by_path[document_path]
                updated_bytes = fixture[document_path] + f"// refresh {ordinal}\n".encode()
                updated_source = {
                    "document_path": document_path,
                    "language": "rust",
                    "content_identity": f"inherent-impl-refresh-{ordinal}",
                    "content_sha256": sha256(updated_bytes),
                }
                next_sources = [
                    updated_source if source["document_path"] == document_path else source
                    for source in sources
                ]
                next_authority = {
                    **authority,
                    "population_sha256": population_sha256(next_sources),
                    "source_epoch": authority["source_epoch"] + 1,
                }
                affected, affected_attachments = provider.call(
                    request_id,
                    {
                        "operation": "refresh_affected",
                        "previous_authority": authority,
                        "next_authority": next_authority,
                        "changes": [
                            {
                                "outcome": "replace",
                                "document_path": document_path,
                                "language": "rust",
                                "previous_content_identity": previous_source[
                                    "content_identity"
                                ],
                                "previous_content_sha256": previous_source[
                                    "content_sha256"
                                ],
                                "content_identity": updated_source["content_identity"],
                                "content_sha256": updated_source["content_sha256"],
                                "attachment_index": 0,
                            }
                        ],
                        "parent_snapshot_sha256": sha256(b"inherent-impl-parent"),
                        "documents": [document_path],
                        "analyses": [],
                    },
                    [updated_bytes],
                )
                authority = next_authority
                sources = next_sources
                source_by_path[document_path] = updated_source
                current_full, current_full_attachments = provider.call(
                    request_id + 1,
                    {
                        "operation": "certify_full",
                        "authority": authority,
                        "analyses": [],
                    },
                )
                current_full_documents = {
                    outcome["document_path"]: current_full_attachments[
                        outcome["attachment_index"]
                    ]
                    for outcome in current_full["body"].get("outcomes", [])
                    if outcome.get("outcome") == "present"
                }
                outcomes = affected["body"].get("outcomes", [])
                if (
                    affected["body"].get("result") != "affected_refreshed"
                    or len(outcomes) != 1
                    or outcomes[0].get("outcome") != "present"
                    or len(affected_attachments) != 1
                    or current_full["body"].get("result") != "full_certification"
                    or document_path not in current_full_documents
                ):
                    raise AssertionError(
                        f"inherent impl control did not emit {document_path}: {affected}"
                    )
                subset_documents[document_path] = affected_attachments[0]
                comparisons[document_path] = (
                    affected_attachments[0] == current_full_documents[document_path]
                )
            closed, _ = provider.call(8, {"operation": "close_session"})
            code, stderr, owned = provider.finish()
        finally:
            provider.terminate()

        if full["body"].get("result") != "full_certification":
            raise AssertionError("inherent impl full certification did not succeed")
        common_nonlocal_symbols = sorted(
            symbol
            for symbol in (
                set(scip_document_symbols(subset_documents["src/a.rs"]))
                & set(scip_document_symbols(subset_documents["src/b.rs"]))
            )
            if not symbol.startswith("local ")
        )
        if common_nonlocal_symbols:
            raise AssertionError(
                "split Rust modules unexpectedly share non-local symbol identity: "
                f"{common_nonlocal_symbols!r}"
            )
        inherent_symbols: dict[str, list[str]] = {}
        for document_path, document in subset_documents.items():
            inherent_symbols[document_path] = [
                symbol
                for symbol in scip_document_symbols(document)
                if "impl#[" in symbol and symbol.endswith("]")
            ]
        if any(len(symbols) != 1 for symbols in inherent_symbols.values()):
            raise AssertionError(
                "each split module must emit one module-qualified inherent symbol: "
                f"{inherent_symbols!r}"
            )
        a_inherent = inherent_symbols["src/a.rs"][0]
        a_occurrence_count = scip_document_occurrence_symbols(
            subset_documents["src/a.rs"]
        ).count(a_inherent)
        if a_occurrence_count < 2:
            raise AssertionError(
                "same-document inherent dedup positive did not fire: "
                f"symbol={a_inherent!r}, occurrences={a_occurrence_count}"
            )
        if not all(comparisons.values()):
            divergent = sorted(path for path, equal in comparisons.items() if not equal)
            raise AssertionError(
                "subset exact document depends on the requested population for "
                f"duplicate inherent impls: {divergent}"
            )
        if closed["body"].get("result") != "session_closed" or code != 0 or stderr:
            raise AssertionError(
                "inherent impl provider close was not clean: "
                f"exit={code}, stderr={stderr!r}"
            )
        return {
            "subset_inherent_impl_documents": len(comparisons),
            "subset_inherent_impl_module_qualified_symbols": sum(
                len(symbols) for symbols in inherent_symbols.values()
            ),
            "subset_inherent_impl_same_document_occurrences": a_occurrence_count,
            "subset_inherent_impl_full_equal": True,
            "subset_inherent_impl_owned_descendants_reaped": len(owned),
        }


def run_malformed_frame(binary: Path, binary_arguments: list[str]) -> dict[str, object]:
    process = subprocess.Popen(
        [str(binary), *binary_arguments],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env={
            **os.environ,
            "H00_RESOLVED_TOOLCHAIN_SHA256": RESOLVED_TOOLCHAIN_SHA256,
            "H00_RUST_SEMANTIC_PROFILE": RUST_SEMANTIC_PROFILE,
            **RUNTIME_TOOLCHAIN_ENVIRONMENT,
            "H00_PROVIDER_PARENT_PID": str(os.getpid()),
        },
    )
    try:
        process.stdin.write(FRAME_MAGIC + struct.pack(">III", 0xFFFFFFFF, 0, 0))
        process.stdin.close()
        code = process.wait(timeout=10)
        stderr = process.stderr.read().decode(errors="replace")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    if code == 0 or "frame" not in stderr.lower():
        raise AssertionError(
            f"oversized declared frame did not fail closed: exit={code}, stderr={stderr!r}"
        )
    return {"oversized_frame_exit": code, "oversized_frame_failed_closed": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-arg", action="append", default=[])
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--receipt", type=Path)
    identity.add_argument("--patch-sha256")
    parser.add_argument("--scratch-root", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--parent-death-only", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve(strict=True)
    binary_sha = sha256(binary.read_bytes())
    if args.receipt is not None:
        receipt = json.loads(args.receipt.resolve(strict=True).read_text())
        if receipt.get("schema") != "h00/rust-semantic-provider-build/v2":
            raise AssertionError("provider build receipt schema mismatch")
        if receipt.get("binary_sha256") != binary_sha:
            raise AssertionError("provider binary differs from its build receipt")
        if receipt.get("upstream_commit") != UPSTREAM_COMMIT:
            raise AssertionError("provider upstream identity mismatch")
        if receipt.get("protocol") != PROTOCOL:
            raise AssertionError("provider build receipt protocol mismatch")
        patch_sha = receipt.get("patch_sha256")
    else:
        patch_sha = args.patch_sha256
    if not isinstance(patch_sha, str) or len(patch_sha) != 64:
        raise AssertionError("provider patch identity is invalid")
    if any(character not in "0123456789abcdef" for character in patch_sha):
        raise AssertionError("provider patch identity is not lowercase hexadecimal")

    identity = {
        "protocol": PROTOCOL,
        "provider_id": "h00-rust-analyzer-scip",
        "language": "rust",
        "implementation_version": "rust-analyzer-1.97.1/cargo-profile=explicit/cargo-lockfile=private-redirect/workspace-resolution=bound/build-scripts=required/proc-macros=required/runtime-executables=exact/durable-semantic-inputs=v1/v5",
        "source_components": {
            "rust_analyzer": {
                "version": "1.97.1",
                "revision": UPSTREAM_COMMIT,
            }
        },
        "patch_sha256": patch_sha,
        "executable_sha256": binary_sha,
    }
    args.scratch_root.mkdir(parents=True, exist_ok=True)
    parent_death = run_parent_death_guard(binary, args.binary_arg)
    if args.parent_death_only:
        print(
            json.dumps(
                {
                    "schema": "h00/rust-semantic-provider-parent-death-test/v1",
                    "binary_sha256": binary_sha,
                    **parent_death,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    result = {
        "schema": "h00/rust-semantic-provider-installed-test/v1",
        "binary_sha256": binary_sha,
        **parent_death,
        **run_same_path_toolchain_drift(
            binary, args.binary_arg, identity, args.scratch_root
        ),
        **run_workspace_input_drift(
            binary, args.binary_arg, identity, args.scratch_root
        ),
        **run_lifecycle(binary, args.binary_arg, identity, args.scratch_root),
        **run_parallel_certification_equivalence(
            binary, args.binary_arg, identity, args.scratch_root
        ),
        **run_subset_inherent_impl_equivalence(
            binary, args.binary_arg, identity, args.scratch_root
        ),
        **run_malformed_frame(binary, args.binary_arg),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
