#!/usr/bin/env python3
"""Installed-boundary lifecycle test for h00ligan's embedded Pyrefly provider."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from h00_semantic_provider_test_harness import (
    Provider,
    error_code,
    population_sha256,
    scip_document_occurrence_symbols,
    scip_document_symbols,
    sha256,
)


PROTOCOL = "h00/semantic-provider/v13"
PROVIDER_ID = "h00-pyrefly-scip"
LANGUAGE = "python"
UPSTREAM_VERSION = "1.2.0"
UPSTREAM_COMMIT = "1933169ad8ee9e4d4114112eb56ef0811fb0a094"
IMPLEMENTATION_VERSION = "pyrefly-1.2.0/h00-semantic-provider-v1"
RESOLVED_TOOLCHAIN_SHA256 = sha256(b"installed-pyrefly-provider-runtime")


def source(document_path: str, identity: str, contents: bytes) -> dict[str, object]:
    return {
        "document_path": document_path,
        "language": LANGUAGE,
        "content_identity": identity,
        "content_sha256": sha256(contents),
    }


def run_lifecycle(
    binary: Path,
    identity: dict[str, object],
    scratch_root: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix="h00-pyrefly-provider.", dir=scratch_root
    ) as directory:
        root = Path(directory).resolve()
        (root / "src/fixture").mkdir(parents=True)
        (root / "pyproject.toml").write_text(
            '[project]\nname = "provider-contract"\nversion = "0.1.0"\n\n'
            '[tool.pyrefly]\nproject_includes = ["src"]\n'
        )
        target = (
            b"def targetA() -> int:\n    return 1\n\n"
            b"def targetB() -> int:\n    return 2\n"
        )
        caller_before = (
            b"from fixture.target import targetA, targetB\n\n"
            b"def caller() -> int:\n    return targetA()\n"
        )
        caller_after = caller_before.replace(b"targetA()\n", b"targetB()\n")
        (root / "src/fixture/__init__.py").write_bytes(b"")
        (root / "src/fixture/target.py").write_bytes(target)
        (root / "src/fixture/caller.py").write_bytes(caller_before)
        sources_v1 = [
            source("src/fixture/__init__.py", "init-v1", b""),
            source("src/fixture/caller.py", "caller-v1", caller_before),
            source("src/fixture/target.py", "target-v1", target),
        ]
        authority_v1 = {
            "session_id": "python-provider-contract",
            "root_sha256": sha256(str(root).encode()),
            "root_topology_sha256": sha256(b"python-topology-v1"),
            "configuration_sha256": "0" * 64,
            "workspace_resolution_sha256": None,
            "semantic_inputs_sha256": None,
            "population_sha256": population_sha256(sources_v1),
            "source_epoch": 1,
        }
        provider = Provider(
            binary,
            [],
            identity,
            "python-provider-contract",
            root,
            {"H00_RESOLVED_TOOLCHAIN_SHA256": RESOLVED_TOOLCHAIN_SHA256},
        )
        descendants: set[int] = set()
        try:
            hello, _ = provider.call(1, {"operation": "hello"})
            if hello["body"].get("result") != "hello":
                raise AssertionError(f"Pyrefly Hello positive control failed: {hello}")
            authority_v1["configuration_sha256"] = hello["body"][
                "runtime_configuration"
            ]["configuration_sha256"]

            replay, _ = provider.call(1, {"operation": "hello"})
            if error_code(replay) != "replayed_request":
                raise AssertionError(f"Pyrefly replay did not fail closed: {replay}")

            opened, _ = provider.call(
                2,
                {
                    "operation": "open_session",
                    "repository_root": str(root),
                    "execution_root": str(root),
                    "execution_prefix": "",
                    "authority": authority_v1,
                    "sources": sources_v1,
                    "expected_semantic_inputs": None,
                },
            )
            if opened["body"].get("result") != "session_opened":
                raise AssertionError(f"Pyrefly session did not open: {opened}")
            health = opened["body"]["health"]
            if health.get("diagnostics_complete") is not True:
                raise AssertionError(f"Pyrefly diagnostics are incomplete: {health}")
            if health.get("degradation_reasons") != []:
                raise AssertionError(f"Pyrefly session is degraded: {health}")
            authority_v1 = opened["body"]["authority"]

            foreign_authority = {**authority_v1, "session_id": "foreign"}
            foreign, _ = provider.call(
                3,
                {
                    "operation": "certify_full",
                    "authority": foreign_authority,
                    "analyses": [],
                },
                session_id="foreign",
            )
            if error_code(foreign) != "request_failed":
                raise AssertionError(f"foreign Pyrefly authority was admitted: {foreign}")

            full_v1, attachments_v1 = provider.call(
                4,
                {
                    "operation": "certify_full",
                    "authority": authority_v1,
                    "analyses": [],
                },
            )
            if full_v1["body"].get("result") != "full_certification":
                raise AssertionError(f"Pyrefly full certification failed: {full_v1}")
            if len(attachments_v1) != 3:
                raise AssertionError("Pyrefly did not export the exact source population")
            by_path_v1 = {
                outcome["document_path"]: attachments_v1[outcome["attachment_index"]]
                for outcome in full_v1["body"]["outcomes"]
            }
            target_a_symbols = [
                symbol
                for symbol in scip_document_symbols(by_path_v1["src/fixture/target.py"])
                if "targetA" in symbol
            ]
            target_b_symbols = [
                symbol
                for symbol in scip_document_symbols(by_path_v1["src/fixture/target.py"])
                if "targetB" in symbol
            ]
            if not target_a_symbols or not target_b_symbols:
                raise AssertionError("Pyrefly target definition controls are empty")
            caller_occurrences = scip_document_occurrence_symbols(
                by_path_v1["src/fixture/caller.py"]
            )
            target_a_occurrences_v1 = sum(
                caller_occurrences.count(symbol) for symbol in target_a_symbols
            )
            target_b_occurrences_v1 = sum(
                caller_occurrences.count(symbol) for symbol in target_b_symbols
            )
            if target_a_occurrences_v1 != 2:
                raise AssertionError(
                    "Pyrefly initial import plus call did not resolve exactly twice to targetA"
                )
            if target_b_occurrences_v1 != 1:
                raise AssertionError("Pyrefly initial targetB import control was not singular")

            caller_v2 = source("src/fixture/caller.py", "caller-v2", caller_after)
            sources_v2 = [sources_v1[0], caller_v2, sources_v1[2]]
            authority_v2 = {
                **authority_v1,
                "population_sha256": population_sha256(sources_v2),
                "source_epoch": 2,
            }
            affected, attachments_v2 = provider.call(
                5,
                {
                    "operation": "refresh_affected",
                    "previous_authority": authority_v1,
                    "next_authority": authority_v2,
                    "changes": [
                        {
                            "outcome": "replace",
                            "document_path": "src/fixture/caller.py",
                            "language": LANGUAGE,
                            "previous_content_identity": "caller-v1",
                            "previous_content_sha256": sha256(caller_before),
                            "content_identity": "caller-v2",
                            "content_sha256": sha256(caller_after),
                            "attachment_index": 0,
                        }
                    ],
                    "parent_snapshot_sha256": hashlib.sha256(b"parent-v1").hexdigest(),
                    "documents": ["src/fixture/caller.py"],
                    "analyses": [],
                },
                [caller_after],
            )
            if affected["body"].get("result") != "affected_refreshed":
                raise AssertionError(f"Pyrefly affected refresh failed: {affected}")
            if affected["body"].get("runtime_configuration") != hello["body"].get(
                "runtime_configuration"
            ):
                raise AssertionError("Pyrefly affected refresh omitted its runtime witness")
            if (
                len(attachments_v2) != 1
                or attachments_v2[0] == by_path_v1["src/fixture/caller.py"]
            ):
                raise AssertionError("Pyrefly persistent epoch did not change semantic output")
            changed_occurrences = scip_document_occurrence_symbols(attachments_v2[0])
            target_a_occurrences_v2 = sum(
                changed_occurrences.count(symbol) for symbol in target_a_symbols
            )
            target_b_occurrences_v2 = sum(
                changed_occurrences.count(symbol) for symbol in target_b_symbols
            )
            if target_a_occurrences_v2 != 1:
                raise AssertionError(
                    "Pyrefly affected refresh retained stale targetA call evidence"
                )
            if target_b_occurrences_v2 != 2:
                raise AssertionError("Pyrefly affected refresh omitted fresh targetB call")
            if (root / "src/fixture/caller.py").read_bytes() != caller_before:
                raise AssertionError("Pyrefly provider modified caller source bytes")
            if (root / "src/fixture/target.py").read_bytes() != target:
                raise AssertionError("Pyrefly provider modified target source bytes")

            stale, _ = provider.call(
                6,
                {
                    "operation": "certify_full",
                    "authority": authority_v1,
                    "analyses": [],
                },
            )
            if error_code(stale) != "request_failed":
                raise AssertionError(f"stale Pyrefly authority was admitted: {stale}")

            closed, _ = provider.call(7, {"operation": "close_session"})
            if closed["body"].get("result") != "session_closed":
                raise AssertionError(f"Pyrefly session did not close: {closed}")
            code, stderr, descendants = provider.finish()
            if code != 0 or stderr:
                raise AssertionError(
                    f"Pyrefly provider terminal state was not clean: {(code, stderr)}"
                )
        finally:
            provider.terminate()

        return {
            "cross_file_reference": True,
            "foreign_session_failed_closed": True,
            "owned_descendants_reaped": len(descendants),
            "persistent_epoch_replaced_call_target": True,
            "replay_failed_closed": True,
            "source_bytes_unchanged": True,
            "stale_authority_failed_closed": True,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    identity_source = parser.add_mutually_exclusive_group(required=True)
    identity_source.add_argument("--receipt", type=Path)
    identity_source.add_argument("--patch-sha256")
    parser.add_argument("--scratch-root", type=Path, default=Path(tempfile.gettempdir()))
    args = parser.parse_args()

    binary = args.binary.resolve(strict=True)
    binary_sha256 = sha256(binary.read_bytes())
    if args.receipt is not None:
        receipt = json.loads(args.receipt.resolve(strict=True).read_text())
        expected_receipt = {
            "schema": "h00/pyrefly-semantic-provider-build/v2",
            "protocol": PROTOCOL,
            "provider_id": PROVIDER_ID,
            "language": LANGUAGE,
            "upstream_version": UPSTREAM_VERSION,
            "upstream_commit": UPSTREAM_COMMIT,
            "binary_sha256": binary_sha256,
        }
        for field, expected in expected_receipt.items():
            if receipt.get(field) != expected:
                raise AssertionError(f"Pyrefly provider receipt mismatch: {field}")
        patch_sha256 = receipt.get("patch_sha256")
    else:
        patch_sha256 = args.patch_sha256
    if not isinstance(patch_sha256, str) or len(patch_sha256) != 64:
        raise AssertionError("Pyrefly provider patch identity is invalid")
    if any(character not in "0123456789abcdef" for character in patch_sha256):
        raise AssertionError("Pyrefly provider patch identity is not lowercase hexadecimal")

    identity = {
        "protocol": PROTOCOL,
        "provider_id": PROVIDER_ID,
        "language": LANGUAGE,
        "implementation_version": IMPLEMENTATION_VERSION,
        "source_components": {
            "pyrefly": {
                "version": UPSTREAM_VERSION,
                "revision": UPSTREAM_COMMIT,
            }
        },
        "patch_sha256": patch_sha256,
        "executable_sha256": binary_sha256,
    }
    args.scratch_root.mkdir(parents=True, exist_ok=True)
    result = {
        "schema": "h00/pyrefly-semantic-provider-installed-test/v1",
        "binary_sha256": binary_sha256,
        **run_lifecycle(binary, identity, args.scratch_root),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
