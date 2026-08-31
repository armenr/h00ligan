#!/usr/bin/env python3
"""Replace machine-local CycloneDX workspace references with stable package URLs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class NormalizationError(ValueError):
    """The generated SBOM cannot be normalized without losing reference integrity."""


def iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)


def replace_refs(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, list):
        return [replace_refs(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: replace_refs(item, replacements) for key, item in value.items()}
    return value


def normalize_document(document: dict[str, Any], workspace_root: Path) -> dict[str, Any]:
    workspace_file_uri = workspace_root.resolve().as_uri()
    workspace_ref_prefix = f"path+{workspace_file_uri}/"
    metadata_component = document.get("metadata", {}).get("component")
    candidates = [metadata_component, *document.get("components", [])]
    replacements: dict[str, str] = {}
    source_paths: dict[str, str] = {}

    for component in candidates:
        if not isinstance(component, dict):
            continue
        bom_ref = component.get("bom-ref")
        if not isinstance(bom_ref, str) or not bom_ref.startswith(workspace_ref_prefix):
            continue
        source_and_version = bom_ref.removeprefix(workspace_ref_prefix)
        source_path, separator, _version = source_and_version.rpartition("#")
        if (
            not separator
            or not source_path
            or source_path.startswith("/")
            or any(part in {"", ".", ".."} for part in source_path.split("/"))
        ):
            raise NormalizationError(
                f"workspace component {component.get('name')!r} has an invalid source path"
            )
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:cargo/"):
            raise NormalizationError(
                f"workspace component {component.get('name')!r} has no stable Cargo purl"
            )
        purl_without_subpath, subpath_separator, subpath = purl.partition("#")
        canonical_purl, query_separator, qualifiers = purl_without_subpath.partition("?")
        if subpath_separator:
            canonical_purl = f"{canonical_purl}#{subpath}"
        expected_qualifiers = f"download_url={workspace_file_uri}/{source_path}"
        root_qualifiers = "download_url=file://."
        if not query_separator or (
            qualifiers != expected_qualifiers
            and not (component is metadata_component and qualifiers == root_qualifiers)
        ):
            raise NormalizationError(
                f"workspace component {component.get('name')!r} has an unexpected source URL"
            )
        if canonical_purl in source_paths:
            raise NormalizationError("workspace component purls are not unique")
        source_paths[canonical_purl] = source_path
        replacements[bom_ref] = canonical_purl
        replacements[purl] = canonical_purl

    if not replacements:
        raise NormalizationError("SBOM contains no workspace-local component references")

    normalized = replace_refs(document, replacements)
    normalized_components = [
        normalized.get("metadata", {}).get("component"),
        *normalized.get("components", []),
    ]
    for component in normalized_components:
        if not isinstance(component, dict):
            continue
        source_path = source_paths.get(component.get("bom-ref"))
        if source_path is None:
            continue
        properties = component.setdefault("properties", [])
        if not isinstance(properties, list):
            raise NormalizationError(
                f"workspace component {component.get('name')!r} has invalid properties"
            )
        if any(
            isinstance(item, dict)
            and item.get("name") == "h00ligan:source:relative-path"
            for item in properties
        ):
            raise NormalizationError(
                f"workspace component {component.get('name')!r} already declares source provenance"
            )
        properties.append(
            {"name": "h00ligan:source:relative-path", "value": source_path}
        )

    remaining_workspace_refs = [
        value for value in iter_strings(normalized) if workspace_file_uri in value
    ]
    if remaining_workspace_refs:
        raise NormalizationError(
            f"{len(remaining_workspace_refs)} workspace reference(s) were not mapped"
        )
    absolute_file_uris = [
        value for value in iter_strings(normalized) if "file:///" in value
    ]
    if absolute_file_uris:
        raise NormalizationError(
            f"{len(absolute_file_uris)} absolute file URI value(s) remain after normalization"
        )

    known_ref_population = [
        component.get("bom-ref")
        for component in normalized_components
        if isinstance(component, dict) and isinstance(component.get("bom-ref"), str)
    ]
    if len(known_ref_population) != len(set(known_ref_population)):
        raise NormalizationError("normalization produced duplicate component references")
    known_refs = set(known_ref_population)
    dependency_refs: set[str] = set()
    for dependency in normalized.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        ref = dependency.get("ref")
        if isinstance(ref, str):
            dependency_refs.add(ref)
        dependency_refs.update(
            item for item in dependency.get("dependsOn", []) if isinstance(item, str)
        )
    if dangling := sorted(dependency_refs - known_refs):
        raise NormalizationError(
            f"normalization left {len(dangling)} dangling dependency reference(s)"
        )
    return normalized


def self_test() -> None:
    root = Path.cwd() / ".h00ligan-sbom-normalizer-self-test"
    workspace_uri = root.resolve().as_uri()
    local_root = f"path+{workspace_uri}/product#0.2.0"
    local_engine = f"path+{workspace_uri}/source/crates/h00ligan-engine#0.1.0"
    root_purl = "pkg:cargo/h00ligan@0.2.0?download_url=file://.#src/main.rs"
    engine_purl = (
        "pkg:cargo/h00ligan-engine@0.1.0?"
        f"download_url={workspace_uri}/source/crates/h00ligan-engine"
    )
    canonical_root = "pkg:cargo/h00ligan@0.2.0#src/main.rs"
    canonical_engine = "pkg:cargo/h00ligan-engine@0.1.0"
    registry_ref = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
    fixture = {
        "metadata": {
            "component": {
                "name": "h00ligan",
                "bom-ref": local_root,
                "purl": root_purl,
            }
        },
        "components": [
            {"name": "h00ligan-engine", "bom-ref": local_engine, "purl": engine_purl},
            {"name": "serde", "bom-ref": registry_ref},
        ],
        "dependencies": [
            {"ref": local_root, "dependsOn": [local_engine, registry_ref]},
            {"ref": local_engine, "dependsOn": [registry_ref]},
            {"ref": registry_ref, "dependsOn": []},
        ],
    }
    normalized = normalize_document(fixture, root)
    assert normalized["metadata"]["component"]["bom-ref"] == canonical_root
    assert normalized["metadata"]["component"]["purl"] == canonical_root
    assert normalized["components"][0]["bom-ref"] == canonical_engine
    assert normalized["components"][0]["purl"] == canonical_engine
    assert normalized["dependencies"][0]["ref"] == canonical_root
    assert normalized["dependencies"][0]["dependsOn"] == [
        canonical_engine,
        registry_ref,
    ]
    assert normalized["metadata"]["component"]["properties"][-1] == {
        "name": "h00ligan:source:relative-path",
        "value": "product",
    }
    assert not any("file:///" in value for value in iter_strings(normalized))

    broken = json.loads(json.dumps(fixture))
    del broken["components"][0]["purl"]
    try:
        normalize_document(broken, root)
    except NormalizationError as error:
        assert "no stable Cargo purl" in str(error)
    else:
        raise AssertionError("missing-purl canary did not fire")

    mismatched_source = json.loads(json.dumps(fixture))
    mismatched_source["components"][0]["purl"] = (
        "pkg:cargo/h00ligan-engine@0.1.0?download_url=file:///foreign/h00ligan-engine"
    )
    try:
        normalize_document(mismatched_source, root)
    except NormalizationError as error:
        assert "unexpected source URL" in str(error)
    else:
        raise AssertionError("foreign-source canary did not fire")

    duplicate = json.loads(json.dumps(fixture))
    duplicate["components"].append(
        {
            "name": "h00ligan-copy",
            "bom-ref": f"path+{workspace_uri}/duplicate#0.2.0",
            "purl": (
                "pkg:cargo/h00ligan@0.2.0?"
                f"download_url={workspace_uri}/duplicate#src/main.rs"
            ),
        }
    )
    try:
        normalize_document(duplicate, root)
    except NormalizationError as error:
        assert "purls are not unique" in str(error)
    else:
        raise AssertionError("duplicate-identity canary did not fire")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("h00ligan-sbom-normalizer: self-test OK (mapping and rejection canaries fired)")
        return 0
    if args.sbom is None or args.workspace_root is None:
        parser.error("--sbom and --workspace-root are required unless --self-test is used")

    try:
        document = json.loads(args.sbom.read_text(encoding="utf-8"))
        normalized = normalize_document(document, args.workspace_root)
    except (OSError, json.JSONDecodeError, NormalizationError) as error:
        print(f"h00ligan-sbom-normalizer: FAIL: {error}", file=sys.stderr)
        return 1
    args.sbom.write_text(
        json.dumps(normalized, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"h00ligan-sbom-normalizer: OK ({args.sbom})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
