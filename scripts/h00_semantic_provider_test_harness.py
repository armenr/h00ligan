#!/usr/bin/env python3
"""Language-neutral process harness for installed semantic-provider tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import time


SOURCE_POPULATION_SCHEMA = b"h00/semantic-provider/source-population/v1\0"
FRAME_MAGIC = b"H00SP15\0"
MAX_FRAME_BYTES = 128 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise AssertionError("truncated protobuf varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise AssertionError("oversized protobuf varint")


def protobuf_length_delimited_fields(data: bytes, field_number: int) -> list[bytes]:
    """Read one repeated length-delimited field without generated SCIP bindings."""
    values = []
    offset = 0
    while offset < len(data):
        key, offset = protobuf_varint(data, offset)
        number = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            _, offset = protobuf_varint(data, offset)
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            length, offset = protobuf_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise AssertionError("truncated protobuf length-delimited field")
            if number == field_number:
                values.append(data[offset:end])
            offset = end
        elif wire_type == 5:
            offset += 4
        else:
            raise AssertionError(f"unsupported protobuf wire type {wire_type}")
        if offset > len(data):
            raise AssertionError("truncated protobuf fixed-width field")
    return values


def scip_document_symbols(document: bytes) -> list[str]:
    symbols = []
    for information in protobuf_length_delimited_fields(document, 3):
        encoded = protobuf_length_delimited_fields(information, 1)
        if len(encoded) != 1:
            raise AssertionError("SCIP SymbolInformation has no unique symbol identity")
        symbols.append(encoded[0].decode())
    return symbols


def scip_document_occurrence_symbols(document: bytes) -> list[str]:
    symbols = []
    for occurrence in protobuf_length_delimited_fields(document, 2):
        encoded = protobuf_length_delimited_fields(occurrence, 2)
        if len(encoded) > 1:
            raise AssertionError("SCIP Occurrence has multiple symbol identities")
        if encoded:
            symbols.append(encoded[0].decode())
    return symbols


def _hash_field(hasher: object, value: bytes) -> None:
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)


def population_sha256(sources: list[dict[str, object]]) -> str:
    hasher = hashlib.sha256()
    _hash_field(hasher, SOURCE_POPULATION_SCHEMA)
    for source in sorted(sources, key=lambda item: str(item["document_path"])):
        for key in ("document_path", "language", "content_identity", "content_sha256"):
            _hash_field(hasher, str(source[key]).encode())
    return hasher.hexdigest()


def encode_frame(
    metadata: dict[str, object], attachments: list[bytes] | tuple[()] = ()
) -> bytes:
    encoded_metadata = json.dumps(metadata, separators=(",", ":")).encode()
    payload = encoded_metadata + b"".join(
        struct.pack(">I", len(attachment)) + attachment for attachment in attachments
    )
    return (
        FRAME_MAGIC
        + struct.pack(">III", len(payload), len(encoded_metadata), len(attachments))
        + payload
    )


def _read_exact(fd: int, length: int, deadline: float) -> bytes:
    output = bytearray()
    while len(output) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise TimeoutError(f"provider frame timed out after {len(output)}/{length} bytes")
        chunk = os.read(fd, length - len(output))
        if not chunk:
            raise EOFError(f"provider frame ended after {len(output)}/{length} bytes")
        output.extend(chunk)
    return bytes(output)


def read_frame(
    process: subprocess.Popen[bytes], timeout: float = 60.0
) -> tuple[dict, list[bytes]]:
    deadline = time.monotonic() + timeout
    if process.stdout is None:
        raise AssertionError("provider stdout is unavailable")
    header = _read_exact(process.stdout.fileno(), 20, deadline)
    if header[:8] != FRAME_MAGIC:
        raise AssertionError("provider response has invalid frame magic")
    payload_len, metadata_len, attachment_count = struct.unpack(">III", header[8:])
    if payload_len + 20 > MAX_FRAME_BYTES:
        raise AssertionError("provider response exceeds the negotiated frame bound")
    payload = _read_exact(process.stdout.fileno(), payload_len, deadline)
    metadata = json.loads(payload[:metadata_len])
    cursor = metadata_len
    attachments = []
    for _ in range(attachment_count):
        attachment_len = struct.unpack(">I", payload[cursor : cursor + 4])[0]
        cursor += 4
        attachments.append(payload[cursor : cursor + attachment_len])
        cursor += attachment_len
    if cursor != len(payload):
        raise AssertionError("provider response attachment population is malformed")
    return metadata, attachments


def _descendants(parent: int) -> set[int]:
    listing = subprocess.run(
        ["ps", "-e", "-o", "pid=", "-o", "ppid="],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    children: dict[int, list[int]] = {}
    for line in listing.splitlines():
        pid_text, parent_text = line.split()
        children.setdefault(int(parent_text), []).append(int(pid_text))
    found: set[int] = set()
    pending = list(children.get(parent, []))
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        found.add(pid)
        pending.extend(children.get(pid, []))
    return found


def _assert_gone(process_ids: set[int]) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        live = []
        for process_id in process_ids:
            try:
                os.kill(process_id, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                live.append(process_id)
            else:
                live.append(process_id)
        if not live:
            return
        time.sleep(0.05)
    raise AssertionError(f"provider descendants survived terminal close: {sorted(live)}")


class Provider:
    def __init__(
        self,
        binary: Path,
        binary_arguments: list[str],
        identity: dict[str, object],
        session_id: str,
        working_directory: Path,
        runtime_environment: dict[str, str],
    ) -> None:
        self.identity = identity
        self.session_id = session_id
        self.process = subprocess.Popen(
            [str(binary), *binary_arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            cwd=working_directory,
            env={
                **os.environ,
                **runtime_environment,
                "H00_PROVIDER_PARENT_PID": str(os.getpid()),
            },
        )

    def call(
        self,
        request_id: int,
        body: dict[str, object],
        attachments: list[bytes] | tuple[()] = (),
        *,
        session_id: str | None = None,
        expected_provider: dict[str, object] | None = None,
    ) -> tuple[dict, list[bytes]]:
        request_session = session_id or self.session_id
        request = {
            "request_id": request_id,
            "session_id": request_session,
            "expected_provider": expected_provider or self.identity,
            "body": body,
        }
        if self.process.stdin is None:
            raise AssertionError("provider stdin is unavailable")
        self.process.stdin.write(encode_frame(request, attachments))
        self.process.stdin.flush()
        metadata, response_attachments = read_frame(self.process)
        if metadata["request_id"] != request_id:
            raise AssertionError("provider response request identity mismatch")
        if metadata["session_id"] != request_session:
            raise AssertionError("provider response session identity mismatch")
        if metadata["provider"] != self.identity:
            raise AssertionError("provider response executable identity mismatch")
        return metadata, response_attachments

    def finish(self) -> tuple[int, str, set[int]]:
        owned = _descendants(self.process.pid)
        if self.process.stdin is None or self.process.stderr is None:
            raise AssertionError("provider process pipes are unavailable")
        self.process.stdin.close()
        code = self.process.wait(timeout=10)
        stderr = self.process.stderr.read().decode(errors="replace")
        _assert_gone(owned)
        return code, stderr, owned

    def terminate(self) -> None:
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)


def error_code(response: dict) -> str:
    body = response["body"]
    if body.get("result") != "error":
        raise AssertionError(f"expected provider error terminal, got {body}")
    return str(body["code"])
