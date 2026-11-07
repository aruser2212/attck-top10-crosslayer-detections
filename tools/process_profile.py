"""Strict Sysmon ProcessCreate source contract for bounded process-rule replay.

Image, parent image and command-line predicate fields are ASCII-only in v1.
Unsupported Unicode is rejected before evaluation, not classified as benign;
this gives the declared Sigma subset and native keyword queries the same case
semantics. Original path/command case and command-line spacing are preserved.
This profile validates an exported observation, not executable authenticity,
command success, remote collection or the meaning of shell arguments.
"""
from __future__ import annotations

from pathlib import Path
import re

try:
    from tools.hunt_engine import parse_timestamp, prepare_events as _prepare_events
    from tools.lsass_profile import (
        ASCII_LOWER, CHANNEL, MAX_TIME, MIN_TIME, PROVIDER, UINT32_MAX,
        UINT64_MAX_TEXT, canonical_guid, canonical_image,
    )
except ModuleNotFoundError:  # Direct invocation by sibling CLI modules.
    from hunt_engine import parse_timestamp, prepare_events as _prepare_events
    from lsass_profile import (
        ASCII_LOWER, CHANNEL, MAX_TIME, MIN_TIME, PROVIDER, UINT32_MAX,
        UINT64_MAX_TEXT, canonical_guid, canonical_image,
    )


PROFILE = "attck-process-v1"
DATASET = "windows.sysmon.process"
MAPPING_PATH = Path(__file__).resolve().parents[1] / "profiles/elastic/process-v1.mapping.json"
REQUIRED_FIELDS = frozenset({
    "@timestamp", "event.id", "event.dataset", "event.code", "host.name",
    "process.guid", "process.parent.guid", "process.executable",
    "process.parent.executable", "process.command_line",
})
OPTIONAL_FIELDS = frozenset({
    "event.provider", "event.channel", "event.record_id", "event.version",
    "win.timestamp_remainder", "process.pid", "process.parent.pid", "user.name",
})
ALLOWED_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS
PREDICATE_FIELDS = frozenset({
    "process.executable", "process.parent.executable", "process.command_line",
})
TEXT_FIELDS = frozenset({
    "event.id", "event.dataset", "event.code", "host.name", "process.guid",
    "process.parent.guid", "process.executable", "process.parent.executable",
    "event.provider", "event.channel", "event.record_id", "user.name",
})


def _text(value, field: str) -> str:
    if (not isinstance(value, str) or not value or value != value.strip() or value == "-"
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"{field} requires nonempty trimmed text without controls or '-' placeholders")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError(f"{field} must contain valid UTF-8 text") from exc
    if length > 32766:
        raise ValueError(f"{field} exceeds the indexed keyword limit of 32766 bytes")
    return value


def _command_line(value) -> None:
    if not isinstance(value, str) or not value.strip(" \t") or value.strip(" \t") == "-":
        raise ValueError("process.command_line requires nonempty command text, not a placeholder")
    if not value.isascii():
        raise ValueError("process.command_line requires ASCII text in process-v1")
    if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
        raise ValueError("process.command_line permits ASCII spaces/tabs but no other controls")
    if len(value) > 32766:
        raise ValueError("process.command_line exceeds the indexed keyword limit of 32766 bytes")


def prepare_events(events) -> tuple[list[dict], dict]:
    """Canonicalize timestamps, validate flat records and deduplicate exact IDs.

    No rule or time filter may precede this validation. Optional context can be
    absent or null; mandatory process identity and predicate fields cannot.
    """
    unique, counters = _prepare_events(events)
    for event in unique:
        unknown = set(event) - ALLOWED_FIELDS
        missing = REQUIRED_FIELDS - set(event)
        if unknown:
            raise ValueError(f"process-v1 unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"process-v1 missing required fields: {', '.join(sorted(missing))}")
        if any(isinstance(value, (dict, list, tuple)) for value in event.values()):
            raise ValueError("process-v1 requires flat scalar fields, not nested objects/arrays")
        if event["event.dataset"] != DATASET or event["event.code"] != "1":
            raise ValueError("process-v1 requires windows.sysmon.process event.code '1'")
        if not MIN_TIME <= parse_timestamp(event["@timestamp"]) <= MAX_TIME:
            raise ValueError("process-v1 date_nanos range is 1970-01-01 through 2262-04-11T23:47:16.854775Z")
        for field in TEXT_FIELDS & set(event):
            if event[field] is None and field in OPTIONAL_FIELDS:
                continue
            _text(event[field], field)
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ValueError("event.id exceeds Elasticsearch's 512-byte _id limit")
        if event["host.name"].translate(ASCII_LOWER) != event["host.name"]:
            raise ValueError("host.name requires canonical ASCII lowercase")
        for field in ("process.guid", "process.parent.guid"):
            if canonical_guid(event[field]) != event[field]:
                raise ValueError(f"{field} requires a canonical lowercase GUID without braces")
        for field in ("process.executable", "process.parent.executable"):
            if not event[field].isascii():
                raise ValueError(f"{field} requires ASCII text in process-v1")
            canonical_image(event[field])
        _command_line(event["process.command_line"])
        for field in ("process.pid", "process.parent.pid"):
            value = event.get(field)
            if value is not None and (type(value) is not int or not 0 <= value <= UINT32_MAX):
                raise ValueError(f"{field} requires an integer in the unsigned 32-bit range")
        for field, required in (("event.provider", PROVIDER), ("event.channel", CHANNEL)):
            if event.get(field) is not None and event[field] != required:
                raise ValueError(f"{field} must be {required}")
        for field, allowed in (("event.version", {5}), ("win.timestamp_remainder", set(range(10)))):
            value = event.get(field)
            if value is not None and (type(value) is not int or value not in allowed):
                raise ValueError(f"{field} has an unsupported integer value")
        record = event.get("event.record_id")
        if record is not None and (
            re.fullmatch(r"0|[1-9][0-9]*", record) is None
            or len(record) > len(UINT64_MAX_TEXT)
            or (len(record) == len(UINT64_MAX_TEXT) and record > UINT64_MAX_TEXT)
        ):
            raise ValueError("event.record_id requires canonical unsigned 64-bit decimal text")
    return unique, counters
