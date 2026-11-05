"""Strict normalized host/file and HTTP contract for finite Basic correlation.

Both sources must identify the same trusted filesystem/workload namespace. A
client-controlled HTTP Host header is not a substitute for resource.namespace.
Paths are already-resolved absolute POSIX paths; no URI, symlink, alias or native
audit-to-write inference is performed here. A successful source write and a
matching HTTP request remain a suspicious candidate, not execution evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

try:
    from tools.correlate_webshell import canonical_path, suspicious_query_keys, validate_event
    from tools.hunt_engine import parse_timestamp, prepare_events as _prepare_events
except ModuleNotFoundError:
    from correlate_webshell import canonical_path, suspicious_query_keys, validate_event
    from hunt_engine import parse_timestamp, prepare_events as _prepare_events

PROFILE = "attck-web-correlation-v1"
DATASETS = ("host.file", "web.access")
MAPPING_PATH = Path(__file__).resolve().parents[1] / "profiles/elastic/web-correlation-v1.mapping.json"
MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(2262, 4, 11, 23, 47, 16, 854775, tzinfo=timezone.utc)
KEYWORD_FIELDS = ("event.id", "event.dataset", "host.id", "resource.namespace",
                  "file.path", "file.operation", "web.resource_path")
MAPPED_OBJECT_FIELDS = frozenset({"event", "host", "resource", "file", "web", "url"})
MAPPED_LEAF_FIELDS = frozenset(KEYWORD_FIELDS) | {"@timestamp", "event.success", "url.query"}
RESERVED_METADATA_FIELDS = frozenset({"_id", "_routing", "_index", "_ignored", "_doc_count"})
# The Hunt field grammar, with nonempty dotted segments. These are source field
# names, not identifiers carried as values; opaque namespace values stay intact.
FIELD_NAME = re.compile(r"[A-Za-z_@][A-Za-z0-9_@-]*(?:\.[A-Za-z0-9_@-]+)*")


def _validate_field_name(field: str) -> None:
    if FIELD_NAME.fullmatch(field) is None:
        raise ValueError("web-correlation-v1 requires valid dotted field names with nonempty segments")
    if field.split(".", 1)[0] in RESERVED_METADATA_FIELDS:
        raise ValueError(f"{field} is reserved Elasticsearch document metadata")
    if field in MAPPED_OBJECT_FIELDS:
        raise ValueError(f"{field} is a mapped object path; use its dotted leaf fields")
    parts = field.split(".")
    for length in range(1, len(parts)):
        ancestor = ".".join(parts[:length])
        if ancestor in MAPPED_LEAF_FIELDS:
            raise ValueError(f"{field} descends below mapped scalar field {ancestor}")


def prepare_events(events) -> tuple[list[dict], dict]:
    """Canonicalize timestamps/deduplicate IDs, then validate every source record.

    Well-formed reads, failed writes and ordinary HTTP queries are admitted as
    noncandidates. Missing required fields and malformed values fail the whole
    batch; they are never interpreted as a negative result or coerced by Elastic.
    This is input preflight, not an atomic bulk-write guarantee: transport failures
    can still leave partial writes, recovered through immutable-event retry.
    """
    unique, counters = _prepare_events(events)
    for event in unique:
        if event["event.dataset"] not in DATASETS:
            raise ValueError("web-correlation-v1 accepts only host.file and web.access datasets")
        if not MIN_TIME <= parse_timestamp(event["@timestamp"]) <= MAX_TIME:
            raise ValueError("web-correlation-v1 date_nanos range is 1970-01-01 through 2262-04-11T23:47:16.854775Z")
        for field, value in event.items():
            _validate_field_name(field)
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("web-correlation-v1 requires flat JSON scalar fields, not nested objects/arrays")
            try:
                field.encode("utf-8")
                if isinstance(value, str):
                    value.encode("utf-8")
            except UnicodeError as exc:
                raise ValueError("web-correlation-v1 requires valid UTF-8 field names and string values") from exc
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ValueError("event.id exceeds Elasticsearch's 512-byte _id limit")
        for field in KEYWORD_FIELDS:
            value = event.get(field)
            if isinstance(value, str) and len(value.encode("utf-8")) > 32766:
                raise ValueError(f"{field} exceeds the 32766-byte indexed keyword limit")
        validate_event(event)
        # All mapped fields retain their types, including when supplied as
        # optional context on the other source. Elastic coercion must not create
        # a different indexed interpretation from the source used by Python.
        for field in ("file.path", "web.resource_path"):
            if event.get(field) is not None:
                canonical_path(event[field], label=field)
        if event.get("file.operation") is not None:
            operation = event["file.operation"]
            if (not isinstance(operation, str) or not operation.strip()
                    or operation != operation.strip()
                    or any(ord(char) < 32 or ord(char) == 127 for char in operation)):
                raise ValueError("file.operation requires a nonempty trimmed scalar string without controls")
        if event.get("event.success") is not None and type(event["event.success"]) is not bool:
            raise ValueError("event.success requires a JSON boolean")
        if event.get("url.query") is not None:
            suspicious_query_keys(event["url.query"])
    return unique, counters
