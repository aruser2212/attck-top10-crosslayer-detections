"""Strict normalized Sysmon ProcessAccess contract for finite LSASS replay.

The source identifies processes by (host.name, ProcessGUID); PIDs and image names
are supplemental context. A canonical GUID is not a signature or an authenticity
check. Only absolute drive-letter DOS image paths are supported, without device,
UNC, alternate-stream or alias resolution. Their original case is preserved.
Missing source evidence is an input error, never a benign classification.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import string

try:
    from tools.hunt_engine import parse_timestamp, prepare_events as _prepare_events
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp, prepare_events as _prepare_events

PROFILE = "attck-lsass-v1"
DATASET = "windows.sysmon.process_access"
PROVIDER = "Microsoft-Windows-Sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
MAPPING_PATH = Path(__file__).resolve().parents[1] / "profiles/elastic/lsass-v1.mapping.json"
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(2262, 4, 11, 23, 47, 16, 854775, tzinfo=timezone.utc)
UINT32_MAX = 2**32 - 1
UINT64_MAX_TEXT = str(2**64 - 1)
REQUIRED_FIELDS = frozenset({
    "@timestamp", "event.id", "event.dataset", "event.code", "host.name",
    "source.process.guid", "target.process.guid", "source.image", "target.image",
    "process.access_mask",
})
OPTIONAL_FIELDS = frozenset({
    "event.provider", "event.channel", "event.record_id", "event.version",
    "win.timestamp_remainder", "source.process.pid", "target.process.pid",
    "source.user", "target.user", "process.call_trace",
})
ALLOWED_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS
TEXT_FIELDS = frozenset({
    "event.id", "event.dataset", "event.code", "host.name", "source.process.guid",
    "target.process.guid", "source.image", "target.image", "event.provider",
    "event.channel", "event.record_id", "source.user", "target.user", "process.call_trace",
})
_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DOS_DEVICE = re.compile(r"(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³]|conin\$|conout\$)")


def _text(value, field: str) -> str:
    if (not isinstance(value, str) or not value or value != value.strip() or value == "-"
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"{field} requires nonempty trimmed text without controls or '-' placeholders")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{field} must contain valid UTF-8 text") from exc
    if len(encoded) > 32766:
        raise ValueError(f"{field} exceeds the indexed keyword limit of 32766 bytes")
    return value


def canonical_guid(value: str) -> str:
    """Normalize a nonzero Sysmon GUID, without RFC version/variant assumptions."""
    _text(value, "ProcessGUID")
    if value.startswith("{") and value.endswith("}"):
        value = value[1:-1]
    if _GUID.fullmatch(value) is None or not any(char != "0" for char in value.replace("-", "")):
        raise ValueError("ProcessGUID requires a nonzero 8-4-4-4-12 hexadecimal GUID")
    return value.translate(ASCII_LOWER)


def canonical_image(value: str) -> str:
    """Validate a limited DOS image path without changing case or resolving it.

    Validation is lexical. It does not attest the executable, its signature, the
    filesystem target of a symlink, or whether a file named lsass.exe is Windows
    LSASS. Unsupported path namespaces are rejected, not interpreted as benign.
    """
    _text(value, "image path")
    if re.match(r"^[A-Za-z]:\\", value) is None:
        raise ValueError("image path requires an absolute drive-letter DOS path")
    parts = value[3:].split("\\")
    if any(not part or part in {".", ".."} or part.endswith((".", " ")) for part in parts):
        raise ValueError("image path contains empty/dot components or trailing dot/space aliases")
    # Win32 reserves these device stems even when followed by an extension.
    # Windows also treats the ISO-8859-1 superscript digits 1, 2 and 3 as digits
    # in COM/LPT device names. They cannot establish a filesystem image path.
    if any(_DOS_DEVICE.fullmatch(part.split(".", 1)[0].translate(ASCII_LOWER)) for part in parts):
        raise ValueError("image path contains a reserved DOS device alias")
    if any(char in value[3:] for char in '/:<>"|?*'):
        raise ValueError("image path contains an unsupported separator, ADS, wildcard or reserved character")
    return value


def _uint32(value, field: str) -> None:
    if type(value) is not int or not 0 <= value <= UINT32_MAX:
        raise ValueError(f"{field} requires an integer in the unsigned 32-bit range")


def prepare_events(events) -> tuple[list[dict], dict]:
    """Normalize timestamps/deduplicate immutable IDs, then validate every record.

    Literal dotted leaf fields are the only accepted representation. Unknown
    fields, nested objects and scalar/object aliases fail before ingestion. The
    same validation is required after retrieval to detect writes that bypassed
    this profile. Null is allowed only for optional source context.
    """
    unique, counters = _prepare_events(events)
    for event in unique:
        unknown = set(event) - ALLOWED_FIELDS
        missing = REQUIRED_FIELDS - set(event)
        if unknown:
            raise ValueError(f"lsass-v1 unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"lsass-v1 missing required fields: {', '.join(sorted(missing))}")
        if any(isinstance(value, (dict, list, tuple)) for value in event.values()):
            raise ValueError("lsass-v1 requires flat scalar fields, not nested objects/arrays")
        if event["event.dataset"] != DATASET or event["event.code"] != "10":
            raise ValueError("lsass-v1 requires windows.sysmon.process_access event.code '10'")
        if not MIN_TIME <= parse_timestamp(event["@timestamp"]) <= MAX_TIME:
            raise ValueError("lsass-v1 date_nanos range is 1970-01-01 through 2262-04-11T23:47:16.854775Z")
        for field in TEXT_FIELDS & set(event):
            if event[field] is None and field in OPTIONAL_FIELDS:
                continue
            _text(event[field], field)
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ValueError("event.id exceeds Elasticsearch's 512-byte _id limit")
        host = event["host.name"]
        if host.translate(ASCII_LOWER) != host:
            raise ValueError("host.name requires canonical ASCII lowercase")
        for field in ("source.process.guid", "target.process.guid"):
            if canonical_guid(event[field]) != event[field]:
                raise ValueError(f"{field} requires a canonical lowercase GUID without braces")
        for field in ("source.image", "target.image"):
            canonical_image(event[field])
        _uint32(event["process.access_mask"], "process.access_mask")
        for field in ("source.process.pid", "target.process.pid"):
            if event.get(field) is not None:
                _uint32(event[field], field)
        for field, required in (("event.provider", PROVIDER), ("event.channel", CHANNEL)):
            if event.get(field) is not None and event[field] != required:
                raise ValueError(f"{field} must be {required}")
        for field, allowed in (("event.version", {3}), ("win.timestamp_remainder", set(range(10)))):
            if event.get(field) is not None and (type(event[field]) is not int or event[field] not in allowed):
                raise ValueError(f"{field} has an unsupported integer value")
        record = event.get("event.record_id")
        if record is not None and (
            re.fullmatch(r"0|[1-9][0-9]*", record) is None
            or len(record) > len(UINT64_MAX_TEXT)
            or (len(record) == len(UINT64_MAX_TEXT) and record > UINT64_MAX_TEXT)
        ):
            raise ValueError("event.record_id requires canonical unsigned 64-bit decimal text")
    return unique, counters
