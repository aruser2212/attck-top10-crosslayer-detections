"""Strict finite Windows 4624/4672 session evidence contract.

Logon IDs are scoped by the observed host and a trusted upstream boot identity.
The local token SID, not account spelling or outbound network credentials, is
the account join key. A profile-valid record is not proof of credential abuse.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import string

try:
    from tools.hunt_engine import parse_timestamp, prepare_events as _prepare_events
    from tools.kerberos_profile import canonical_sid, unsigned_decimal
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp, prepare_events as _prepare_events
    from kerberos_profile import canonical_sid, unsigned_decimal

PROFILE = "attck-newcredentials-v1"
DATASET = "windows.security.sessions"
PROVIDER = "Microsoft-Windows-Security-Auditing"
CHANNEL = "Security"
MAPPING_PATH = Path(__file__).resolve().parents[1] / "profiles/elastic/newcredentials-v1.mapping.json"
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(2262, 4, 11, 23, 47, 16, 854775, tzinfo=timezone.utc)
UINT32_MAX = 2**32 - 1
REQUIRED_FIELDS = frozenset({
    "@timestamp", "event.id", "event.dataset", "event.code", "host.name",
    "host.boot.id", "session.id", "user.id",
})
OPTIONAL_FIELDS = frozenset({
    "event.provider", "event.channel", "event.record_id", "event.version",
    "win.timestamp_remainder", "user.name", "user.domain",
})
LOGON_FIELDS = frozenset({"win.logon_type", "win.logon_process"})
PRIVILEGE_FIELDS = frozenset({"win.privileges"})
TEXT_FIELDS = frozenset({
    "event.id", "event.dataset", "event.code", "host.name", "host.boot.id",
    "session.id", "user.id", "event.provider", "event.channel", "event.record_id",
    "user.name", "user.domain", "win.logon_process",
})


def _text(value, field: str) -> str:
    if (not isinstance(value, str) or not value or value != value.strip() or value == "-"
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError(f"{field} requires nonempty trimmed text without controls or placeholders")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{field} must contain valid UTF-8 text") from exc
    if len(encoded) > 32766:
        raise ValueError(f"{field} exceeds the indexed keyword limit of 32766 bytes")
    return value


def canonical_logon_id(value: str) -> str:
    """Normalize a nonzero native decimal/hex uint64 LUID without guessing scope."""
    _text(value, "LogonId")
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        digits = value[2:].lstrip("0") or "0"
        if len(digits) > 16:
            raise ValueError("LogonId exceeds the unsigned 64-bit range")
        number = int(digits, 16)
    else:
        number = int(unsigned_decimal(value, 64, "LogonId"))
    if number == 0:
        raise ValueError("LogonId must be nonzero")
    return hex(number)


def prepare_events(events) -> tuple[list[dict], dict]:
    """Validate the entire immutable batch before ingestion or correlation.

    Input uses literal dotted leaf names. win.privileges is the sole permitted
    array, only on 4672, with sorted unique native privilege names. Extra aliases,
    nested objects, coercible types and missing join evidence fail explicitly.
    """
    unique, counters = _prepare_events(events)
    for event in unique:
        code = event.get("event.code")
        if event["event.dataset"] != DATASET or not isinstance(code, str) or code not in {"4624", "4672"}:
            raise ValueError("newcredentials-v1 requires windows.security.sessions event.code '4624' or '4672'")
        specific = LOGON_FIELDS if code == "4624" else PRIVILEGE_FIELDS
        required = REQUIRED_FIELDS | specific
        allowed = required | OPTIONAL_FIELDS
        unknown = set(event) - allowed
        missing = required - set(event)
        if unknown:
            raise ValueError(f"newcredentials-v1 unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"newcredentials-v1 missing required fields: {', '.join(sorted(missing))}")
        for key, value in event.items():
            if key != "win.privileges" and isinstance(value, (dict, list, tuple)):
                raise ValueError("newcredentials-v1 requires flat scalar fields except win.privileges")
        if not MIN_TIME <= parse_timestamp(event["@timestamp"]) <= MAX_TIME:
            raise ValueError("newcredentials-v1 timestamp is outside its date_nanos range")
        for field in TEXT_FIELDS & set(event):
            if event[field] is None and field in OPTIONAL_FIELDS:
                continue
            _text(event[field], field)
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ValueError("event.id exceeds Elasticsearch's 512-byte _id limit")
        for field in ("host.name", "user.name", "user.domain", "win.logon_process"):
            value = event.get(field)
            if value is not None and value.translate(ASCII_LOWER) != value:
                raise ValueError(f"{field} requires canonical ASCII lowercase")
        if canonical_logon_id(event["session.id"]) != event["session.id"]:
            raise ValueError("session.id requires canonical nonzero lowercase hex LogonId")
        sid = event["user.id"]
        if canonical_sid(sid) != sid or sid == "S-1-0-0":
            raise ValueError("user.id requires a canonical non-null local-token SID")
        if code == "4624":
            logon_type = event["win.logon_type"]
            if type(logon_type) is not int or not 0 <= logon_type <= UINT32_MAX:
                raise ValueError("win.logon_type requires an integer in the unsigned 32-bit range")
        else:
            privileges = event["win.privileges"]
            if not isinstance(privileges, list) or not privileges:
                raise ValueError("win.privileges requires a nonempty sorted unique list")
            for privilege in privileges:
                _text(privilege, "win.privileges item")
                if re.fullmatch(r"Se[A-Za-z0-9]+Privilege", privilege) is None:
                    raise ValueError("win.privileges requires native Se…Privilege names")
            if privileges != sorted(set(privileges)):
                raise ValueError("win.privileges requires a sorted unique list")
        for field, expected in (("event.provider", PROVIDER), ("event.channel", CHANNEL)):
            if event.get(field) is not None and event[field] != expected:
                raise ValueError(f"{field} must be {expected}")
        versions = {0, 2} if code == "4624" else {0}
        for field, permitted in (("event.version", versions), ("win.timestamp_remainder", set(range(10)))):
            value = event.get(field)
            if value is not None and (type(value) is not int or value not in permitted):
                raise ValueError(f"{field} has an unsupported integer value")
        record = event.get("event.record_id")
        if record is not None and unsigned_decimal(record, 64, "event.record_id") != record:
            raise ValueError("event.record_id requires canonical unsigned 64-bit decimal text")
    return unique, counters
