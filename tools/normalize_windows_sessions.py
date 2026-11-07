#!/usr/bin/env python3
"""Normalize exported Security 4624/4672 XML into newcredentials-v1 JSONL.

4624 versions 0/2 and 4672 version 0 are supported. The local-token identity is
TargetLogonId/TargetUserSid for 4624 and SubjectLogonId/SubjectUserSid for 4672.
Outbound credentials, account names and the creator's SubjectLogonId never
substitute for that identity. A trusted, explicitly supplied boot scope is
required: Computer, record counters and timestamps cannot establish one.

Time is the native System/TimeCreated envelope time, with microseconds for
replay and the remaining 100ns digit retained in event identity. No event order
is inferred. Additional native EventData fields are ignored rather than guessed
into normalized fields. This validates an export, not its authenticity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

try:
    from tools.hunt_engine import format_timestamp, parse_timestamp
    from tools.kerberos_profile import canonical_sid, unsigned_decimal
    from tools.newcredentials_profile import ASCII_LOWER, DATASET, canonical_logon_id, prepare_events
except ModuleNotFoundError:  # Direct invocation outside the repository directory.
    from hunt_engine import format_timestamp, parse_timestamp
    from kerberos_profile import canonical_sid, unsigned_decimal
    from newcredentials_profile import ASCII_LOWER, DATASET, canonical_logon_id, prepare_events


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PREFIX = "{" + NS["e"] + "}"
PROVIDER = "Microsoft-Windows-Security-Auditing"
CHANNEL = "Security"
VERSIONS = {"4624": {"0", "2"}, "4672": {"0"}}


def normalize_event(xml: str, *, boot_id: str) -> dict:
    """Normalize one supported event with an upstream-attested boot scope."""
    if (not isinstance(boot_id, str) or not boot_id or boot_id != boot_id.strip()
            or boot_id == "-" or any(ord(char) < 32 or ord(char) == 127 for char in boot_id)):
        raise ValueError("boot_id requires explicit nonempty trimmed trusted boot context")
    try:
        boot_id.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("boot_id must contain valid UTF-8 text") from exc
    if not isinstance(xml, str):
        raise ValueError("Expected Windows Event XML text")
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("Windows event exports must not contain DTD/entities")
    event = ET.fromstring(xml)
    if event.tag != PREFIX + "Event":
        raise ValueError("Expected one Windows Event XML element with its standard namespace")
    systems = event.findall("e:System", NS)
    containers = event.findall("e:EventData", NS)
    if len(systems) != 1:
        raise ValueError("Expected exactly one System element")
    if len(containers) != 1:
        raise ValueError("Expected exactly one EventData element")
    system_fields = {}
    for entry in systems[0]:
        if not entry.tag.startswith(PREFIX) or len(entry):
            raise ValueError("System must contain scalar Windows event elements only")
        name = entry.tag[len(PREFIX):]
        if name in system_fields:
            raise ValueError(f"Expected exactly one System/{name}")
        system_fields[name] = entry

    def element(name: str) -> ET.Element:
        if name not in system_fields:
            raise ValueError(f"Missing System/{name}")
        return system_fields[name]

    def required_system(name: str) -> str:
        value = element(name).text
        if not value or not value.strip() or value == "-":
            raise ValueError(f"Missing System/{name}")
        if value != value.strip():
            raise ValueError(f"System/{name} has surrounding whitespace")
        return value

    code, channel, host = (required_system(name) for name in ("EventID", "Channel", "Computer"))
    if code not in VERSIONS or channel != CHANNEL or element("Provider").get("Name") != PROVIDER:
        raise ValueError("Only Microsoft-Windows-Security-Auditing Security 4624/4672 events are supported")
    version = required_system("Version")
    if version not in VERSIONS[code]:
        raise ValueError("Only native 4624 versions 0/2 and 4672 version 0 are supported")
    host = host.translate(ASCII_LOWER)
    record = unsigned_decimal(required_system("EventRecordID"), 64, "EventRecordID")
    raw_time = element("TimeCreated").get("SystemTime")
    match = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
        r"(?:\.([0-9]{1,7}))?(Z|[+-][0-9]{2}:[0-9]{2})", raw_time or "",
    )
    if match is None:
        raise ValueError("TimeCreated must be a timezone-qualified timestamp with at most 7 fractional digits")
    fraction = match[2] or ""
    timestamp = format_timestamp(parse_timestamp(
        match[1] + ("." + fraction[:6] if fraction else "") + match[3],
    ))
    remaining_tick = fraction[6:7] or "0"
    fields = {}
    for entry in containers[0]:
        if entry.tag != PREFIX + "Data" or len(entry):
            raise ValueError("EventData must contain scalar Data elements only")
        name = entry.get("Name")
        if not name or name != name.strip() or name in fields:
            raise ValueError("EventData requires unique named Data fields")
        fields[name] = entry.text or ""

    def optional(name: str) -> str | None:
        value = fields.get(name)
        if value is None or not value.strip() or value == "-":
            return None
        if value != value.strip():
            raise ValueError(f"EventData/{name} has surrounding whitespace")
        return value

    def required(name: str) -> str:
        value = optional(name)
        if value is None:
            raise ValueError(f"Missing EventData/{name}")
        return value

    identity = json.dumps([host, boot_id, channel, record, timestamp, remaining_tick, code],
                          ensure_ascii=False, separators=(",", ":"))
    result = {
        "@timestamp": timestamp,
        "event.id": "windows-session:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "event.dataset": DATASET,
        "event.code": code,
        "event.provider": PROVIDER,
        "event.channel": channel,
        "event.record_id": record,
        "event.version": int(version),
        "host.name": host,
        "host.boot.id": boot_id,
        "win.timestamp_remainder": int(remaining_tick),
    }
    prefix = "Target" if code == "4624" else "Subject"
    result["session.id"] = canonical_logon_id(required(prefix + "LogonId"))
    result["user.id"] = canonical_sid(required(prefix + "UserSid"))
    for suffix, field in (("UserName", "user.name"), ("DomainName", "user.domain")):
        if (value := optional(prefix + suffix)) is not None:
            result[field] = value.translate(ASCII_LOWER)
    if code == "4624":
        result["win.logon_type"] = int(unsigned_decimal(required("LogonType"), 32, "LogonType"))
        # Windows exports may pad LogonProcessName (for example, "User32 ").
        # Only this descriptive process field is trimmed, never identity fields.
        process = fields.get("LogonProcessName", "").strip(" \t\r\n")
        if not process or process == "-":
            raise ValueError("Missing EventData/LogonProcessName")
        result["win.logon_process"] = process.translate(ASCII_LOWER)
    else:
        # Native PrivilegeList uses whitespace-separated tokens, often newlines
        # and tabs. The profile validates individual names, never this raw blob.
        privileges = fields.get("PrivilegeList", "").split()
        if not privileges:
            raise ValueError("Missing EventData/PrivilegeList")
        result["win.privileges"] = sorted(set(privileges))
    validated, _ = prepare_events([result])
    return validated[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot-id", required=True,
                        help="Trusted boot scope shared only by events from the same host boot; never guessed")
    parser.add_argument("events", type=Path, nargs="+", help="One exported Security Event XML per file")
    args = parser.parse_args()
    try:
        events, _ = prepare_events(
            normalize_event(path.read_text(encoding="utf-8-sig"), boot_id=args.boot_id) for path in args.events
        )
        for event in events:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"Session normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
