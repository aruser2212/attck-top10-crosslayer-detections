#!/usr/bin/env python3
"""Normalize one exported Sysmon ProcessAccess XML event per file into lsass-v1.

Only Microsoft-Windows-Sysmon/Operational event 10, native version 3, is
supported. Required process GUIDs, images and GrantedAccess are never inferred
from PIDs, account names or a familiar executable basename. This validates an
export's representation; it does not authenticate the exporting endpoint.

Event time is System/TimeCreated, not EventData/UtcTime. Microseconds are used
for replay; the remaining native 100ns digit is retained in event identity and
win.timestamp_remainder. Other native EventData fields (including UtcTime and
SourceThreadId) are ignored, not guessed into normalized fields.
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
    from tools.lsass_profile import ASCII_LOWER, DATASET, canonical_guid, canonical_image, prepare_events
except ModuleNotFoundError:  # Direct invocation outside the repository directory.
    from hunt_engine import format_timestamp, parse_timestamp
    from lsass_profile import ASCII_LOWER, DATASET, canonical_guid, canonical_image, prepare_events


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PREFIX = "{" + NS["e"] + "}"
PROVIDER = "Microsoft-Windows-Sysmon"
CHANNEL = PROVIDER + "/Operational"


def _unsigned_decimal(value: str, bits: int, field: str) -> str:
    """Bound the canonical digits before int(), including padded exports."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise ValueError(f"{field} must be an ASCII unsigned {bits}-bit decimal integer")
    canonical = value.lstrip("0") or "0"
    maximum = str(2**bits - 1)
    if len(canonical) > len(maximum) or (len(canonical) == len(maximum) and canonical > maximum):
        raise ValueError(f"{field} exceeds the unsigned {bits}-bit range")
    return canonical


def _access_mask(value: str) -> int:
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        digits = value[2:].lstrip("0") or "0"
        if len(digits) > 8:
            raise ValueError("GrantedAccess exceeds the unsigned 32-bit range")
        return int(digits, 16)
    return int(_unsigned_decimal(value, 32, "GrantedAccess"))


def normalize_event(xml: str) -> dict:
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
    system = systems[0]
    system_fields = {}
    for entry in system:
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
    if code != "10" or channel != CHANNEL or element("Provider").get("Name") != PROVIDER:
        raise ValueError("Only Microsoft-Windows-Sysmon/Operational event 10 is supported")
    if required_system("Version") != "3":
        raise ValueError("Only native Sysmon event 10 version 3 is supported")
    host = host.translate(ASCII_LOWER)
    record = _unsigned_decimal(required_system("EventRecordID"), 64, "EventRecordID")
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

    identity = json.dumps([host, channel, record, timestamp, remaining_tick, code],
                          ensure_ascii=False, separators=(",", ":"))
    result = {
        "@timestamp": timestamp,
        "event.id": "windows-sysmon:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "event.dataset": DATASET,
        "event.code": code,
        "event.provider": PROVIDER,
        "event.channel": channel,
        "event.record_id": record,
        "event.version": 3,
        "host.name": host,
        "win.timestamp_remainder": int(remaining_tick),
        "source.process.guid": canonical_guid(required("SourceProcessGUID")),
        "target.process.guid": canonical_guid(required("TargetProcessGUID")),
        "source.image": canonical_image(required("SourceImage")),
        "target.image": canonical_image(required("TargetImage")),
        "process.access_mask": _access_mask(required("GrantedAccess")),
    }
    for source, target in (("SourceProcessId", "source.process.pid"), ("TargetProcessId", "target.process.pid")):
        if (value := optional(source)) is not None:
            result[target] = int(_unsigned_decimal(value, 32, source))
    for source, target in (("SourceUser", "source.user"), ("TargetUser", "target.user"),
                           ("CallTrace", "process.call_trace")):
        if (value := optional(source)) is not None:
            result[target] = value
    validated, _ = prepare_events([result])
    return validated[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, nargs="+", help="One exported Sysmon Event XML per file")
    args = parser.parse_args()
    try:
        events, _ = prepare_events(normalize_event(path.read_text(encoding="utf-8-sig")) for path in args.events)
        for event in events:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"Sysmon normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
