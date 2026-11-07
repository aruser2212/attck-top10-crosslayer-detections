#!/usr/bin/env python3
"""Normalize one Sysmon ProcessCreate v5 Event XML per file into process-v1.

This is a strict export normalizer, not a collector or command-line parser.
Image, ParentImage and CommandLine must be ASCII in this bounded profile.
System/TimeCreated supplies record time; the native seventh fractional digit
is retained in event identity while replay uses microseconds. Unknown scalar
native fields are ignored, not treated as verified enrichment.
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
    from tools.process_profile import (
        ASCII_LOWER, CHANNEL, DATASET, PROVIDER, canonical_guid, canonical_image, prepare_events,
    )
except ModuleNotFoundError:
    from hunt_engine import format_timestamp, parse_timestamp
    from process_profile import (
        ASCII_LOWER, CHANNEL, DATASET, PROVIDER, canonical_guid, canonical_image, prepare_events,
    )


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PREFIX = "{" + NS["e"] + "}"


def _unsigned_decimal(value: str, bits: int, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise ValueError(f"{field} must be an ASCII unsigned {bits}-bit decimal integer")
    canonical = value.lstrip("0") or "0"
    maximum = str(2**bits - 1)
    if len(canonical) > len(maximum) or (len(canonical) == len(maximum) and canonical > maximum):
        raise ValueError(f"{field} exceeds the unsigned {bits}-bit range")
    return canonical


def normalize_event(xml: str) -> dict:
    if not isinstance(xml, str):
        raise ValueError("Expected Windows Event XML text")
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("Windows event exports must not contain DTD/entities")
    event = ET.fromstring(xml)
    if event.tag != PREFIX + "Event":
        raise ValueError("Expected one Windows Event XML element with its standard namespace")
    if any(child.tag not in {PREFIX + "System", PREFIX + "EventData"} for child in event):
        raise ValueError("Expected only System and EventData containers")
    systems, containers = event.findall("e:System", NS), event.findall("e:EventData", NS)
    if len(systems) != 1 or len(containers) != 1:
        raise ValueError("Expected exactly one System and one EventData element")
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

    def system_text(name: str) -> str:
        value = element(name).text
        if not value or not value.strip() or value == "-":
            raise ValueError(f"Missing System/{name}")
        if value != value.strip():
            raise ValueError(f"System/{name} has surrounding whitespace")
        return value

    code, channel, host = (system_text(name) for name in ("EventID", "Channel", "Computer"))
    if code != "1" or channel != CHANNEL or element("Provider").get("Name") != PROVIDER:
        raise ValueError("Only Microsoft-Windows-Sysmon/Operational event 1 is supported")
    if system_text("Version") != "5":
        raise ValueError("Only native Sysmon event 1 version 5 is supported")
    host = host.translate(ASCII_LOWER)
    record = _unsigned_decimal(system_text("EventRecordID"), 64, "EventRecordID")
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
    remainder = fraction[6:7] or "0"
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

    # CommandLine is an opaque predicate field: whitespace is meaningful and
    # must not be altered by the generic trimmed native-metadata reader.
    if "CommandLine" not in fields:
        raise ValueError("Missing EventData/CommandLine")
    identity = json.dumps([host, channel, record, timestamp, remainder, code],
                          ensure_ascii=False, separators=(",", ":"))
    result = {
        "@timestamp": timestamp,
        "event.id": "windows-sysmon:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "event.dataset": DATASET, "event.code": code,
        "event.provider": PROVIDER, "event.channel": channel,
        "event.record_id": record, "event.version": 5,
        "host.name": host, "win.timestamp_remainder": int(remainder),
        "process.guid": canonical_guid(required("ProcessGuid")),
        "process.parent.guid": canonical_guid(required("ParentProcessGuid")),
        "process.executable": canonical_image(required("Image")),
        "process.parent.executable": canonical_image(required("ParentImage")),
        "process.command_line": fields["CommandLine"],
    }
    for source, target in (("ProcessId", "process.pid"), ("ParentProcessId", "process.parent.pid")):
        if (value := optional(source)) is not None:
            result[target] = int(_unsigned_decimal(value, 32, source))
    if (value := optional("User")) is not None:
        result["user.name"] = value
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
        print(f"Sysmon process normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
