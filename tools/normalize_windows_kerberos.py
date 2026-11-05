#!/usr/bin/env python3
"""Normalize one exported Security 4769 XML per file into kerberos-v1 JSONL.

Both native versions 0 and 2 use the explicitly named core fields below. Requester
TargetUserName/TargetDomainName remain separate; SubjectUserName is not substituted.
ServiceSid identifies the service account. ServiceName is retained only as text
context and is not interpreted as a complete SPN. Missing values do not get guessed.
Timestamp arithmetic uses microseconds; the native 100ns remainder is retained in
event identity and win.timestamp_remainder, not used as extra rolling precision.
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
    from tools.kerberos_profile import ASCII_LOWER, DATASET, canonical_ip, canonical_sid, prepare_events, unsigned_decimal
except ModuleNotFoundError:
    from hunt_engine import format_timestamp, parse_timestamp
    from kerberos_profile import ASCII_LOWER, DATASET, canonical_ip, canonical_sid, prepare_events, unsigned_decimal

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PREFIX = "{" + NS["e"] + "}"


def _uint32(value: str, field: str) -> int:
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        digits = value[2:].lstrip("0") or "0"
        if len(digits) > 8:
            raise ValueError(f"{field} is outside the unsigned 32-bit range")
        return int(digits, 16)
    return int(unsigned_decimal(value, 32, field))


def normalize_event(xml: str) -> dict:
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("Windows event exports must not contain DTD/entities")
    event = ET.fromstring(xml)
    if event.tag != PREFIX + "Event":
        raise ValueError("Expected one Windows Event XML element with its standard namespace")
    systems = event.findall("e:System", NS)
    if len(systems) != 1:
        raise ValueError("Expected exactly one System element")
    system = systems[0]

    def element(name: str) -> ET.Element:
        elements = system.findall(f"e:{name}", NS)
        if len(elements) != 1:
            raise ValueError(f"Expected exactly one System/{name}")
        if len(elements[0]):
            raise ValueError(f"System/{name} must not contain child elements")
        return elements[0]

    def required(name: str) -> str:
        value = element(name).text
        if not value or not value.strip():
            raise ValueError(f"Missing System/{name}")
        if value != value.strip():
            raise ValueError(f"System/{name} has surrounding whitespace")
        return value

    code, channel, host = (required(name) for name in ("EventID", "Channel", "Computer"))
    if code != "4769" or channel != "Security" or element("Provider").get("Name") != "Microsoft-Windows-Security-Auditing":
        raise ValueError("Only Microsoft-Windows-Security-Auditing Security 4769 events are supported")
    version = required("Version")
    if version not in {"0", "2"}:
        raise ValueError("Only native 4769 versions 0 and 2 are supported")
    host = host.translate(ASCII_LOWER)
    record = unsigned_decimal(required("EventRecordID"), 64, "EventRecordID")
    raw_time = element("TimeCreated").get("SystemTime")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,7}))?(Z|[+-][0-9]{2}:[0-9]{2})", raw_time or "")
    if match is None:
        raise ValueError("TimeCreated must be a timezone-qualified timestamp with at most 7 fractional digits")
    fraction = match[2] or ""
    timestamp = format_timestamp(parse_timestamp(match[1] + ("." + fraction[:6] if fraction else "") + match[3]))
    remaining_tick = fraction[6:7] or "0"

    containers = event.findall("e:EventData", NS)
    if len(containers) != 1:
        raise ValueError("Expected exactly one EventData element")
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

    identity = json.dumps([host, channel, record, timestamp, remaining_tick, code], ensure_ascii=False, separators=(",", ":"))
    result = {
        "@timestamp": timestamp,
        "event.id": "windows-security:" + hashlib.sha256(identity.encode()).hexdigest(),
        "event.dataset": DATASET,
        "event.code": code,
        "event.channel": channel,
        "event.record_id": record,
        "event.version": int(version),
        "host.name": host,
        "win.timestamp_remainder": int(remaining_tick),
    }
    for source, target in (("TargetUserName", "user.name"), ("TargetDomainName", "user.domain")):
        if (value := optional(source)) is not None:
            result[target] = value.translate(ASCII_LOWER)
    if (value := optional("IpAddress")) is not None:
        result["source.ip"] = canonical_ip(value)
    if (value := optional("ServiceSid")) is not None:
        sid = canonical_sid(value)
        if sid != "S-1-0-0":
            result["service.id"] = sid
    if (value := optional("ServiceName")) is not None:
        result["service.name"] = value
    for source, target in (("Status", "win.status"), ("TicketEncryptionType", "ticket.encryption_type")):
        if (value := optional(source)) is not None:
            result[target] = _uint32(value, source)
    validated, _ = prepare_events([result])
    return validated[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, nargs="+", help="One exported Event XML per file")
    args = parser.parse_args()
    try:
        events, _ = prepare_events(normalize_event(path.read_text(encoding="utf-8-sig")) for path in args.events)
        for event in events:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"Normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
