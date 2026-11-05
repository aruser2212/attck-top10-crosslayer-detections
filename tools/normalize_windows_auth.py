#!/usr/bin/env python3
"""Normalize exported Windows Security 4624/4625 XML into auth-v1 JSONL.

This consumes event XML, not binary EVTX. Event identity includes host, channel,
record ID, timestamp and event code; subject and target accounts are not merged.
Missing IP/target data remains missing so aggregation can reject incomplete data.
Computer names use ASCII lowercase and record IDs use canonical unsigned-64-bit
decimal text. This does not resolve host aliases, directory aliases or Unicode
account equivalence. Batch CLI re-delivery is deduplicated; identity conflicts fail.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import string
import sys
import xml.etree.ElementTree as ET

try:
    from tools.hunt_engine import format_timestamp, parse_timestamp, prepare_events
except ModuleNotFoundError:
    from hunt_engine import format_timestamp, parse_timestamp, prepare_events

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def normalize_event(xml: str) -> dict:
    # Event exports do not require a DTD or entities. Reject them before parsing.
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("Windows event exports must not contain DTD/entities")
    event = ET.fromstring(xml)
    if event.tag != f"{{{NS['e']}}}Event":
        raise ValueError("Expected one Windows Event XML element with its standard namespace")
    systems = event.findall("e:System", NS)
    if len(systems) != 1:
        raise ValueError("Expected exactly one System element")
    system = systems[0]

    def required_element(name: str) -> ET.Element:
        elements = system.findall(f"e:{name}", NS)
        if len(elements) != 1:
            raise ValueError(f"Expected exactly one System/{name}")
        return elements[0]

    def required(name: str) -> str:
        element = required_element(name)
        if len(element):
            raise ValueError(f"System/{name} must contain text only")
        value = element.text
        if not value or not value.strip():
            raise ValueError(f"Missing System/{name}")
        return value.strip()

    code, host, channel, record = (required(name) for name in ("EventID", "Computer", "Channel", "EventRecordID"))
    host = host.translate(ASCII_LOWER)
    provider = required_element("Provider")
    if channel != "Security" or provider.get("Name") != "Microsoft-Windows-Security-Auditing":
        raise ValueError("Only Microsoft-Windows-Security-Auditing Security events are supported")
    if code not in {"4624", "4625"}:
        raise ValueError("Only Security 4624/4625 events are supported by auth-v1")
    if not re.fullmatch(r"[0-9]+", record):
        raise ValueError("EventRecordID must be an ASCII unsigned 64-bit decimal integer")
    # Strip insignificant zeros before conversion, including very long padding;
    # bound the value without relying on Python's large-integer parsing limit.
    record = record.lstrip("0") or "0"
    if len(record) > 20 or (len(record) == 20 and record > "18446744073709551615"):
        raise ValueError("EventRecordID is outside the unsigned 64-bit range")
    record = str(int(record))
    created = required_element("TimeCreated")
    raw_time = created.get("SystemTime")
    # Native Windows XML uses 100ns ticks (7 fractional digits). The runtime's
    # datetime contract is microseconds; keep the remaining tick in event identity.
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})", raw_time or "")
    if match is None:
        raise ValueError("TimeCreated must be an ISO timestamp with timezone and at most 7 fractional digits")
    fraction = match[2] or ""
    micro_time = match[1] + ("." + fraction[:6] if fraction else "") + match[3]
    timestamp = format_timestamp(parse_timestamp(micro_time))
    remaining_tick = fraction[6:7] or "0"
    fields = {}
    for entry in event.findall("e:EventData/e:Data", NS):
        name = entry.get("Name")
        if not name or name in fields:
            raise ValueError("EventData requires unique named Data fields")
        fields[name] = entry.text or ""
    identity = json.dumps([host, channel, record, timestamp, remaining_tick, code], ensure_ascii=False, separators=(",", ":"))
    result = {
        "@timestamp": timestamp,
        "event.id": "windows-security:" + hashlib.sha256(identity.encode()).hexdigest(),
        "event.dataset": "windows.security.logons",
        "event.code": code,
        "host.name": host,
    }
    account = fields.get("TargetUserName")
    if account and account.strip() and account != "-":
        # Preserve domain identity to avoid merging equal usernames in different domains.
        domain = fields.get("TargetDomainName")
        principal = f"{domain}\\{account}" if domain and domain.strip() and domain != "-" else account
        # Windows ASCII account names are case-insensitive. Full Unicode casefold
        # can merge identifiers (e.g. ß/ss); directory-backed alias resolution is
        # required for non-ASCII/UPN cases, rather than guessing that equivalence.
        result["target.user"] = principal.translate(ASCII_LOWER)
    address = fields.get("IpAddress")
    if address and address.strip() and address != "-":
        if "%" in address:
            raise ValueError("Scoped source IP addresses require an explicit collector mapping")
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        result["source.ip"] = str(ip)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, nargs="+", help="One exported Event XML per file")
    args = parser.parse_args()
    try:
        # Validate all inputs before emitting a partial stream.
        events, _ = prepare_events(
            normalize_event(path.read_text(encoding="utf-8-sig")) for path in args.events
        )
        for event in events:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True))
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"Normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
