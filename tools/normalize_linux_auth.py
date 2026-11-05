#!/usr/bin/env python3
"""Normalize journalctl --output=json sshd records into linux.auth.sshd JSONL.

Supported messages are Failed password (including invalid user), Accepted
password, and Accepted publickey. Generic syslog text is deliberately unsupported:
the journal's __REALTIME_TIMESTAMP is integer Unix microseconds, and identity is
the opaque __CURSOR namespaced by _MACHINE_ID. No dates, zones, or IDs are guessed.

_COMM is authoritative when present. Exact source names sshd, sshd-session, and
sshd-auth are supported. SYSLOG_IDENTIFIER is used only as a fallback when _COMM
was omitted from the export; it selects records, not authenticates their origin.
Supply exports from a trusted collector.
Other sources and unrelated sshd messages are counted as ignored. Recognized auth
messages with malformed/missing required data fail the complete input batch.
Raw messages, key fingerprints, and unrelated journal fields are not emitted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Iterable, Mapping, TextIO

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MACHINE_ID = re.compile(r"[0-9a-fA-F]{32}")
SSHD_SOURCES = frozenset({"sshd", "sshd-session", "sshd-auth"})
AUTH_PREFIXES = ("Failed password", "Accepted password", "Accepted publickey")
AUTH_MESSAGE = re.compile(
    r"(?P<action>Failed password|Accepted password|Accepted publickey) for "
    r"(?:(?P<invalid>invalid user) )?(?P<user>[^\s]+) from "
    r"(?P<address>[^\s]+) port (?P<port>[0-9]{1,5}) ssh2(?P<tail>[^\r\n]*)"
)


def _text(record: Mapping, field: str, *, required: bool = True) -> str | None:
    value = record.get(field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or any(
        ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
    ):
        raise ValueError(f"Journal field {field} must be a nonempty string without surrounding whitespace/control characters")
    return value


def _journal_time(record: Mapping) -> str:
    raw = record.get("__REALTIME_TIMESTAMP")
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,18}", raw):
        raise ValueError("__REALTIME_TIMESTAMP must be a decimal string of Unix microseconds")
    try:
        value = EPOCH + timedelta(microseconds=int(raw))
    except (OverflowError, ValueError) as exc:
        raise ValueError("__REALTIME_TIMESTAMP is outside the supported UTC datetime range") from exc
    return value.isoformat().replace("+00:00", "Z")


def normalize_event(record: Mapping) -> dict | None:
    """Normalize one record; return None only for an unrelated source/message.

    Errors intentionally identify fields, never their raw values or MESSAGE.
    """
    if not isinstance(record, dict) or not all(isinstance(key, str) for key in record):
        raise ValueError("Each journal record must be a JSON object with string keys")
    comm = _text(record, "_COMM", required=False)
    if comm is not None and comm not in SSHD_SOURCES:
        return None
    identifier = _text(record, "SYSLOG_IDENTIFIER", required=False)
    if comm is None and identifier not in SSHD_SOURCES:
        return None
    if comm in SSHD_SOURCES and identifier is not None and identifier not in SSHD_SOURCES:
        raise ValueError("Conflicting sshd source fields _COMM and SYSLOG_IDENTIFIER")

    message = record.get("MESSAGE")
    if not isinstance(message, str):
        raise ValueError("sshd MESSAGE must be one text string")
    if not message.startswith(AUTH_PREFIXES):
        return None
    parsed = AUTH_MESSAGE.fullmatch(message)
    if parsed is None:
        raise ValueError("Unsupported or malformed sshd authentication message")
    action, tail = parsed["action"], parsed["tail"]
    if parsed["invalid"] and action != "Failed password":
        raise ValueError("Accepted authentication cannot contain the invalid user marker")
    if action == "Accepted publickey":
        # OpenSSH appends key/certificate metadata after ': '; discard it rather
        # than interpreting fingerprints or copying potentially sensitive text.
        if tail and (not tail.startswith(": ") or not tail[2:].strip()):
            raise ValueError("Unsupported publickey authentication message suffix")
    elif tail not in ("", " [preauth]") or (action == "Accepted password" and tail):
        raise ValueError("Unsupported password authentication message suffix")
    account = parsed["user"]
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in account):
        raise ValueError("Authentication user must be a nonempty token without control characters")
    if "%" in parsed["address"]:
        raise ValueError("Scoped source IP addresses require an explicit collector mapping")
    try:
        address = ipaddress.ip_address(parsed["address"])
    except ValueError:
        # ipaddress's original exception contains its input; keep it out of
        # traceback chains that a collector might log.
        raise ValueError("Authentication source address must be a valid IPv4 or IPv6 address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    port = int(parsed["port"])
    if not 0 <= port <= 65535:
        raise ValueError("Authentication source port is outside the 16-bit range")

    machine = _text(record, "_MACHINE_ID")
    if MACHINE_ID.fullmatch(machine) is None:
        raise ValueError("_MACHINE_ID must be a 32-character hexadecimal journal machine ID")
    machine = machine.lower()
    cursor = _text(record, "__CURSOR")
    timestamp = _journal_time(record)
    identity = json.dumps([machine, cursor], separators=(",", ":"), ensure_ascii=False)
    event = {
        "@timestamp": timestamp,
        "event.id": "linux-journal:" + hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "event.dataset": "linux.auth.sshd",
        "event.action": "ssh_authentication",
        "event.outcome": "failure" if action == "Failed password" else "success",
        "host.id": machine,
        "user.name": account,  # Linux account names retain their original case.
        "source.ip": str(address),
        "source.port": port,
        "message": action,
    }
    hostname = _text(record, "_HOSTNAME", required=False)
    if hostname is not None:
        event["host.name"] = hostname
    return event


def normalize_records(records: Iterable[Mapping]) -> dict:
    """Validate the whole batch, deduplicate re-delivery, and reject conflicts."""
    events = {}
    summary = {"input_records": 0, "ignored_records": 0, "duplicate_records": 0, "normalized_events": 0}
    for record in records:
        summary["input_records"] += 1
        event = normalize_event(record)
        if event is None:
            summary["ignored_records"] += 1
            continue
        previous = events.get(event["event.id"])
        if previous is not None:
            if previous != event:
                raise ValueError("Conflicting records share a journal machine ID and cursor")
            summary["duplicate_records"] += 1
        else:
            events[event["event.id"]] = event
    if not summary["input_records"]:
        raise ValueError("Journal JSONL input is empty")
    if not events:
        raise ValueError("Journal input contains no supported sshd authentication events")
    summary["normalized_events"] = len(events)
    return {"events": list(events.values()), "summary": summary}


def read_jsonl(stream: TextIO) -> list[dict]:
    """Strict JSONL: one object per line, unique keys, no NaN or blank records."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("Non-finite JSON values are unsupported")

    records = []
    for number, line in enumerate(stream, start=1):
        if not line.strip():
            raise ValueError(f"Blank journal JSONL record at line {number}")
        try:
            record = json.loads(line, object_pairs_hook=unique, parse_constant=nonfinite)
        except ValueError as exc:
            raise ValueError(f"Invalid journal JSONL record at line {number}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Journal JSONL record at line {number} must be an object")
        records.append(record)
    if not records:
        raise ValueError("Journal JSONL input is empty")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", nargs="+", help="journalctl JSONL file(s), or '-' for stdin once")
    args = parser.parse_args()
    try:
        if args.events.count("-") > 1:
            raise ValueError("stdin may only be consumed once")
        records = []
        for path in args.events:
            if path == "-":
                records.extend(read_jsonl(sys.stdin))
            else:
                with Path(path).open(encoding="utf-8") as stream:
                    records.extend(read_jsonl(stream))
        result = normalize_records(records)
        # No output is emitted until every input record has passed validation.
        for event in result["events"]:
            print(json.dumps(event, ensure_ascii=False, sort_keys=True, allow_nan=False))
        print(json.dumps(result["summary"], sort_keys=True), file=sys.stderr)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Normalization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
