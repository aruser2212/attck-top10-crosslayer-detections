"""Strict flat event contract for the Windows 4769 Kerberos replay profile.

Missing telemetry stays absent/null; present identities and numeric fields must
already be canonical. This module never equates UPN/SAM names or resolves aliases.
Service identity is a validated SID, not the ServiceName text or a guessed SPN.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import re
import string

try:
    from tools.hunt_engine import parse_timestamp, prepare_events as _prepare_events
except ModuleNotFoundError:
    from hunt_engine import parse_timestamp, prepare_events as _prepare_events

PROFILE = "attck-kerberos-v1"
DATASET = "windows.security.kerberos_tgs"
MAPPING_PATH = Path(__file__).resolve().parents[1] / "profiles/elastic/kerberos-v1.mapping.json"
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(2262, 4, 11, 23, 47, 16, 854775, tzinfo=timezone.utc)
UINT32_MAX = 2**32 - 1


def unsigned_decimal(value: str, bits: int, field: str) -> str:
    """Validate bounded ASCII decimal without parsing unbounded padded integers."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
        raise ValueError(f"{field} must be an ASCII unsigned {bits}-bit decimal integer")
    canonical = value.lstrip("0") or "0"
    maximum = str(2**bits - 1)
    if len(canonical) > len(maximum) or (len(canonical) == len(maximum) and canonical > maximum):
        raise ValueError(f"{field} is outside the unsigned {bits}-bit range")
    return canonical


def canonical_ip(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("source.ip must be an IP address without a scope identifier")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def canonical_sid(value: str) -> str:
    """Canonical revision-1 SID with a 48-bit authority and 1..15 uint32 RIDs.

    Hexadecimal identifier authorities are accepted as Windows SID strings may
    use that representation; subauthorities are decimal. No SID/name lookup is
    performed. The null SID is syntactically valid but is not a service identity.
    """
    if not isinstance(value, str) or re.fullmatch(
        r"[Ss]-1-(?:[0-9]+|0[xX][0-9a-fA-F]+)(?:-[0-9]+){1,15}", value
    ) is None:
        raise ValueError("ServiceSid must be a revision-1 SID with 1..15 subauthorities")
    _, _, authority, *subauthorities = value.split("-")
    if authority.lower().startswith("0x"):
        digits = authority[2:].lstrip("0") or "0"
        if len(digits) > 12:
            raise ValueError("ServiceSid identifier authority exceeds 48 bits")
        authority = str(int(digits, 16))
    else:
        authority = unsigned_decimal(authority, 48, "ServiceSid identifier authority")
    parts = [unsigned_decimal(part, 32, "ServiceSid subauthority") for part in subauthorities]
    return "S-1-" + "-".join([authority, *parts])


def prepare_events(events) -> tuple[list[dict], dict]:
    """Normalize timestamps/deduplicate IDs, then require canonical 4769 fields."""
    unique, counters = _prepare_events(events)
    for event in unique:
        if event["event.dataset"] != DATASET or event.get("event.code") != "4769":
            raise ValueError("kerberos-v1 requires windows.security.kerberos_tgs event.code 4769")
        if not MIN_TIME <= parse_timestamp(event["@timestamp"]) <= MAX_TIME:
            raise ValueError("kerberos-v1 date_nanos range is 1970-01-01 through 2262-04-11T23:47:16.854775Z")
        if len(event["event.id"].encode("utf-8")) > 512:
            raise ValueError("event.id exceeds Elasticsearch's 512-byte _id limit")
        if any(isinstance(value, (dict, list, tuple)) for value in event.values()):
            raise ValueError("kerberos-v1 requires flat scalar fields, not nested objects/arrays")
        for field in ("user.name", "user.domain", "host.name", "source.ip", "service.id", "service.name",
                      "event.channel", "event.record_id"):
            value = event.get(field)
            if value is None:
                continue
            if not isinstance(value, str) or not value or value != value.strip() or value == "-":
                raise ValueError(f"{field} must be a nonempty scalar string without surrounding whitespace")
            if field in ("user.name", "user.domain", "host.name") and value.translate(ASCII_LOWER) != value:
                raise ValueError(f"{field} requires canonical ASCII lowercase")
            if field == "source.ip" and canonical_ip(value) != value:
                raise ValueError("source.ip must be canonical (IPv4-mapped IPv6 becomes IPv4)")
            if field == "service.id" and (canonical_sid(value) != value or value == "S-1-0-0"):
                raise ValueError("service.id must be a canonical non-null SID")
            if field == "event.channel" and value != "Security":
                raise ValueError("event.channel must be Security")
            if field == "event.record_id" and unsigned_decimal(value, 64, field) != value:
                raise ValueError("event.record_id must be canonical unsigned 64-bit decimal")
        for field in ("win.status", "ticket.encryption_type"):
            value = event.get(field)
            if value is not None and (type(value) is not int or not 0 <= value <= UINT32_MAX):
                raise ValueError(f"{field} requires an integer in the unsigned 32-bit range")
        for field, allowed in (("event.version", {0, 2}), ("win.timestamp_remainder", set(range(10)))):
            value = event.get(field)
            if value is not None and (type(value) is not int or value not in allowed):
                raise ValueError(f"{field} has an unsupported integer value")
    return unique, counters
