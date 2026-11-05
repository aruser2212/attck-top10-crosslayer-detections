"""Native XML and strict normalized-field contracts for Kerberos candidate replay."""
from pathlib import Path
import json
import subprocess
import sys

import pytest

from tools import kerberos_profile
from tools.hunt_engine import HuntError
from tools.normalize_windows_kerberos import normalize_event

ROOT = Path(__file__).resolve().parents[1]
XML = (ROOT / "tests/fixtures/kerberos/xml/4769-v0.xml").read_text()
XML_V2 = (ROOT / "tests/fixtures/kerberos/xml/4769-v2.xml").read_text()
SID = "S-1-5-21-111111111-222222222-333333333-1101"


def replace_field(xml, name, value):
    import xml.etree.ElementTree as ET
    event = ET.fromstring(xml)
    field = event.find(f"{{*}}EventData/{{*}}Data[@Name='{name}']")
    assert field is not None
    field.text = value
    return ET.tostring(event, encoding="unicode")


def test_native_requester_fields_are_separate_and_service_name_is_only_context():
    event = normalize_event(XML.replace("</EventData>", '<Data Name="SubjectUserName">SYSTEM</Data></EventData>'))
    assert event["event.code"] == "4769"
    assert event["event.dataset"] == "windows.security.kerberos_tgs"
    assert event["user.name"] == "alice@lab.example"
    assert event["user.domain"] == "lab.example"
    assert event["service.id"] == SID
    assert event["service.name"] == "LegacySqlSvc"
    assert event["host.name"] == "dc01.lab.example"
    assert event["source.ip"] == "192.0.2.10"
    assert event["ticket.encryption_type"] == 23
    assert event["win.status"] == 0
    assert event["event.record_id"] == "1001"
    assert "subject.user" not in event and "target.user" not in event


def test_v2_core_fields_use_ticket_type_not_session_key_type_and_retain_machine_requester():
    event = normalize_event(XML_V2)
    assert event["event.version"] == 2
    assert event["ticket.encryption_type"] == 23
    assert event["user.name"] == "apphost$@lab.example"
    assert event["source.ip"] == "2001:db8::10"


def test_no_upn_sam_domain_or_unicode_alias_guessing():
    upn = normalize_event(XML)
    sam = normalize_event(replace_field(XML, "TargetUserName", "Alice"))
    assert upn["user.name"] != sam["user.name"]
    other_domain = normalize_event(replace_field(XML, "TargetDomainName", "LAB"))
    assert upn["user.domain"] != other_domain["user.domain"]
    assert normalize_event(replace_field(XML, "TargetUserName", "straße"))["user.name"] != normalize_event(
        replace_field(XML, "TargetUserName", "strasse"))["user.name"]


@pytest.mark.parametrize("name,target", [
    ("TargetUserName", "user.name"), ("TargetDomainName", "user.domain"),
    ("ServiceSid", "service.id"), ("ServiceName", "service.name"),
    ("IpAddress", "source.ip"), ("Status", "win.status"), ("TicketEncryptionType", "ticket.encryption_type"),
])
def test_missing_semantic_data_does_not_receive_a_guessed_value(name, target):
    assert target not in normalize_event(replace_field(XML, name, "-"))
    assert target not in normalize_event(replace_field(XML, name, ""))


def test_null_sid_is_absent_even_when_service_name_is_available():
    event = normalize_event(replace_field(XML, "ServiceSid", "s-1-00-000"))
    assert "service.id" not in event
    assert event["service.name"] == "LegacySqlSvc"


def test_decimal_hex_and_padded_values_have_one_numeric_interpretation():
    native = normalize_event(XML)
    alternate = normalize_event(replace_field(replace_field(XML, "TicketEncryptionType", "00023"), "Status", "0X0000"))
    assert native == alternate
    failure = normalize_event(replace_field(replace_field(XML, "Status", "0xFFFFFFFF"), "TicketEncryptionType", "4294967295"))
    assert failure["win.status"] == failure["ticket.encryption_type"] == 2**32 - 1


@pytest.mark.parametrize("value", ["RC4", "0x17 (RC4)", "23.0", "-1", "+23", " 23", "٢٣", "0x100000000", "4294967296"])
def test_native_numeric_fields_fail_instead_of_coercing_malformed_values(value):
    with pytest.raises(ValueError):
        normalize_event(replace_field(XML, "TicketEncryptionType", value))


def test_equivalent_sid_spellings_are_canonical_but_distinct_sids_stay_distinct():
    source = "s-1-0x05-021-0111111111-0222222222-0333333333-01101"
    assert normalize_event(replace_field(XML, "ServiceSid", source))["service.id"] == SID
    assert normalize_event(replace_field(XML, "ServiceSid", SID[:-4] + "1102"))["service.id"] != SID
    maximum = "S-1-281474976710655-4294967295"
    assert kerberos_profile.canonical_sid(maximum) == maximum


@pytest.mark.parametrize("sid", ["LegacySqlSvc", "S-2-5-21-1", "S-1-5", "S-1-5--1", "S-1-281474976710656-1",
                                  "S-1-0x1000000000000-1", "S-1-5-4294967296", "S-1-5-" + "1-" * 15 + "1"])
def test_native_sid_validation_is_bounded_and_does_not_fall_back_to_name(sid):
    with pytest.raises(ValueError, match="ServiceSid"):
        normalize_event(replace_field(XML, "ServiceSid", sid))


def test_source_identity_preserves_native_ticks_and_canonicalizes_export_format():
    native = normalize_event(XML)
    alternate = XML.replace("DC01.LAB.EXAMPLE", "dc01.lab.example").replace(">1001<", ">0001001<").replace(
        "2026-01-01T00:00:10.1234567Z", "2026-01-01T03:00:10.1234567+03:00")
    assert normalize_event(alternate) == native
    second_tick = normalize_event(XML.replace(".1234567Z", ".1234568Z"))
    assert native["@timestamp"] == second_tick["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert native["win.timestamp_remainder"] == 7 and second_tick["win.timestamp_remainder"] == 8
    assert native["event.id"] != second_tick["event.id"]
    assert normalize_event(XML.replace("DC01", "DC02"))["event.id"] != native["event.id"]
    assert normalize_event(XML.replace("2026-01-01", "2026-01-02"))["event.id"] != native["event.id"]


@pytest.mark.parametrize("original,replacement", [
    (">4769<", ">4624<"), (">0</Version>", ">1</Version>"),
    (">Security<", ">System<"), ("Microsoft-Windows-Security-Auditing", "Other-Provider"),
    (">1001<", ">18446744073709551616<"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10.1234567+03:60"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10.12345678Z"),
    ("2026-01-01T00:00:10.1234567Z", "1969-12-31T23:59:59Z"),
    ("::ffff:192.0.2.10", "fe80::1%eth0"),
])
def test_unsupported_or_malformed_native_metadata_fails(original, replacement):
    with pytest.raises(ValueError):
        normalize_event(XML.replace(original, replacement))


@pytest.mark.parametrize("extra,location", [
    ("<System/>", "</System>"), ("<EventData/>", "</EventData>"),
    ("<Version>2</Version>", "</System>"),
    ('<Data Name="ServiceSid">S-1-5-21-1</Data>', "</EventData>"),
    ('<Data Name="Nested"><Data>value</Data></Data>', "</EventData>"),
])
def test_ambiguous_duplicate_or_nested_xml_fails(extra, location):
    if extra in {"<System/>", "<EventData/>"}:
        changed = XML.replace(location, location + extra)
    else:
        changed = XML.replace(location, extra + location)
    with pytest.raises(ValueError):
        normalize_event(changed)


def test_dtd_is_not_accepted():
    with pytest.raises(ValueError, match="DTD"):
        normalize_event('<!DOCTYPE Event [<!ENTITY a "example">]>' + XML)


@pytest.mark.parametrize("field,value", [
    ("win.status", "0x0"), ("win.status", False), ("ticket.encryption_type", 23.0),
    ("ticket.encryption_type", 2**32), ("user.name", "ALICE"), ("user.domain", "LAB.EXAMPLE"),
    ("host.name", "DC01"), ("source.ip", "::ffff:192.0.2.10"), ("source.ip", "not-an-ip"),
    ("service.id", "S-1-0-0"), ("service.id", "s-1-5-21-1"), ("service.id", "service-name"),
    ("service.name", ["svc1", "svc2"]), ("user", {"name": "alice"}),
    ("event.record_id", "001001"), ("event.channel", "System"),
    ("event.version", True), ("win.timestamp_remainder", 10),
    ("event.code", 4769), ("event.dataset", "windows.security.logons"),
    ("event.id", "я" * 257), ("@timestamp", "2262-04-11T23:47:16.854776Z"),
])
def test_normalized_profile_rejects_ambiguous_or_incompatible_scalars(field, value):
    event = {**normalize_event(XML), field: value}
    with pytest.raises(ValueError):
        kerberos_profile.prepare_events([event])


def test_incomplete_normalized_events_remain_missing_and_duplicate_ids_are_checked():
    minimal = {key: normalize_event(XML)[key] for key in ("@timestamp", "event.id", "event.dataset", "event.code")}
    minimal["service.id"] = None
    prepared, counters = kerberos_profile.prepare_events([minimal, minimal])
    assert prepared == [minimal]
    assert counters == {"input_events": 2, "unique_events": 1, "duplicate_events": 1}
    with pytest.raises(HuntError, match="conflicting duplicate"):
        kerberos_profile.prepare_events([minimal, {**minimal, "service.name": "different"}])


def test_cli_validates_whole_batch_before_output_and_deduplicates(tmp_path):
    first, second = tmp_path / "first.xml", tmp_path / "second.xml"
    first.write_text(XML)
    second.write_text(XML.replace(">1001<", ">0001001<"))
    command = [sys.executable, str(ROOT / "tools/normalize_windows_kerberos.py"), str(first), str(second)]
    good = subprocess.run(command, capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert [json.loads(line) for line in good.stdout.splitlines()] == [normalize_event(XML)]
    second.write_text(replace_field(XML, "ServiceSid", "invalid"))
    bad = subprocess.run(command, capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stdout == ""
    second.write_text(replace_field(XML, "TargetUserName", "Other"))
    conflict = subprocess.run(command, capture_output=True, text=True)
    assert conflict.returncode != 0 and conflict.stdout == "" and "conflicting duplicate" in conflict.stderr
