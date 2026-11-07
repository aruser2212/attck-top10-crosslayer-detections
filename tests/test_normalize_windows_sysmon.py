"""Synthetic native-shaped XML checks for the strict Sysmon ProcessAccess source."""
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from tools.normalize_windows_sysmon import normalize_event


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tests/fixtures/lsass/native"
XML = (NATIVE / "process-access-v3.xml").read_text()
QUERY_ONLY = (NATIVE / "benign-query-only-v3.xml").read_text()
SOURCE_GUID = "a1b2c3d4-1111-2222-3333-444455556666"
TARGET_GUID = "a1b2c3d4-7777-8888-9999-aaaabbbbcccc"


def replace_field(xml, name, value):
    event = ET.fromstring(xml)
    field = event.find(f"{{*}}EventData/{{*}}Data[@Name='{name}']")
    assert field is not None
    field.text = value
    return ET.tostring(event, encoding="unicode")


def remove_field(xml, name):
    event = ET.fromstring(xml)
    parent = event.find("{*}EventData")
    field = parent.find(f"{{*}}Data[@Name='{name}']")
    assert field is not None
    parent.remove(field)
    return ET.tostring(event, encoding="unicode")


def test_native_mapping_keeps_guids_and_access_semantics_not_pids_or_name_inference():
    event = normalize_event(XML)
    assert event["event.dataset"] == "windows.sysmon.process_access"
    assert event["event.code"] == "10"
    assert event["event.provider"] == "Microsoft-Windows-Sysmon"
    assert event["event.channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event["event.version"] == 3
    assert event["host.name"] == "ws01.lab.example"
    assert event["event.record_id"] == "1001"
    assert event["source.process.guid"] == SOURCE_GUID
    assert event["target.process.guid"] == TARGET_GUID
    assert event["source.process.pid"] == 4100
    assert event["target.process.pid"] == 680
    assert event["source.image"] == r"C:\Tools\Diagnostic.exe"
    assert event["target.image"] == r"C:\Windows\System32\lsass.exe"
    assert event["process.access_mask"] == 0x1010
    assert event["source.user"] == r"LAB\operator"
    assert event["target.user"] == r"NT AUTHORITY\SYSTEM"
    assert event["process.call_trace"].endswith(r"C:\Tools\Diagnostic.exe+1234")
    assert event["event.id"].startswith("windows-sysmon:")
    assert len(event["event.id"]) == len("windows-sysmon:") + 64
    assert not any(name in event for name in ("SourceThreadId", "UtcTime", "RuleName", "user.name"))


def test_query_only_native_mask_is_kept_without_becoming_read_access():
    event = normalize_event(QUERY_ONLY)
    assert event["process.access_mask"] == 0x1000
    assert event["process.access_mask"] & 0x10 == 0
    assert "process.call_trace" not in event


@pytest.mark.parametrize("name", ["SourceProcessGUID", "TargetProcessGUID", "SourceImage", "TargetImage", "GrantedAccess"])
@pytest.mark.parametrize("value", [None, "", "-", "   "])
def test_missing_required_native_data_is_rejected_without_guessed_identity(name, value):
    xml = remove_field(XML, name) if value is None else replace_field(XML, name, value)
    with pytest.raises(ValueError, match="Missing EventData/" + name):
        normalize_event(xml)


@pytest.mark.parametrize("name,target", [
    ("SourceProcessId", "source.process.pid"), ("TargetProcessId", "target.process.pid"),
    ("SourceUser", "source.user"), ("TargetUser", "target.user"), ("CallTrace", "process.call_trace"),
])
def test_missing_optional_context_is_omitted_without_substitution(name, target):
    for xml in (remove_field(XML, name), replace_field(XML, name, ""), replace_field(XML, name, "-")):
        event = normalize_event(xml)
        assert target not in event
        assert event["source.process.guid"] == SOURCE_GUID
        assert event["target.process.guid"] == TARGET_GUID


def test_equivalent_guid_case_braces_numeric_padding_and_timezone_deduplicate():
    alternate = XML.replace("WS01.LAB.EXAMPLE", "ws01.lab.example").replace(
        ">1001<", ">0001001<").replace("2026-01-01T00:00:10.1234567Z", "2026-01-01T03:00:10.1234567+03:00")
    alternate = replace_field(alternate, "SourceProcessGUID", SOURCE_GUID)
    alternate = replace_field(alternate, "TargetProcessGUID", TARGET_GUID)
    alternate = replace_field(alternate, "SourceProcessId", "0004100")
    alternate = replace_field(alternate, "GrantedAccess", "0004112")
    assert normalize_event(alternate) == normalize_event(XML)


def test_guids_are_not_restricted_to_rfc_uuid_versions_or_variants():
    value = "{ABCDEF01-1234-F678-0123-456789ABCDEF}"
    event = normalize_event(replace_field(XML, "SourceProcessGUID", value))
    assert event["source.process.guid"] == "abcdef01-1234-f678-0123-456789abcdef"


def test_timestamp_uses_systemtime_and_keeps_100ns_identity_without_claiming_precision():
    first = normalize_event(XML)
    second = normalize_event(XML.replace(".1234567Z", ".1234568Z"))
    assert first["@timestamp"] == second["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert first["win.timestamp_remainder"] == 7
    assert second["win.timestamp_remainder"] == 8
    assert first["event.id"] != second["event.id"]
    assert normalize_event(replace_field(XML, "UtcTime", "2020-01-01 00:00:00.000")) == first
    assert normalize_event(remove_field(XML, "UtcTime")) == first
    assert normalize_event(XML.replace(">1001<", ">1002<"))["event.id"] != first["event.id"]
    assert normalize_event(XML.replace("WS01", "WS02"))["event.id"] != first["event.id"]
    assert normalize_event(XML.replace("2026-01-01T", "2026-01-02T"))["event.id"] != first["event.id"]


@pytest.mark.parametrize("timestamp,expected,remainder", [
    ("2026-01-01T00:00:10Z", "2026-01-01T00:00:10Z", 0),
    ("2026-01-01T00:00:10.1Z", "2026-01-01T00:00:10.100000Z", 0),
    ("2026-01-01T00:00:10.0000001Z", "2026-01-01T00:00:10Z", 1),
])
def test_fractional_timestamp_representations_are_exactly_declared(timestamp, expected, remainder):
    event = normalize_event(XML.replace("2026-01-01T00:00:10.1234567Z", timestamp))
    assert event["@timestamp"] == expected
    assert event["win.timestamp_remainder"] == remainder


@pytest.mark.parametrize("value,expected", [
    ("0", 0), ("0x00000000", 0), ("16", 16), ("0X00000010", 16),
    ("4294967295", 2**32 - 1), ("0xFFFFFFFF", 2**32 - 1),
    ("0" * 5000 + "4112", 4112), ("0x" + "0" * 5000 + "1010", 4112),
])
def test_native_mask_normalization_is_bounded_decimal_or_hex(value, expected):
    assert normalize_event(replace_field(XML, "GrantedAccess", value))["process.access_mask"] == expected


@pytest.mark.parametrize("value", [
    "true", "False", "16.0", "-16", "+16", " 16", "16 ", "١٦", "0x", "0b10000",
    "1010h", "0x1_010", "0x100000000", "4294967296", "1" * 5000,
])
def test_bad_mask_is_rejected_instead_of_coerced(value):
    with pytest.raises(ValueError):
        normalize_event(replace_field(XML, "GrantedAccess", value))


@pytest.mark.parametrize("value", ["-1", "0x10", "3.0", "4294967296", "True", "١٦"])
def test_pid_context_is_bounded_decimal_and_never_repairs_a_guid(value):
    with pytest.raises(ValueError):
        normalize_event(replace_field(XML, "SourceProcessId", value))


@pytest.mark.parametrize("value", [
    "00000000-0000-0000-0000-000000000000", "4100", "invalid", SOURCE_GUID.replace("-", ""),
    "{" + SOURCE_GUID, SOURCE_GUID + "}", "{{" + SOURCE_GUID + "}}", " " + SOURCE_GUID,
])
def test_bad_guid_fails_even_when_pid_and_image_are_available(value):
    with pytest.raises(ValueError):
        normalize_event(replace_field(XML, "SourceProcessGUID", value))


@pytest.mark.parametrize("value", [
    "lsass.exe", r"C:lsass.exe", r"\\server\share\lsass.exe", r"\\?\C:\Windows\lsass.exe",
    r"C:\Windows\..\lsass.exe", r"C:\Windows\lsass.exe:alternate", r"C:\Windows\lsass.exe.",
    "C:\\Windows\\lsass.exe ", "C:/Windows/lsass.exe",
])
def test_unsupported_path_forms_fail_without_path_resolution(value):
    with pytest.raises(ValueError):
        normalize_event(replace_field(XML, "TargetImage", value))


def test_path_case_and_non_lsass_targets_are_retained_for_detector_decision():
    image = r"C:\Windows\SYSTEM32\LSASS.EXE"
    assert normalize_event(replace_field(XML, "TargetImage", image))["target.image"] == image
    other = r"C:\Windows\explorer.exe"
    assert normalize_event(replace_field(XML, "TargetImage", other))["target.image"] == other


@pytest.mark.parametrize("original,replacement", [
    (">10</EventID>", ">1</EventID>"), (">3</Version>", ">2</Version>"),
    (">3</Version>", ">03</Version>"), ("Microsoft-Windows-Sysmon\"", "Other-Provider\""),
    ("Microsoft-Windows-Sysmon/Operational", "Security"),
    (">1001<", ">18446744073709551616<"), (">1001<", ">-1<"),
    (">WS01.LAB.EXAMPLE<", ">-<"), (">WS01.LAB.EXAMPLE<", "> WS01.LAB.EXAMPLE<"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10.12345678Z"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10+03:60"),
    ("2026-01-01T00:00:10.1234567Z", "1969-12-31T23:59:59Z"),
    ("2026-01-01T00:00:10.1234567Z", "2262-04-11T23:47:16.854776Z"),
])
def test_source_metadata_is_required_and_exact(original, replacement):
    assert original in XML
    with pytest.raises(ValueError):
        normalize_event(XML.replace(original, replacement))


@pytest.mark.parametrize("extra,location", [
    ("<System/>", "</System>"), ("<EventData/>", "</EventData>"),
    ("<Version>3</Version>", "</System>"), ("<Level>4</Level>", "</System>"),
    ('<TimeCreated SystemTime="2026-01-01T00:00:10Z"/>', "</System>"),
    ('<Data Name="GrantedAccess">0x10</Data>', "</EventData>"),
    ('<Data Name="Unknown"><Data>nested</Data></Data>', "</EventData>"),
    ('<Data Name=" SourceImage">C:\\Other.exe</Data>', "</EventData>"),
    ('<Data>unnamed</Data>', "</EventData>"), ('<Other/>', "</EventData>"),
    ("<Unknown><Child/></Unknown>", "</System>"),
])
def test_duplicate_or_structurally_ambiguous_exports_fail(extra, location):
    placement = location + extra if extra in {"<System/>", "<EventData/>"} else extra + location
    with pytest.raises(ValueError):
        normalize_event(XML.replace(location, placement))


def test_xml_entities_root_and_namespace_are_not_accepted():
    with pytest.raises(ValueError, match="DTD/entities"):
        normalize_event('<!DOCTYPE Event [<!ENTITY payload "test">]>' + XML)
    with pytest.raises(ValueError, match="standard namespace"):
        normalize_event(XML.replace(' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ""))
    with pytest.raises(ValueError, match="standard namespace"):
        normalize_event("<Events>" + XML + "</Events>")


def test_unmapped_scalar_data_is_ignored_but_not_treated_as_alternative_identity():
    native = normalize_event(XML)
    extended = XML.replace("</EventData>", '<Data Name="FutureField">opaque</Data></EventData>')
    assert normalize_event(extended) == native
    wrong_alias = remove_field(XML, "SourceProcessGUID").replace(
        "</ns0:EventData>", f'<ns0:Data Name="SourceProcessGuid">{SOURCE_GUID}</ns0:Data></ns0:EventData>')
    with pytest.raises(ValueError, match="Missing EventData/SourceProcessGUID"):
        normalize_event(wrong_alias)


def test_cli_outside_checkout_validates_whole_batch_before_output(tmp_path):
    first, second = tmp_path / "first.xml", tmp_path / "second.xml"
    first.write_text("\ufeff" + XML)
    second.write_text(XML.replace(">1001<", ">0001001<"))
    command = [sys.executable, str(ROOT / "tools/normalize_windows_sysmon.py"), str(first), str(second)]
    good = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert good.returncode == 0, good.stderr
    assert [json.loads(line) for line in good.stdout.splitlines()] == [normalize_event(XML)]
    second.write_text(replace_field(XML, "GrantedAccess", "broken"))
    bad = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert bad.returncode != 0 and bad.stdout == ""
    second.write_text(replace_field(XML, "GrantedAccess", "0x1000"))
    conflict = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert conflict.returncode != 0 and conflict.stdout == "" and "conflicting duplicate" in conflict.stderr
    second.write_text("<Event>")
    malformed = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert malformed.returncode != 0 and malformed.stdout == ""
