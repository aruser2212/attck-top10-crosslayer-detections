"""Synthetic native-shaped Security XML checks for exact local-session identity."""
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from tools.normalize_windows_sessions import normalize_event


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tests/fixtures/newcredentials/native"
LOGON0 = (NATIVE / "newcredentials-v0.xml").read_text()
LOGON2 = (NATIVE / "newcredentials-v2.xml").read_text()
PRIVILEGES = (NATIVE / "special-privileges-v0.xml").read_text()
BOOT = "trusted-lab-boot-a"
SID = "S-1-5-21-100-200-300-1001"


def normalized(xml=LOGON2, *, boot=BOOT):
    return normalize_event(xml, boot_id=boot)


def field(xml, name, value):
    root = ET.fromstring(xml)
    node = root.find(f"{{*}}EventData/{{*}}Data[@Name='{name}']")
    assert node is not None
    node.text = value
    return ET.tostring(root, encoding="unicode")


def without_field(xml, name):
    root = ET.fromstring(xml)
    parent = root.find("{*}EventData")
    node = parent.find(f"{{*}}Data[@Name='{name}']")
    assert node is not None
    parent.remove(node)
    return ET.tostring(root, encoding="unicode")


@pytest.mark.parametrize("xml,version", [(LOGON0, 0), (LOGON2, 2)])
def test_native_logon_maps_target_local_identity_not_creator_or_outbound_credentials(xml, version):
    actual = normalized(xml)
    assert actual["event.dataset"] == "windows.security.sessions"
    assert actual["event.code"] == "4624"
    assert actual["event.provider"] == "Microsoft-Windows-Security-Auditing"
    assert actual["event.channel"] == "Security"
    assert actual["event.version"] == version
    assert actual["host.name"] == "ws01.lab.example"
    assert actual["host.boot.id"] == BOOT
    assert actual["session.id"] == "0xabcde"
    assert actual["user.id"] == SID
    assert actual["user.name"] == "local-operator"
    assert actual["user.domain"] == "lab"
    assert actual["win.logon_type"] == 9
    assert actual["win.logon_process"] == "seclogo"
    assert "win.privileges" not in actual
    assert len(actual["event.id"]) == len("windows-session:") + 64
    assert actual["event.id"].startswith("windows-session:")
    altered = field(xml, "SubjectUserSid", "S-1-5-18")
    altered = field(altered, "SubjectLogonId", "0x999")
    assert normalized(altered) == actual
    if version == 2:
        altered = field(xml, "TargetOutboundUserName", "Different-Network-User")
        altered = field(altered, "TargetOutboundDomainName", "OTHER")
        altered = field(altered, "TargetLinkedLogonId", "0x9999")
        assert normalized(altered) == actual


def test_privilege_event_maps_subject_to_same_local_session_and_tokenizes_native_whitespace():
    logon, special = normalized(), normalized(PRIVILEGES)
    for key in ("host.name", "host.boot.id", "session.id", "user.id", "@timestamp"):
        assert logon[key] == special[key]
    assert special["event.code"] == "4672"
    assert special["event.version"] == 0
    assert special["event.record_id"] == "3002"
    assert special["win.privileges"] == ["SeDebugPrivilege", "SeImpersonatePrivilege"]
    assert "win.logon_type" not in special and "win.logon_process" not in special
    padded = field(PRIVILEGES, "PrivilegeList", " \n\tSeDebugPrivilege  SeImpersonatePrivilege\r\nSeDebugPrivilege ")
    assert normalized(padded) == special


@pytest.mark.parametrize("xml,name", [
    (LOGON2, "TargetLogonId"), (LOGON2, "TargetUserSid"),
    (LOGON2, "LogonType"), (LOGON2, "LogonProcessName"),
    (PRIVILEGES, "SubjectLogonId"), (PRIVILEGES, "SubjectUserSid"),
    (PRIVILEGES, "PrivilegeList"),
])
@pytest.mark.parametrize("value", [None, "", "-", "  "])
def test_missing_join_or_event_semantics_never_become_silent_nonmatches(xml, name, value):
    candidate = without_field(xml, name) if value is None else field(xml, name, value)
    with pytest.raises(ValueError):
        normalized(candidate)


@pytest.mark.parametrize("value,expected", [
    ("0X000ABCDE", "0xabcde"), ("703710", "0xabcde"),
    ("000703710", "0xabcde"), ("0x0001", "0x1"),
    ("18446744073709551615", "0xffffffffffffffff"),
    ("0xFFFFFFFFFFFFFFFF", "0xffffffffffffffff"),
    ("0x" + "0" * 5000 + "abcde", "0xabcde"),
])
def test_native_luid_hex_decimal_and_padding_normalize_without_pid_substitution(value, expected):
    for xml, key in ((LOGON2, "TargetLogonId"), (PRIVILEGES, "SubjectLogonId")):
        assert normalized(field(xml, key, value))["session.id"] == expected


@pytest.mark.parametrize("value", [
    "0", "0x0", "000", "-1", "+1", "1.0", "true", "0x", "0xGG", " 0x1", "0x1 ",
    "18446744073709551616", "0x10000000000000000", "１２", "1_000",
])
def test_invalid_or_null_luid_is_rejected(value):
    with pytest.raises(ValueError):
        normalized(field(LOGON2, "TargetLogonId", value))


@pytest.mark.parametrize("value", ["S-1-0-0", "s-1-0-0", "S-1-5", "S-2-5-18", "invalid", "S-1-5--1", " S-1-5-18"])
def test_invalid_or_null_sid_is_rejected(value):
    with pytest.raises(ValueError):
        normalized(field(PRIVILEGES, "SubjectUserSid", value))


def test_sid_text_has_canonical_numeric_representation():
    xml = field(LOGON2, "TargetUserSid", "s-1-0x5-021-100-200-300-01001")
    assert normalized(xml)["user.id"] == SID


@pytest.mark.parametrize("value", ["-1", "0x9", "9.0", "true", "4294967296", "９"])
def test_invalid_logon_type_is_rejected(value):
    with pytest.raises(ValueError):
        normalized(field(LOGON2, "LogonType", value))


def test_noncandidate_native_logon_type_and_padded_process_are_preserved():
    actual = normalized(field(field(LOGON2, "LogonType", "0003"), "LogonProcessName", "User32 "))
    assert actual["win.logon_type"] == 3
    assert actual["win.logon_process"] == "user32"
    assert normalized(field(LOGON2, "LogonProcessName", " SeClOgO\t"))["win.logon_process"] == "seclogo"


@pytest.mark.parametrize("value", ["NotAPrivilege", "sedebugprivilege", "SeDebugPrivilege;SeTcbPrivilege", "SeDebugPrivilege\x7f"])
def test_invalid_privilege_tokens_do_not_create_an_empty_or_guessed_privilege_set(value):
    with pytest.raises(ValueError):
        normalized(field(PRIVILEGES, "PrivilegeList", value))


@pytest.mark.parametrize("boot", [None, 1, True, "", " ", "-", " boot", "boot ", "boot\nother", "boot\x7f", "\ud800"])
def test_boot_scope_is_explicit_strict_text_and_never_inferred(boot):
    with pytest.raises(ValueError):
        normalized(boot=boot)


def test_boot_context_is_required_by_api_and_changes_event_identity():
    with pytest.raises(TypeError):
        normalize_event(LOGON2)
    original, other = normalized(), normalized(boot="trusted-lab-boot-b")
    assert original["event.id"] != other["event.id"]
    assert {k: v for k, v in original.items() if k not in {"event.id", "host.boot.id"}} == {
        k: v for k, v in other.items() if k not in {"event.id", "host.boot.id"}}


@pytest.mark.parametrize("xml,name,target", [
    (LOGON2, "TargetUserName", "user.name"), (LOGON2, "TargetDomainName", "user.domain"),
    (PRIVILEGES, "SubjectUserName", "user.name"), (PRIVILEGES, "SubjectDomainName", "user.domain"),
])
def test_optional_account_context_does_not_substitute_join_identity(xml, name, target):
    for value in (None, "", "-"):
        actual = normalized(without_field(xml, name) if value is None else field(xml, name, value))
        assert target not in actual
        assert actual["user.id"] == SID and actual["session.id"] == "0xabcde"


def test_native_ticks_are_identity_evidence_but_not_additional_replay_precision():
    original, later = normalized(), normalized(LOGON2.replace(".1234567Z", ".1234568Z"))
    assert original["@timestamp"] == later["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert original["win.timestamp_remainder"] == 7 and later["win.timestamp_remainder"] == 8
    assert original["event.id"] != later["event.id"]
    assert normalized(LOGON2.replace("WS01", "WS02"))["event.id"] != original["event.id"]
    assert normalized(LOGON2.replace(">3001<", ">3003<"))["event.id"] != original["event.id"]


def test_timezone_host_record_and_luid_padding_normalize_to_identical_events():
    alternate = LOGON2.replace("WS01.LAB.EXAMPLE", "ws01.lab.example").replace(
        ">3001<", ">0003001<").replace("2026-01-01T00:00:10.1234567Z", "2026-01-01T03:00:10.1234567+03:00")
    alternate = field(alternate, "TargetLogonId", "703710")
    assert normalized(alternate) == normalized()


@pytest.mark.parametrize("value", [
    "2026-01-01T00:00:10", "2026-01-01 00:00:10Z", "2026-01-01T00:00:10.12345678Z",
    "2026-02-30T00:00:10Z", "1969-12-31T23:59:59Z", "2263-01-01T00:00:00Z", "",
])
def test_invalid_or_unsupported_timestamp_is_rejected(value):
    with pytest.raises(ValueError):
        normalized(LOGON2.replace("2026-01-01T00:00:10.1234567Z", value))


@pytest.mark.parametrize("value", ["-1", "true", "1.0", "0x1", "18446744073709551616", "１２"])
def test_invalid_record_identity_is_rejected(value):
    with pytest.raises(ValueError):
        normalized(LOGON2.replace(">3001<", ">" + value + "<"))


@pytest.mark.parametrize("xml", [
    LOGON2.replace('Name="Microsoft-Windows-Security-Auditing"', 'Name="Other-Provider"'),
    LOGON2.replace("<Channel>Security</Channel>", "<Channel>System</Channel>"),
    LOGON2.replace("<EventID>4624</EventID>", "<EventID>4625</EventID>"),
    LOGON2.replace("<Version>2</Version>", "<Version>1</Version>"),
    PRIVILEGES.replace("<Version>0</Version>", "<Version>2</Version>"),
    LOGON2.replace("<Version>2</Version>", "<Version>true</Version>"),
    LOGON2.replace("<Computer>WS01.LAB.EXAMPLE</Computer>", "<Computer> WS01.LAB.EXAMPLE </Computer>"),
    LOGON2.replace('xmlns="http://schemas.microsoft.com/win/2004/08/events/event"', ''),
    "<!DOCTYPE Event>" + LOGON2,
    "<!DOCTYPE Event [<!ENTITY bogus 'text'>]>" + LOGON2,
])
def test_source_namespace_native_version_and_provider_contract(xml):
    with pytest.raises(ValueError):
        normalized(xml)


@pytest.mark.parametrize("mutation", [
    "missing_system", "duplicate_system", "missing_eventdata", "duplicate_eventdata",
    "duplicate_system_element", "nested_system_element", "duplicate_data", "unnamed_data", "nested_data",
])
def test_ambiguous_xml_structure_is_rejected(mutation):
    root = ET.fromstring(LOGON2)
    system, data = root.find("{*}System"), root.find("{*}EventData")
    if mutation == "missing_system": root.remove(system)
    elif mutation == "duplicate_system": root.append(ET.fromstring(ET.tostring(system)))
    elif mutation == "missing_eventdata": root.remove(data)
    elif mutation == "duplicate_eventdata": root.append(ET.fromstring(ET.tostring(data)))
    elif mutation == "duplicate_system_element": system.append(ET.fromstring(ET.tostring(system[0])))
    elif mutation == "nested_system_element": ET.SubElement(system[0], "Child")
    elif mutation == "duplicate_data": data.append(ET.fromstring(ET.tostring(data[0])))
    elif mutation == "unnamed_data": data[0].attrib.pop("Name")
    elif mutation == "nested_data": ET.SubElement(data[0], "Child")
    with pytest.raises(ValueError):
        normalized(ET.tostring(root, encoding="unicode"))


def test_unknown_scalar_native_data_is_explicitly_ignored_not_converted_to_identity():
    root = ET.fromstring(LOGON2)
    ET.SubElement(root.find("{*}EventData"), "{http://schemas.microsoft.com/win/2004/08/events/event}Data",
                  Name="FutureField").text = "not-a-session-key"
    assert normalized(ET.tostring(root, encoding="unicode")) == normalized()


def cli(*args, cwd=ROOT):
    return subprocess.run([sys.executable, str(ROOT / "tools/normalize_windows_sessions.py"), *map(str, args)],
                          cwd=cwd, capture_output=True, text=True)


def test_cli_outside_repository_has_explicit_boot_and_batch_dedup(tmp_path):
    result = cli("--boot-id", BOOT, NATIVE / "newcredentials-v2.xml", NATIVE / "special-privileges-v0.xml",
                 NATIVE / "newcredentials-v2.xml", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert events == [normalized(), normalized(PRIVILEGES)]


def test_cli_refuses_missing_boot_without_guessing(tmp_path):
    result = cli(NATIVE / "newcredentials-v2.xml", cwd=tmp_path)
    assert result.returncode != 0 and not result.stdout
    assert "--boot-id" in result.stderr


@pytest.mark.parametrize("bad_xml", ["<not-an-event>", field(LOGON2, "TargetUserSid", "S-1-0-0"),
                                     field(LOGON2, "TargetUserSid", "S-1-5-21-100-200-300-1999")])
def test_cli_never_emits_partial_output_for_later_invalid_or_conflicting_input(tmp_path, bad_xml):
    path = tmp_path / "bad.xml"
    path.write_text(bad_xml)
    result = cli("--boot-id", BOOT, NATIVE / "newcredentials-v2.xml", path, cwd=tmp_path)
    assert result.returncode == 1
    assert not result.stdout and "Session normalization failed" in result.stderr
