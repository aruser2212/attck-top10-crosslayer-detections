from pathlib import Path
import json
import subprocess
import sys

import pytest

from tools.normalize_windows_auth import normalize_event
from tools.hunt_engine import HuntError, evaluate_hunt, load_hunt, prepare_events

XML = (Path(__file__).parent / "fixtures/windows/4625.xml").read_text()


def test_target_account_not_subject_and_ip_canonicalized():
    event = normalize_event(XML)
    assert event["target.user"] == "lab\\alice"
    assert event["source.ip"] == "192.0.2.10"
    assert event["event.dataset"] == "windows.security.logons"
    assert event["event.code"] == "4625"
    assert event["@timestamp"] == "2026-01-01T00:00:10Z"


def test_identity_survives_formatting_but_not_record_reuse():
    event = normalize_event(XML)
    assert normalize_event(XML.replace("  ", "    "))["event.id"] == event["event.id"]
    assert normalize_event(XML.replace("2026-01-01", "2026-01-02"))["event.id"] != event["event.id"]
    assert normalize_event(XML.replace("lab-client", "other-client"))["event.id"] != event["event.id"]


def test_native_windows_100ns_precision_is_preserved_in_identity():
    first = normalize_event(XML.replace(".0000000Z", ".1234561Z"))
    second = normalize_event(XML.replace(".0000000Z", ".1234562Z"))
    assert first["@timestamp"] == second["@timestamp"] == "2026-01-01T00:00:10.123456Z"
    assert first["event.id"] != second["event.id"]


def test_missing_ip_and_target_remain_missing():
    event = normalize_event(XML.replace("::ffff:192.0.2.10", "-").replace(">alice<", ">-<"))
    assert "source.ip" not in event
    assert "target.user" not in event


def test_domains_are_not_merged():
    assert normalize_event(XML)["target.user"] != normalize_event(XML.replace(">LAB<", ">OTHER<"))["target.user"]


def test_ascii_account_and_domain_case_variants_merge():
    assert normalize_event(XML)["target.user"] == normalize_event(XML.replace(">alice<", ">ALICE<").replace(">LAB<", ">lab<"))["target.user"]


def test_unicode_expansions_are_not_guessed_as_same_principal():
    assert normalize_event(XML.replace(">alice<", ">straße<"))["target.user"] != normalize_event(XML.replace(">alice<", ">strasse<"))["target.user"]


def test_capitalization_variants_do_not_create_spray_or_split_brute():
    names = ["alice", "ALICE", "Alice", "aLiCe", "AlIcE"] * 3
    events = [normalize_event(XML.replace(">alice<", f">{name}<").replace(">1001<", f">{1001+i}<")) for i, name in enumerate(names)]
    root = Path(__file__).resolve().parents[1] / "techniques/T1110_Brute_Force/hunts"
    spray = evaluate_hunt(load_hunt(root / "win_4625_spray_agg.hunt.yaml"), events)
    brute = evaluate_hunt(load_hunt(root / "win_4625_brute_agg.hunt.yaml"), events)
    assert spray["alerts"] == []
    assert len(brute["alerts"]) == 1
    assert brute["alerts"][0]["fails"] == 15


@pytest.mark.parametrize("original,replacement", [
    (">4625<", ">4769<"),
    (">Security<", ">System<"),
    ("Microsoft-Windows-Security-Auditing", "Another-Provider"),
    ("::ffff:192.0.2.10", "not-an-ip"),
    ("2026-01-01T00:00:10.0000000Z", "2026-01-01T00:00:10"),
    (">1001<", ">abc<"),
    ('<Data Name="SubjectUserName">', '<Data Name="TargetUserName">'),
])
def test_malformed_or_unsupported_events_fail(original, replacement):
    with pytest.raises(ValueError):
        normalize_event(XML.replace(original, replacement))


def test_dtd_is_rejected():
    with pytest.raises(ValueError, match="DTD"):
        normalize_event('<!DOCTYPE Event [<!ENTITY x "example">]>' + XML)


def test_record_and_computer_format_variants_are_one_source_event_not_brute_force():
    root = Path(__file__).resolve().parents[1]
    variants = [XML.replace(">1001<", f">{'0' * i}1001<").replace(
        "lab-client.example.test", "LAB-CLIENT.EXAMPLE.TEST" if i % 2 else "lab-client.example.test"
    ) for i in range(10)]
    events = [normalize_event(xml) for xml in variants]
    assert len({event["event.id"] for event in events}) == 1
    assert {event["host.name"] for event in events} == {"lab-client.example.test"}
    result = evaluate_hunt(load_hunt(root / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml"), events)
    assert result["alerts"] == []
    assert result["summary"]["unique_events"] == 1
    assert result["summary"]["duplicate_events"] == 9


@pytest.mark.parametrize("record", ["0", "18446744073709551615"])
def test_unsigned_64_bit_record_id_boundaries_are_canonical(record):
    native = normalize_event(XML.replace(">1001<", f">{record}<"))
    padded = normalize_event(XML.replace(">1001<", f">000{record}<"))
    assert native == padded


@pytest.mark.parametrize("record", ["18446744073709551616", "-1", "+1001", "١٠٠١", "１００１", "1e3"])
def test_non_native_or_out_of_range_record_ids_fail(record):
    with pytest.raises(ValueError, match="EventRecordID"):
        normalize_event(XML.replace(">1001<", f">{record}<"))


@pytest.mark.parametrize("name,extra", [
    ("EventID", "<EventID>4624</EventID>"),
    ("Computer", "<Computer>another-host</Computer>"),
    ("Channel", "<Channel>System</Channel>"),
    ("EventRecordID", "<EventRecordID>2000</EventRecordID>"),
    ("Provider", '<Provider Name="Different-Provider"/>'),
    ("TimeCreated", '<TimeCreated SystemTime="2026-01-02T00:00:10Z"/>'),
])
def test_duplicate_system_metadata_is_rejected_even_if_first_value_would_pass(name, extra):
    with pytest.raises(ValueError, match=f"exactly one System/{name}"):
        normalize_event(XML.replace("</System>", extra + "</System>"))


def test_multiple_system_containers_are_rejected():
    with pytest.raises(ValueError, match="exactly one System element"):
        normalize_event(XML.replace("</System>", "</System><System/>"))


@pytest.mark.parametrize("source", [
    "2026-01-01T04:00:10.1234567+03:60",
    "2026-01-01T00:00:10.1234567-00:60",
    "2026-01-01T00:00:10.1234567+24:00",
])
def test_invalid_native_timestamp_offsets_fail_without_silent_correction(source):
    with pytest.raises(ValueError, match="timestamp"):
        normalize_event(XML.replace("2026-01-01T00:00:10.0000000Z", source))


def test_equivalent_timezone_exports_preserve_100ns_identity():
    original = normalize_event(XML.replace(".0000000Z", ".1234567Z"))
    offset = normalize_event(XML.replace(
        "2026-01-01T00:00:10.0000000Z", "2026-01-01T03:00:10.1234567+03:00"
    ))
    assert original == offset
    assert original["@timestamp"] == "2026-01-01T00:00:10.123456Z"


def test_scoped_ipv6_requires_explicit_collector_mapping():
    with pytest.raises(ValueError, match="Scoped source IP"):
        normalize_event(XML.replace("::ffff:192.0.2.10", "fe80::1%eth0"))


def test_conflicting_payload_with_canonical_source_identity_is_rejected():
    original = normalize_event(XML)
    conflict = normalize_event(XML.replace(">1001<", ">001001<").replace(
        "lab-client", "LAB-CLIENT").replace(">alice<", ">bob<"))
    assert original["event.id"] == conflict["event.id"]
    with pytest.raises(HuntError, match="conflicting duplicate"):
        prepare_events([original, conflict])


def test_cli_deduplicates_equivalent_sources_and_fails_conflicts_before_output(tmp_path):
    first, second = tmp_path / "first.xml", tmp_path / "second.xml"
    first.write_text(XML)
    second.write_text(XML.replace(">1001<", ">001001<").replace("lab-client", "LAB-CLIENT"))
    command = [sys.executable, str(Path(__file__).resolve().parents[1] / "tools/normalize_windows_auth.py"), str(first), str(second)]
    deduplicated = subprocess.run(command, text=True, capture_output=True)
    assert deduplicated.returncode == 0, deduplicated.stderr
    assert [json.loads(line) for line in deduplicated.stdout.splitlines()] == [normalize_event(XML)]
    second.write_text(second.read_text().replace(">alice<", ">bob<"))
    conflict = subprocess.run(command, text=True, capture_output=True)
    assert conflict.returncode != 0
    assert conflict.stdout == ""
    assert "conflicting duplicate" in conflict.stderr
