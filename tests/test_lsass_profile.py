"""The native source contract is strict independently of candidate matching."""
from copy import deepcopy
import json

import pytest

from tools import lsass_profile as profile


def event(**changes):
    return {
        "@timestamp": "2026-01-01T00:00:00Z", "event.id": "access-1",
        "event.dataset": profile.DATASET, "event.code": "10", "host.name": "host01.example",
        "source.process.guid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "target.process.guid": "11111111-2222-3333-4444-555555555555",
        "source.image": "C:\\Tools\\collector.exe", "target.image": "C:\\Windows\\System32\\lsass.exe",
        "process.access_mask": 0x1010, **changes,
    }


def test_supported_source_context_keeps_original_paths_and_does_not_mutate_input():
    original = event(**{
        "event.provider": profile.PROVIDER, "event.channel": profile.CHANNEL,
        "event.record_id": "18446744073709551615", "event.version": 3,
        "win.timestamp_remainder": 9, "source.process.pid": 0, "target.process.pid": 2**32 - 1,
        "source.user": "LAB\\Alice", "target.user": "NT AUTHORITY\\SYSTEM",
        "process.call_trace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9e0f4",
    })
    before = deepcopy(original)
    prepared, counts = profile.prepare_events([original])
    assert original == before == prepared[0]
    assert counts == {"input_events": 1, "unique_events": 1, "duplicate_events": 0}


def test_optional_unknown_context_can_be_absent_or_null():
    original = event(**{field: None for field in profile.OPTIONAL_FIELDS})
    assert profile.prepare_events([original])[0] == [original]


@pytest.mark.parametrize("field", sorted(profile.REQUIRED_FIELDS))
def test_missing_required_evidence_fails_instead_of_producing_a_benign_record(field):
    item = event()
    del item[field]
    with pytest.raises(ValueError):
        profile.prepare_events([item])


@pytest.mark.parametrize("field,value", [
    ("event.id", " "), ("event.id", " leading"), ("event.id", "bad\x00id"),
    ("event.id", 10), ("event.id", False), ("event.id", None),
    ("host.name", "HOST01.example"), ("host.name", "host01.example "),
    ("host.name", "-"), ("host.name", "bad\x7fhost"), ("host.name", None),
    ("event.code", 10), ("event.code", "010"), ("event.code", "1"),
    ("event.dataset", "windows.security.logons"), ("event.dataset", "Windows.Sysmon.Process_Access"),
    ("source.user", "-"), ("target.user", " alice"), ("process.call_trace", ""),
    ("process.call_trace", "frame\nframe"), ("source.image", None),
    ("event.provider", "Microsoft-Windows-Security-Auditing"),
    ("event.channel", "Security"), ("event.version", 0), ("event.version", True),
    ("event.version", "3"), ("win.timestamp_remainder", -1),
    ("win.timestamp_remainder", 10), ("win.timestamp_remainder", True),
])
def test_field_types_source_scope_and_placeholder_values_are_enforced(field, value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{field: value})])


@pytest.mark.parametrize("field", ["process.access_mask", "source.process.pid", "target.process.pid"])
@pytest.mark.parametrize("value", [True, False, -1, 2**32, 16.0, "16", "0x10"])
def test_masks_and_pids_never_use_elastic_numeric_coercion(field, value):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        profile.prepare_events([event(**{field: value})])


@pytest.mark.parametrize("mask", [0, 1, 0x1000, 0x10, 2**32 - 1])
def test_valid_masks_are_admitted_independent_of_candidate_classification(mask):
    original = event(**{"process.access_mask": mask})
    assert profile.prepare_events([original])[0] == [original]


@pytest.mark.parametrize("record", ["00", "01", "-1", "0x10", "18446744073709551616", "1" * 100, 7, False])
def test_record_ids_require_bounded_canonical_decimal_text(record):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{"event.record_id": record})])


def test_event_identity_obeys_utf8_byte_limit_not_character_count():
    accepted = event(**{"event.id": "я" * 256})
    assert profile.prepare_events([accepted])[0] == [accepted]
    with pytest.raises(ValueError, match="512-byte"):
        profile.prepare_events([event(**{"event.id": "я" * 257})])


@pytest.mark.parametrize("field", ["event.id", "host.name", "source.user", "source.image"])
def test_source_text_must_encode_as_utf8(field):
    with pytest.raises(ValueError, match="UTF-8"):
        profile.prepare_events([event(**{field: "bad\ud800text"})])


@pytest.mark.parametrize("field,value", [
    ("collector", "extra"), ("event", "scalar"), ("source.process", "scalar"),
    ("source.process.guid.child", "alias"), ("@timestamp.child", "alias"),
    ("_id", "reserved"), ("source", {"image": "C:\\wrong.exe"}),
    ("process.access_mask", [16]), ("source.image", {"value": "C:\\bad.exe"}),
])
def test_unknown_fields_and_nested_aliases_cannot_bypass_the_flat_profile(field, value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{field: value})])


@pytest.mark.parametrize("value", [
    "00000000-0000-0000-0000-000000000000", "{00000000-0000-0000-0000-000000000000}",
    "aaaaaaaabbbbccccddddeeeeeeeeeeee", "not-a-guid",
    "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
    "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", None,
])
def test_native_guid_parser_requires_an_explicit_nonzero_guid(value):
    with pytest.raises(ValueError):
        profile.canonical_guid(value)


def test_native_guid_canonicalization_does_not_impose_rfc_uuid_version_rules():
    assert profile.canonical_guid("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert profile.canonical_guid("00000000-0000-0000-0000-000000000001") == "00000000-0000-0000-0000-000000000001"


@pytest.mark.parametrize("value", ["{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"])
def test_normalized_profile_does_not_silently_rewrite_process_identity(value):
    with pytest.raises(ValueError, match="canonical lowercase"):
        profile.prepare_events([event(**{"source.process.guid": value})])


@pytest.mark.parametrize("path", [
    "lsass.exe", "C:lsass.exe", "\\Windows\\lsass.exe", "/Windows/lsass.exe",
    "\\\\server\\share\\lsass.exe", "\\\\?\\C:\\Windows\\lsass.exe",
    "\\Device\\HarddiskVolume1\\Windows\\lsass.exe", "C:/Windows/lsass.exe",
    "C:\\Windows\\lsass.exe:stream", "C:\\Windows\\..\\lsass.exe",
    "C:\\Windows\\.\\lsass.exe", "C:\\Windows\\\\lsass.exe", "C:\\Windows\\",
    "C:\\Windows \\lsass.exe", "C:\\Windows.\\lsass.exe", "C:\\Windows\\lsass.exe.",
    "C:\\Windows\\lsass.exe ", "C:\\Windows\\lsa*ss.exe", 'C:\\Windows\\"lsass.exe"',
    "C:\\Windows\\lsass.exe\x00", "C:\\Windows\\lsa\x7fss.exe",
])
def test_unsupported_or_ambiguous_image_paths_fail_the_source_contract(path):
    with pytest.raises(ValueError):
        profile.canonical_image(path)
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{"target.image": path})])


@pytest.mark.parametrize("path", ["c:\\Windows\\SYSTEM32\\LSASS.EXE", "D:\\Tools\\échantillon.exe", "C:\\Users\\Public\\lsass.exe"])
def test_supported_images_preserve_exact_case_and_do_not_attest_system_location(path):
    assert profile.canonical_image(path) == path
    assert profile.prepare_events([event(**{"target.image": path})])[0][0]["target.image"] == path


@pytest.mark.parametrize("path", [
    "C:\\CON\\lsass.exe", "C:\\Tools\\NUL.exe", "C:\\Tools\\prn.ExE",
    "C:\\AuX\\lsass.exe", "C:\\COM1\\lsass.exe", "C:\\Tools\\com9.exe",
    "C:\\LPT1\\lsass.exe", "C:\\Tools\\Lpt9.exe", "C:\\CONIN$\\lsass.exe",
    "C:\\Tools\\conout$.exe", "C:\\COM¹\\lsass.exe", "C:\\Tools\\com².exe",
    "C:\\COM³\\lsass.exe", "C:\\Tools\\LPT¹.exe", "C:\\Lpt²\\lsass.exe",
    "C:\\Tools\\lpt³.exe",
])
def test_dos_device_aliases_cannot_supply_either_process_image(path):
    with pytest.raises(ValueError, match="DOS device alias"):
        profile.canonical_image(path)
    for field in ("source.image", "target.image"):
        with pytest.raises(ValueError, match="DOS device alias"):
            profile.prepare_events([event(**{field: path})])


@pytest.mark.parametrize("path", [
    "C:\\COM10\\lsass.exe", "C:\\Tools\\LPT10.exe", "C:\\Tools\\CONSOLE.EXE",
    "C:\\AUXILIARY\\lsass.exe", "C:\\Tools\\NULL.exe", "C:\\Tools\\COM1-helper.exe",
])
def test_device_like_ordinary_names_remain_accepted_image_paths(path):
    assert profile.canonical_image(path) == path
    item = event(**{"source.image": path, "target.image": path})
    assert profile.prepare_events([item])[0] == [item]


def test_timestamp_normalization_and_immutable_duplicate_id_contract():
    first = event(**{"@timestamp": "2026-01-01T01:00:00.000001+01:00"})
    equivalent = event(**{"@timestamp": "2026-01-01T00:00:00.000001Z"})
    prepared, counts = profile.prepare_events([first, equivalent])
    assert prepared == [equivalent]
    assert counts["duplicate_events"] == 1
    with pytest.raises(ValueError, match="conflicting duplicate"):
        profile.prepare_events([first, {**equivalent, "process.access_mask": 0x1000}])


@pytest.mark.parametrize("timestamp", ["1969-12-31T23:59:59.999999Z", "2262-04-11T23:47:16.854776Z", "2026-01-01T00:00:00.0000001Z"])
def test_profile_rejects_timestamps_outside_its_declared_precision_and_range(timestamp):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{"@timestamp": timestamp})])


def test_mapping_covers_the_entire_accepted_field_contract_with_exact_integer_types():
    mapping = json.loads(profile.MAPPING_PATH.read_text())["mappings"]
    def leaves(properties, prefix=""):
        result = {}
        for name, value in properties.items():
            path = prefix + name
            if "properties" in value:
                result.update(leaves(value["properties"], path + "."))
            else:
                result[path] = value
        return result
    fields = leaves(mapping["properties"])
    assert set(fields) == profile.ALLOWED_FIELDS
    assert mapping["_meta"]["profile"] == profile.PROFILE
    assert fields["@timestamp"]["type"] == "date_nanos"
    for field in ("process.access_mask", "source.process.pid", "target.process.pid", "event.version", "win.timestamp_remainder"):
        assert fields[field]["type"] in {"integer", "long"}
        assert fields[field]["coerce"] is False
