"""Reject incomplete or ambiguous source representations before any session join."""
from copy import deepcopy
import json

import pytest

from tools import newcredentials_profile as profile


def event(code="4624", **changes):
    specific = ({"win.logon_type": 9, "win.logon_process": "seclogo"} if code == "4624"
                else {"win.privileges": ["SeDebugPrivilege", "SeTcbPrivilege"]})
    return {
        "@timestamp": "2026-01-01T00:00:30Z", "event.id": "record-" + code,
        "event.dataset": profile.DATASET, "event.code": code,
        "host.name": "host01.example", "host.boot.id": "boot-A",
        "session.id": "0x1234", "user.id": "S-1-5-21-100-200-300-1001",
        **specific, **changes,
    }


@pytest.mark.parametrize("code,version", [("4624", 0), ("4624", 2), ("4672", 0)])
def test_native_metadata_and_context_preserved_without_mutating_input(code, version):
    original = event(code, **{
        "event.provider": profile.PROVIDER, "event.channel": "Security",
        "event.record_id": "18446744073709551615", "event.version": version,
        "win.timestamp_remainder": 9, "user.name": "alice", "user.domain": "lab.example",
    })
    snapshot = deepcopy(original)
    prepared, counts = profile.prepare_events([original])
    assert original == snapshot == prepared[0]
    assert counts == {"input_events": 1, "unique_events": 1, "duplicate_events": 0}


@pytest.mark.parametrize("code", ["4624", "4672"])
def test_optional_source_context_may_be_absent_or_null(code):
    original = event(code, **{field: None for field in profile.OPTIONAL_FIELDS})
    assert profile.prepare_events([original])[0] == [original]


@pytest.mark.parametrize("code,field", [
    *( (code, field) for code in ("4624", "4672") for field in sorted(profile.REQUIRED_FIELDS)),
    ("4624", "win.logon_type"), ("4624", "win.logon_process"), ("4672", "win.privileges"),
])
def test_missing_join_evidence_is_an_error_not_a_negative_result(code, field):
    item = event(code)
    del item[field]
    with pytest.raises(ValueError):
        profile.prepare_events([item])


@pytest.mark.parametrize("field,value", [
    ("event.code", 4624), ("event.code", None), ("event.code", []), ("event.code", {}),
    ("event.code", "4625"), ("event.dataset", "windows.security.logons"),
    ("event.id", " leading"), ("event.id", "bad\x00id"), ("event.id", None),
    ("host.name", "HOST01"), ("host.name", "-"), ("host.name", None),
    ("host.boot.id", ""), ("host.boot.id", "-"), ("host.boot.id", "boot\nA"),
    ("host.boot.id", None), ("host.boot.id", 1), ("host.boot.id", {"value": "boot-A"}),
    ("user.name", "Alice"), ("user.domain", "DOMAIN"),
    ("win.logon_process", "Seclogo"), ("win.logon_process", "-"),
    ("event.provider", "Microsoft-Windows-Sysmon"), ("event.channel", "System"),
    ("event.version", 1), ("event.version", True), ("event.version", "2"),
    ("win.timestamp_remainder", -1), ("win.timestamp_remainder", 10),
    ("win.timestamp_remainder", True),
])
def test_field_types_provider_and_canonical_context_are_enforced(field, value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{field: value})])


@pytest.mark.parametrize("value", [True, False, -1, 2**32, 9.0, "9", None])
def test_logon_type_is_uint32_without_numeric_coercion(value):
    with pytest.raises(ValueError, match="unsigned 32-bit"):
        profile.prepare_events([event(**{"win.logon_type": value})])


@pytest.mark.parametrize("native,expected", [
    ("0x01", "0x1"), ("0XABCDEF", "0xabcdef"), ("0004660", "0x1234"),
    ("18446744073709551615", "0xffffffffffffffff"),
    ("0x0000000000000000FFFFFFFFFFFFFFFF", "0xffffffffffffffff"),
])
def test_native_logon_id_normalization_is_exact_uint64(native, expected):
    assert profile.canonical_logon_id(native) == expected


@pytest.mark.parametrize("value", [
    "0", "0000", "0x0", "0X000", "-1", "+1", " 1", "1 ", "0x", "0xZZ", "1.0",
    "0x10000000000000000", "18446744073709551616", "١", "1" * 5000,
    None, True, 1, 1.0,
])
def test_missing_zero_malformed_or_overflow_native_logon_id_rejected(value):
    with pytest.raises(ValueError):
        profile.canonical_logon_id(value)


@pytest.mark.parametrize("value", ["4660", "0X1234", "0x01234", "0xABCD"])
def test_profile_requires_already_canonical_logon_ids(value):
    with pytest.raises(ValueError, match="canonical"):
        profile.prepare_events([event(**{"session.id": value})])


@pytest.mark.parametrize("value", [
    "S-1-0-0", "s-1-5-21-100-200-300-1001", "S-1-05-21-100-200-300-1001",
    "LAB\\alice", "S-2-5-1", "S-1-5", "-", None, [],
])
def test_local_token_sid_cannot_be_replaced_by_a_name_or_null_sid(value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{"user.id": value})])


@pytest.mark.parametrize("privileges", [
    [], None, "SeDebugPrivilege", {}, ["SeTcbPrivilege", "SeDebugPrivilege"],
    ["SeDebugPrivilege", "SeDebugPrivilege"], ["sedebugprivilege"], ["-"],
    ["SeDebugPrivilege\n"], [True], [1], [["SeDebugPrivilege"]], ["SeDebugPrivileg"],
])
def test_privileges_are_sorted_unique_native_names_not_coercible_context(privileges):
    with pytest.raises(ValueError):
        profile.prepare_events([event("4672", **{"win.privileges": privileges})])


def test_privilege_names_are_not_a_fixed_detection_allowlist():
    item = event("4672", **{"win.privileges": ["SeFutureFeaturePrivilege"]})
    assert profile.prepare_events([item])[0] == [item]


@pytest.mark.parametrize("code,field,value", [
    ("4624", "win.privileges", ["SeDebugPrivilege"]),
    ("4672", "win.logon_type", 9), ("4672", "win.logon_process", "seclogo"),
    ("4672", "event.version", 2), ("4624", "host", {"name": "host01"}),
    ("4624", "host.boot", "alias"), ("4624", "session", "alias"),
    ("4624", "user.id.child", "alias"), ("4672", "win.privileges.child", "alias"),
    ("4624", "collector", "extra"), ("4624", "session.id", ["0x1234"]),
])
def test_event_specific_fields_and_dotted_aliases_cannot_bypass_profile(code, field, value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(code, **{field: value})])


@pytest.mark.parametrize("value", ["01", "-1", "0x1", "18446744073709551616", 1, True])
def test_record_id_requires_canonical_uint64_decimal(value):
    with pytest.raises(ValueError):
        profile.prepare_events([event(**{"event.record_id": value})])


def test_event_id_limit_is_bytes_and_text_is_valid_utf8():
    assert profile.prepare_events([event(**{"event.id": "я" * 256})])[0]
    with pytest.raises(ValueError, match="512-byte"):
        profile.prepare_events([event(**{"event.id": "я" * 257})])
    with pytest.raises(ValueError, match="UTF-8"):
        profile.prepare_events([event(**{"host.boot.id": "boot\ud800"})])


@pytest.mark.parametrize("timestamp", ["1969-12-31T23:59:59Z", "2262-04-11T23:47:16.854776Z"])
def test_date_nanos_range_is_enforced(timestamp):
    with pytest.raises(ValueError, match="date_nanos"):
        profile.prepare_events([event(**{"@timestamp": timestamp})])


def test_timestamps_normalize_and_identical_retries_deduplicate():
    first = event(**{"@timestamp": "2026-01-01T03:00:30+03:00"})
    prepared, counters = profile.prepare_events([first, event()])
    assert prepared == [event()]
    assert counters == {"input_events": 2, "unique_events": 1, "duplicate_events": 1}


def test_typed_conflicts_do_not_disappear_during_deduplication():
    with pytest.raises(ValueError, match="conflicting duplicate"):
        profile.prepare_events([event(), event(**{"win.logon_type": 9.0})])
    with pytest.raises(ValueError, match="conflicting duplicate"):
        profile.prepare_events([event(), event(**{"host.boot.id": "boot-B"})])


def test_mapping_has_all_leaf_fields_and_noncoercing_numeric_types():
    mapping = json.loads(profile.MAPPING_PATH.read_text())["mappings"]
    leaves = {}
    def visit(properties, prefix=""):
        for name, item in properties.items():
            key = prefix + name
            if "properties" in item:
                visit(item["properties"], key + ".")
            else:
                leaves[key] = item
    visit(mapping["properties"])
    assert set(leaves) == profile.REQUIRED_FIELDS | profile.OPTIONAL_FIELDS | profile.LOGON_FIELDS | profile.PRIVILEGE_FIELDS
    assert mapping["_meta"]["profile"] == profile.PROFILE
    assert leaves["@timestamp"]["type"] == "date_nanos"
    assert leaves["win.privileges"]["type"] == "keyword"
    assert all(leaves[field]["coerce"] is False for field in ("win.logon_type", "event.version", "win.timestamp_remainder"))
