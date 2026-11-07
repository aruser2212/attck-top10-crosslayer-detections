"""Independent predicate, catalog, identity and boundary checks for process-v1."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml
from sigma.rule import SigmaRule

from tools import process_detection as detector

RULE_ID = "d9c34981-e92c-4e9d-b74f-b97be56fddc0"
OTHER_ID = "94ff3865-2eab-49dd-aebc-165023917037"


def rule(selection=None, *, identifier=RULE_ID, source=None, condition="selection", **selections):
    return SigmaRule.from_dict({
        "title": "Inert process predicate fixture", "id": identifier,
        "logsource": source or {"product": "windows", "category": "process_creation"},
        "detection": {"selection": selection or {"Image|endswith": r"\cmd.exe"}, **selections, "condition": condition},
    })


def event(**changes):
    return {"@timestamp": "2026-01-01T00:00:00Z", "event.id": "process-1",
            "event.dataset": "windows.sysmon.process", "event.code": "1", "host.name": "host01",
            "process.guid": "00000001-0000-0000-0000-000000000001",
            "process.parent.guid": "00000002-0000-0000-0000-000000000002",
            "process.executable": r"C:\Windows\System32\cmd.exe",
            "process.parent.executable": r"C:\Windows\explorer.exe",
            "process.command_line": "cmd.exe /c echo benign", **changes}


def evaluate(events, selected=None, **options):
    return detector.evaluate_events(events, rules={RULE_ID: selected or rule()}, **options)


@pytest.mark.parametrize("field,value,source,matched", [
    ("Image|endswith", r"\cmd.exe", {"process.executable": r"C:\Windows\CMD.EXE"}, True),
    ("Image|endswith", r"\cmd.exe", {"process.executable": r"C:\Windows\notcmd.exe"}, False),
    ("ParentImage|endswith", r"\explorer.exe", {}, True),
    ("CommandLine|contains", "(sample)+[x]", {"process.command_line": "run (sample)+[x] now"}, True),
    ("CommandLine|contains", "(sample)+[x]", {"process.command_line": "samplex"}, False),
    ("CommandLine", r"*literal\*and\?path\\tail*", {"process.command_line": r"literal*and?path\tail"}, True),
    ("CommandLine", r"*literal\*and\?path\\tail*", {"process.command_line": r"literalXandYpath\tail"}, False),
    ("CommandLine", "a?b", {"process.command_line": "a b"}, True),
    ("CommandLine", "a?b", {"process.command_line": "aXXb"}, False),
    ("CommandLine|cased|contains", "TOKEN", {"process.command_line": "cmd TOKEN"}, True),
    ("CommandLine|cased|contains", "TOKEN", {"process.command_line": "cmd token"}, False),
    ("CommandLine|contains", "\t-e\t", {"process.command_line": "powershell\t-e\tQQ=="}, True),
])
def test_supported_strings_have_independent_expected_matches(field, value, source, matched):
    result = evaluate([event(**source)], rule({field: value}))
    assert bool(result["alerts"]) is matched


def test_compiler_preserves_literal_wildcards_backslashes_and_case():
    query = detector.compile_rule(rule({"CommandLine": r"*literal\*and\?path\\tail*"}))
    assert query == {"wildcard": {"process.command_line": {
        "value": r"*literal\*and\?path\\tail*", "case_insensitive": True,
    }}}
    assert detector.compile_rule(rule({"CommandLine|cased": "X"}))["wildcard"]["process.command_line"]["case_insensitive"] is False


def test_boolean_logic_and_multiple_conditions_are_explicit():
    selected = rule(condition="selection and not excluded", excluded={"CommandLine|contains": "safe"})
    assert len(evaluate([event()], selected)["alerts"]) == 1
    assert not evaluate([event(**{"process.command_line": "cmd.exe safe"})], selected)["alerts"]
    selected = rule(condition=["selection", "other"], other={"Image|endswith": r"\powershell.exe"})
    assert len(evaluate([event(**{"process.executable": r"C:\Windows\powershell.exe"})], selected)["alerts"]) == 1
    native = detector.compile_rule(selected)
    assert native["bool"]["minimum_should_match"] == 1


@pytest.mark.parametrize("selection", [
    {"Image|re": "cmd.*"}, {"ProcessId": "123"}, {"Image": 1}, {"Image": True},
    {"Image": None}, {"CommandLine|contains": "caf\u00e9"}, {"CommandLine|contains": "bad\nline"},
])
def test_unsupported_entire_rule_fails_even_when_other_branch_would_match(selection):
    selected = rule(condition="selection or unsupported", unsupported=selection)
    with pytest.raises(ValueError):
        evaluate([event()], selected)


@pytest.mark.parametrize("source", [
    {"product": "linux", "category": "process_creation"},
    {"product": "windows", "category": "registry_event"},
    {"product": "windows", "category": "process_creation", "service": "sysmon"},
])
def test_other_sources_are_rejected(source):
    with pytest.raises(ValueError, match="logsource"):
        evaluate([event()], rule(source=source))


def test_alerts_stable_across_delivery_order_duplicates_and_rule_order():
    selected = {OTHER_ID: rule({"CommandLine|contains": "echo"}, identifier=OTHER_ID), RULE_ID: rule()}
    a, b = event(), event(**{"event.id": "process-2"})
    first = detector.evaluate_events([b, a, deepcopy(a)], rules=selected)
    second = detector.evaluate_events([a, b], rules=dict(reversed(list(selected.items()))))
    assert first["alerts"] == second["alerts"]
    assert [(x["event.id"], x["rule.id"]) for x in first["alerts"]] == [
        (identifier, rule_id) for identifier in ("process-1", "process-2") for rule_id in sorted(selected)
    ]
    assert len({x["alert.id"] for x in first["alerts"]}) == 4
    assert first["summary"]["duplicate_events"] == 1
    assert first["summary"]["matched_events"] == 2
    assert all(x["process.guid"] == a["process.guid"] and x["host.name"] == "host01" for x in first["alerts"])


def test_identity_changes_with_host_or_guid_and_conflicting_source_id_fails():
    original = event()
    original_id = evaluate([original])["alerts"][0]["alert.id"]
    for field, value in (("host.name", "host02"), ("process.guid", "00000003-0000-0000-0000-000000000003")):
        changed = {**original, field: value}
        assert evaluate([changed])["alerts"][0]["alert.id"] != original_id
        with pytest.raises(ValueError, match="conflicting duplicate"):
            evaluate([original, changed])


def test_bounds_are_inclusive_exclusive_at_microsecond_precision():
    events = [event(**{"event.id": str(i), "@timestamp": f"2026-01-01T00:00:00.00000{i}Z"}) for i in range(4)]
    result = evaluate(events, start="2026-01-01T00:00:00.000001Z", end="2026-01-01T00:00:00.000003Z")
    assert [a["event.id"] for a in result["alerts"]] == ["1", "2"]
    assert result["summary"]["out_of_range_events"] == 2


def test_malformed_out_of_range_or_nonmatching_input_is_not_silently_ignored():
    for bad in (event(**{"process.command_line": "caf\u00e9"}), event(**{"event.code": "10"})):
        with pytest.raises(ValueError):
            evaluate([bad], start="2026-01-02T00:00:00Z", end="2026-01-03T00:00:00Z")


@pytest.mark.parametrize("options", [
    {"max_events": 0}, {"max_events": True}, {"max_alerts": 0}, {"max_alerts": 1.5},
    {"start": "2026-01-01T00:00:00Z"},
    {"start": "1969-12-31T23:59:59Z", "end": "2026-01-01T00:00:00Z"},
    {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
])
def test_invalid_configuration_rejected(options):
    with pytest.raises(ValueError):
        evaluate([], **options)


def test_caps_apply_to_raw_input_and_all_rule_matches():
    with pytest.raises(ValueError, match="max_events"):
        evaluate([event(), event()], max_events=1)
    selected = {RULE_ID: rule(), OTHER_ID: rule(identifier=OTHER_ID)}
    with pytest.raises(ValueError, match="max_alerts"):
        detector.evaluate_events([event()], rules=selected, max_alerts=1)


def catalog_file(tmp_path, monkeypatch, contents=None):
    monkeypatch.setattr(detector, "ROOT", tmp_path)
    relative = "techniques/T0000_Test/sigma/process.yml"
    target = tmp_path / relative
    target.parent.mkdir(parents=True)
    target.write_text(yaml.safe_dump({
        "title": "Catalog fixture", "id": RULE_ID,
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": {"Image|endswith": r"\cmd.exe"}, "condition": "selection"},
    }))
    path = tmp_path / "catalog.json"
    path.write_text(contents or json.dumps({"schema_version": 1, "rules": [relative]}))
    return path, relative, target


def test_catalog_routes_only_explicit_supported_paths(tmp_path, monkeypatch):
    path, _, _ = catalog_file(tmp_path, monkeypatch)
    assert set(detector.load_rules(path)) == {RULE_ID}


@pytest.mark.parametrize("payload", [
    {"schema_version": True, "rules": []}, {"schema_version": 1, "rules": []},
    {"schema_version": 1, "rules": ["/tmp/a.yml"]},
    {"schema_version": 1, "rules": ["../other.yml"]},
    {"schema_version": 1, "rules": ["docs/rule.yml"]},
    {"schema_version": 1, "rules": ["techniques/T0000_Test/sigma/process.yml"] * 2},
    {"schema_version": 1, "rules": [42]},
    {"schema_version": 1, "rules": [], "extra": 1},
])
def test_catalog_invalid_structure_paths_and_duplicates_rejected(tmp_path, monkeypatch, payload):
    path, _, _ = catalog_file(tmp_path, monkeypatch, json.dumps(payload))
    with pytest.raises(ValueError):
        detector.load_rules(path)


def test_catalog_duplicate_json_keys_and_escaping_symlink_rejected(tmp_path, monkeypatch):
    path, relative, target = catalog_file(tmp_path, monkeypatch, '{"schema_version":1,"schema_version":1,"rules":[]}')
    with pytest.raises(ValueError, match="Duplicate"):
        detector.load_rules(path)
    outside = tmp_path / "outside.yml"
    target.rename(outside)
    target.symlink_to(outside)
    path.write_text(json.dumps({"schema_version": 1, "rules": [relative]}))
    with pytest.raises(ValueError, match="technique Sigma"):
        detector.load_rules(path)


@pytest.mark.parametrize("selected", [{}, {"wrong-id": rule()}, []])
def test_rule_mapping_identity_is_checked(selected):
    with pytest.raises(ValueError):
        detector.evaluate_events([], rules=selected)


def test_empty_offline_cli_fails_outside_repository(tmp_path):
    source = tmp_path / "empty.jsonl"
    source.write_text("")
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema_version": 1, "rules": [
        "techniques/T1566_Phishing/sigma/win_office_spawns_script.yml",
    ]}))
    result = subprocess.run([sys.executable, str(detector.ROOT / "tools/process_detection.py"),
                             "--events", str(source), "--catalog", str(catalog)],
                            cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
    assert not result.stdout
    assert "no events found" in result.stderr
