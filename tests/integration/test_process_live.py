"""Native Basic matching against manual process predicates and strict source input.

Every raw Sigma fixture receives an explicitly synthetic common process/parent
envelope. Missing mandatory source text is retained as a profile error. The
case's handwritten match expectation, not another detector, defines success.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest
from sigma.collection import SigmaCollection

from tools import elastic_process as process
from tools import elastic_rolling as auth
from tools.process_detection import evaluate_events, load_rules

ROOT = Path(__file__).resolve().parents[2]
RULES = load_rules()
MANIFEST = json.loads((ROOT / "tests/fixtures/sigma/predicates.json").read_text())
SUITES = [suite for suite in MANIFEST["rules"] if suite["rule_id"] in RULES]
CASES = [(suite["rule_id"], case) for suite in SUITES for case in suite["cases"]]
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic process checks")
    connection = process.ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                                       username=os.environ.get("ELASTIC_USERNAME"),
                                       password=os.environ.get("ELASTIC_PASSWORD"))
    license = connection.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return connection


@contextmanager
def index_for(client, adapter=process):
    name = "attck-test-process-" + uuid4().hex
    adapter.create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", process.index_path(name))


def event(identifier="process-one", **changes):
    return {
        "@timestamp": "2026-01-01T00:00:10Z", "event.id": identifier,
        "event.dataset": process.DATASET, "event.code": "1", "host.name": "fixture-host",
        "process.guid": str(uuid5(NAMESPACE_URL, identifier)),
        "process.parent.guid": "10000000-0000-0000-0000-000000000001",
        "process.parent.executable": r"C:\Windows\explorer.exe",
        "process.executable": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "process.command_line": "powershell.exe -EncodedCommand VwByAGkAdABlAA==",
        **changes,
    }


def normalized_case(case):
    item = event()
    item.pop("process.executable")
    item.pop("process.command_line")
    for source, target in (("Image", "process.executable"),
                           ("CommandLine", "process.command_line"),
                           ("ParentImage", "process.parent.executable")):
        if source in case["event"]:
            item[target] = case["event"][source]
    return item


def powershell_rule():
    matches = {key: rule for key, rule in RULES.items()
               if any(str(tag) == "attack.t1059.001" for tag in rule.tags)}
    assert len(matches) == 1
    return matches


@pytest.mark.parametrize("rule_id,case", CASES,
                         ids=[key[:8] + "/" + case["name"] for key, case in CASES])
def test_manual_predicate_case_on_native_basic(client, rule_id, case):
    item = normalized_case(case)
    selected = {rule_id: RULES[rule_id]}
    with index_for(client) as index:
        if not case["profile_valid"]:
            with pytest.raises(ValueError):
                process.ingest_events(client, index, [event("valid-first"), item], batch_size=1)
            assert client.request("GET", process.index_path(index) + "/_count")["count"] == 0
            return
        process.ingest_events(client, index, [item])
        result = process.evaluate_index(client, index, rules=selected, page_size=1)
        expected = [(rule_id, item["event.id"])] if case["match"] else []
        assert [(alert["rule.id"], alert["event.id"]) for alert in result["alerts"]] == expected
        assert result["alerts"] == evaluate_events([item], rules=selected)["alerts"]
        assert result["profile"] == "attck-process-v1"
        assert result["summary"]["fetched_events"] == 1


def test_native_immutable_retry_and_conflicting_process_identity(client):
    events = [event()]
    with index_for(client) as index:
        assert process.ingest_events(client, index, events)["inserted_events"] == 1
        retry = process.ingest_events(client, index, events + deepcopy(events))
        assert (retry["inserted_events"], retry["existing_events"], retry["duplicate_events"]) == (0, 1, 1)
        before = process.evaluate_index(client, index, rules=powershell_rule())["alerts"]
        assert len(before) == 1
        with pytest.raises(process.ElasticError, match="Conflicting stored"):
            process.ingest_events(client, index, [event(**{"host.name": "another-host"})])
        assert process.evaluate_index(client, index, rules=powershell_rule())["alerts"] == before


def test_native_nonmatching_events_still_count_towards_complete_input_cap(client):
    rows = [event(), event("ordinary", **{
        "process.executable": r"C:\Windows\System32\notepad.exe",
        "process.command_line": "notepad.exe notes.txt",
    })]
    with index_for(client) as index:
        process.ingest_events(client, index, rows)
        with pytest.raises(ValueError, match="max_events"):
            process.evaluate_index(client, index, rules=powershell_rule(), page_size=1, max_events=1)
        result = process.evaluate_index(client, index, rules=powershell_rule(), page_size=1)
        assert result["summary"]["fetched_events"] == 2
        assert [(a["event.id"]) for a in result["alerts"]] == ["process-one"]


@pytest.mark.parametrize("violation", ["wrong_document_id", "missing_guid", "unicode_command", "array_command", "unknown_field"])
def test_native_direct_write_of_nonmatching_event_cannot_bypass_validation(client, violation):
    item = event("invalid-nonmatch", **{
        "process.executable": r"C:\Windows\System32\notepad.exe",
        "process.command_line": "notepad.exe notes.txt",
    })
    identifier = item["event.id"]
    if violation == "wrong_document_id":
        identifier = "unrelated-id"
    elif violation == "missing_guid":
        item.pop("process.guid")
    elif violation == "unicode_command":
        item["process.command_line"] += " \u00e9"
    elif violation == "array_command":
        item["process.command_line"] = [item["process.command_line"]]
    else:
        item["unsupported.context"] = "unknown"
    with index_for(client) as index:
        client.request("PUT", process.index_path(index) + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ValueError):
            process.evaluate_index(client, index, rules=powershell_rule(), page_size=1)


def test_native_profile_isolation_preserves_existing_auth_index(client):
    with index_for(client, auth) as index:
        prior = client.request("GET", process.index_path(index) + "/_mapping")
        with pytest.raises(process.ElasticError, match="process-v1"):
            process.ingest_events(client, index, [event()])
        with pytest.raises(process.ElasticError, match="process-v1"):
            process.evaluate_index(client, index)
        assert client.request("GET", process.index_path(index) + "/_mapping") == prior
        assert client.request("GET", process.index_path(index) + "/_count")["count"] == 0


def test_native_uuid_binding_rejects_recreated_index(client):
    with index_for(client) as index:
        old_uuid = process.get_index_identity(client, index)["uuid"]
        client.request("DELETE", process.index_path(index))
        process.create_index(client, index)
        with pytest.raises(process.ElasticError, match="expected binding"):
            process.evaluate_index(client, index, expected_index_uuid=old_uuid)


def test_native_microsecond_bounds_and_equal_time_order(client):
    rows = [event("before", **{"@timestamp": "2026-01-01T00:00:09.999999Z"}),
            event("tie-b"), event("tie-a"),
            event("inside", **{"@timestamp": "2026-01-01T00:00:10.000001Z"}),
            event("end", **{"@timestamp": "2026-01-01T00:00:10.000002Z"})]
    bounds = {"start": "2026-01-01T00:00:10Z", "end": "2026-01-01T00:00:10.000002Z"}
    with index_for(client) as index:
        process.ingest_events(client, index, list(reversed(rows)))
        actual = process.evaluate_index(client, index, rules=powershell_rule(), page_size=1, **bounds)
        assert [alert["event.id"] for alert in actual["alerts"]] == ["tie-a", "tie-b", "inside"]
        assert actual["alerts"] == evaluate_events(rows, rules=powershell_rule(), **bounds)["alerts"]
        assert actual["summary"]["fetched_events"] == 3


def test_native_alert_limit_rejects_entire_replay(client):
    with index_for(client) as index:
        process.ingest_events(client, index, [event("first"), event("second")])
        with pytest.raises(ValueError, match="max_alerts"):
            process.evaluate_index(client, index, rules=powershell_rule(), max_alerts=1, page_size=1)


def test_native_literal_wildcards_and_multiple_named_matches(client):
    # These independently specified supported predicates exercise Lucene's
    # literal wildcard/backslash escaping, not only corpus-specific text.
    rule = SigmaCollection.from_yaml(r'''
title: Literal command punctuation
id: 2552df1e-3116-40c6-bc20-3869f2114e23
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'C:\literal\file\*\?.txt'
  condition: selection
''').rules[0]
    # An exact Sigma match is independently expressed as the full input text;
    # both queries must be named on one hit, with no duplicate event alert IDs.
    exact = SigmaCollection.from_yaml(r'''
title: Same command exact
id: 1375f1ec-ebfa-484a-9f9d-4b53349ce4ad
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine: 'inspect.exe C:\literal\file\*\?.txt'
  condition: selection
''').rules[0]
    selected = {str(rule.id): rule, str(exact.id): exact}
    row = event(**{"process.command_line": r"inspect.exe C:\literal\file*?.txt"})
    near = event("near", **{"process.command_line": r"inspect.exe C:\literal\fileAB.txt"})
    with index_for(client) as index:
        process.ingest_events(client, index, [row, near])
        result = process.evaluate_index(client, index, rules=selected, page_size=1)
        assert [(a["event.id"], a["rule.id"]) for a in result["alerts"]] == [
            (row["event.id"], key) for key in sorted(selected)
        ]
        assert len({a["alert.id"] for a in result["alerts"]}) == 2
        assert result["alerts"] == evaluate_events([row, near], rules=selected)["alerts"]


def test_native_xml_to_cli_replay_outside_repository(client, tmp_path):
    fixtures = ROOT / "tests/fixtures/process/native"
    completed = subprocess.run([
        sys.executable, str(ROOT / "tools/normalize_windows_process.py"),
        str(fixtures / "process-create-v5.xml"), str(fixtures / "benign-process-v5.xml"),
    ], cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
    rows = [json.loads(line) for line in completed.stdout.splitlines()]
    assert len(rows) == 2 and {row["event.version"] for row in rows} == {5}
    normalized = tmp_path / "normalized.jsonl"
    normalized.write_text(completed.stdout)
    offline = subprocess.run([
        sys.executable, str(ROOT / "tools/process_detection.py"), "--events", str(normalized),
    ], cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30)
    expected = json.loads(offline.stdout)
    scriptlet_id = next(key for key, rule in RULES.items()
                        if any(str(tag) == "attack.t1218.010" for tag in rule.tags))
    assert [(a["event.id"], a["rule.id"]) for a in expected["alerts"]] == [(rows[0]["event.id"], scriptlet_id)]
    index = "attck-test-process-cli-" + uuid4().hex
    command = [sys.executable, str(ROOT / "tools/elastic_process.py"), "--index", index]
    created = subprocess.run(command + ["create-index"], cwd=tmp_path,
                             check=True, capture_output=True, text=True, timeout=30)
    try:
        assert json.loads(created.stdout)["profile"] == "attck-process-v1"
        first = subprocess.run(command + ["ingest", str(normalized)], cwd=tmp_path,
                               check=True, capture_output=True, text=True, timeout=30)
        retry = subprocess.run(command + ["ingest", str(normalized)], cwd=tmp_path,
                               check=True, capture_output=True, text=True, timeout=30)
        actual = subprocess.run(command + ["evaluate", "--page-size", "1"], cwd=tmp_path,
                                check=True, capture_output=True, text=True, timeout=30)
        assert json.loads(first.stdout)["inserted_events"] == 2
        assert json.loads(retry.stdout)["inserted_events"] == 0
        assert json.loads(actual.stdout)["alerts"] == expected["alerts"]
    finally:
        client.request("DELETE", process.index_path(index))
