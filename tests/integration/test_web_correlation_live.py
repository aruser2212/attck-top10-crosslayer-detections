"""Native Basic replay of hand-declared host/file + HTTP correlation evidence."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

import pytest

from tools import elastic_web_correlation as web
from tools import elastic_rolling as auth
from tools.correlate_webshell import correlate

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "tests/fixtures/correlation/cases.json").read_text())["cases"]
pytestmark = pytest.mark.integration


def selected_case(name="write_then_matching_request"):
    return deepcopy(next(case for case in CASES if case["name"] == name))


def semantic_alerts(result):
    for alert in result["alerts"]:
        assert re.fullmatch(r"[0-9a-f]{64}", alert["alert.id"])
    return [{key: value for key, value in alert.items() if key != "alert.id"}
            for alert in result["alerts"]]


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to execute real Elasticsearch Basic correlation checks")
    result = web.ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                               username=os.environ.get("ELASTIC_USERNAME"),
                               password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def index_for(client, adapter=web):
    name = "attck-test-web-correlation-" + uuid4().hex
    adapter.create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", "/" + name)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_manual_cases_on_real_basic(client, case):
    with index_for(client) as index:
        if not case["profile_valid"]:
            with pytest.raises(ValueError):
                web.ingest_events(client, index, case["events"])
            assert client.request("GET", "/" + index + "/_count")["count"] == 0
            return
        web.ingest_events(client, index, case["events"])
        actual = web.evaluate_index(client, index, page_size=1, **case["config"])
        assert semantic_alerts(actual) == case["expected_alerts"], case["reason"]
        assert actual["alerts"] == correlate(case["events"], **case["config"])["alerts"]
        assert actual["profile"] == "attck-web-correlation-v1"


def test_native_immutable_retry_and_conflicting_namespace(client):
    case = selected_case()
    with index_for(client) as index:
        assert web.ingest_events(client, index, case["events"])["inserted_events"] == 2
        retry = web.ingest_events(client, index, case["events"] + [deepcopy(case["events"][0])])
        assert retry["inserted_events"] == 0
        assert retry["existing_events"] == 2
        assert retry["duplicate_events"] == 1
        conflict = {**case["events"][0], "resource.namespace": "different-container"}
        with pytest.raises(ValueError, match="Conflicting stored"):
            web.ingest_events(client, index, [conflict])
        assert semantic_alerts(web.evaluate_index(client, index, page_size=1, **case["config"])) == case["expected_alerts"]


@pytest.mark.parametrize("field", [
    "file", "resource", "file.path.child", "",
    "_id", "_routing", "_index", "_ignored", "_doc_count",
])
def test_native_mapping_name_conflicts_reject_entire_batch_before_writes(client, field):
    valid = selected_case()["events"][0]
    malformed = {**valid, "event.id": "malformed-second", field: "scalar-conflict"}
    with index_for(client) as index:
        with pytest.raises(ValueError):
            web.ingest_events(client, index, [valid, malformed], batch_size=1)
        # Refresh makes an accidental partial first-batch write observable even
        # when the caller failed before its normal visibility barrier.
        client.request("POST", "/" + index + "/_refresh")
        assert client.request("GET", "/" + index + "/_count")["count"] == 0


@pytest.mark.parametrize("violation", ["wrong_document_id", "string_boolean", "missing_namespace", "noncanonical_path"])
def test_native_direct_write_cannot_bypass_source_validation(client, violation):
    item = selected_case()["events"][0]
    identifier = item["event.id"]
    if violation == "wrong_document_id":
        identifier = "other-source-id"
    elif violation == "string_boolean":
        item["event.success"] = "true"
    elif violation == "missing_namespace":
        item.pop("resource.namespace")
    else:
        item["file.path"] = "/var/www/html/../example.php"
    with index_for(client) as index:
        client.request("PUT", "/" + index + "/_doc/" + identifier + "?refresh=true", item)
        with pytest.raises(ValueError):
            web.evaluate_index(client, index, webroots=["/var/www/html"], page_size=1)


def test_native_auth_profile_is_rejected_without_mutation(client):
    case = selected_case()
    with index_for(client, auth) as index:
        mapping = client.request("GET", "/" + index + "/_mapping")
        with pytest.raises(ValueError):
            web.ingest_events(client, index, case["events"])
        with pytest.raises(ValueError):
            web.evaluate_index(client, index, **case["config"])
        assert client.request("GET", "/" + index + "/_mapping") == mapping
        assert client.request("GET", "/" + index + "/_count")["count"] == 0


def test_native_exact_microsecond_context_and_request_end(client):
    case = selected_case("bounded_replay_retains_file_context")
    with index_for(client) as index:
        web.ingest_events(client, index, case["events"])
        actual = web.evaluate_index(client, index, page_size=1, max_events=2, **case["config"])
        assert semantic_alerts(actual) == case["expected_alerts"]
        assert actual["summary"]["fetched_events"] == 2


def test_native_caps_fail_without_partial_alerts_then_allow_retry(client):
    case = selected_case("repeated_requests_preserve_each_evidence_pair")
    with index_for(client) as index:
        web.ingest_events(client, index, case["events"])
        with pytest.raises(ValueError, match="max_events"):
            web.evaluate_index(client, index, page_size=1, max_events=2, **case["config"])
        with pytest.raises(ValueError, match="max_alerts"):
            web.evaluate_index(client, index, page_size=1, max_alerts=1, **case["config"])
        actual = web.evaluate_index(client, index, page_size=1, **case["config"])
        assert semantic_alerts(actual) == case["expected_alerts"]


def test_native_long_query_value_remains_source_evidence(client):
    case = selected_case()
    case["events"][1]["url.query"] = "cmd=" + "x" * 40_000
    with index_for(client) as index:
        assert web.ingest_events(client, index, case["events"])["inserted_events"] == 2
        actual = web.evaluate_index(client, index, page_size=1, **case["config"])
        assert semantic_alerts(actual) == case["expected_alerts"]


def test_native_cli_round_trip_outside_repository(client, tmp_path):
    case = selected_case()
    path = tmp_path / "normalized.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in case["events"]))
    index = "attck-test-web-correlation-cli-" + uuid4().hex

    def cli(*args):
        result = subprocess.run([sys.executable, str(ROOT / "tools/elastic_web_correlation.py"),
                                 "--index", index, *map(str, args)], cwd=tmp_path,
                                check=True, capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)

    cli("create-index")
    try:
        assert cli("ingest", path)["inserted_events"] == 2
        assert cli("ingest", path)["existing_events"] == 2
        actual = cli("evaluate", "--webroot", "/var/www/html", "--page-size", "1")
        assert semantic_alerts(actual) == case["expected_alerts"]
        assert actual["alerts"] == correlate(case["events"], **case["config"])["alerts"]
    finally:
        client.request("DELETE", "/" + index)
