"""Adapter contract tests; live Elasticsearch parity is tested separately."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

from tools.elastic_adapter import (
    ElasticError, MAPPING_PATH, compile_hunt, evaluate_index, event_time_bounds, get_index_identity, index_path,
    ingest_events, predicate_query,
)
from tools.hunt_engine import HuntError, load_hunt
import tools.elastic_adapter as adapter

ROOT = Path(__file__).resolve().parents[1]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml"
SPRAY = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_spray_agg.hunt.yaml"
INDEX = "attck-test-unit"
WINDOW = 1767225600000


def mapping_response():
    return {INDEX: {"mappings": json.loads(MAPPING_PATH.read_text())["mappings"]}}


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.responses, f"Unexpected {method} {path}"
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def event(identifier="one"):
    return {"@timestamp": "2026-01-01T00:00:00Z", "event.id": identifier,
            "event.dataset": "windows.security.logons", "event.code": "4625",
            "source.ip": "192.0.2.1", "target.user": "alice"}


def test_spray_counts_users_exactly_across_composite_pages():
    buckets = [{"key": {"window": WINDOW, "d0": "192.0.2.1", "d1": f"user{i:02}"}, "doc_count": 3}
               for i in range(15)]
    client = FakeClient([
        mapping_response(), {"id": "pit-1"},
        {"aggregations": {"events": {"buckets": buckets[:7], "after_key": buckets[6]["key"]}}},
        {"pit_id": "pit-2", "aggregations": {"events": {"buckets": buckets[7:]}}},
        {"succeeded": True},
    ])
    result = evaluate_index(client, INDEX, load_hunt(SPRAY), page_size=7)
    assert result["alerts"] == [{"window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:10:00Z", "source.ip": "192.0.2.1", "distinct_users": 15}]
    assert result["summary"]["pages"] == 2
    assert client.calls[3][2]["aggs"]["events"]["composite"]["after"] == buckets[6]["key"]
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "pit-2"})
    assert "cardinality" not in json.dumps(client.calls)


def test_brute_uses_bucket_event_count_and_having_threshold():
    client = FakeClient([
        mapping_response(), {"id": "pit"},
        {"aggregations": {"events": {"buckets": [
            {"key": {"window": WINDOW, "d0": "alice", "d1": "192.0.2.1"}, "doc_count": 9},
            {"key": {"window": WINDOW, "d0": "bob", "d1": "192.0.2.1"}, "doc_count": 10},
        ]}}}, {"succeeded": True},
    ])
    result = evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["target.user"] == "bob"
    assert result["alerts"][0]["fails"] == 10


@pytest.mark.parametrize("bad", [{"timed_out": True}, {"_shards": {"failed": 1}}, {}])
def test_incomplete_search_fails_and_closes_pit(bad):
    client = FakeClient([mapping_response(), {"id": "pit"}, bad, {"succeeded": True}])
    with pytest.raises(ElasticError):
        evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "pit"})


def test_pagination_must_advance():
    page = {"aggregations": {"events": {"buckets": [
        {"key": {"window": WINDOW, "d0": "alice", "d1": "192.0.2.1"}, "doc_count": 10},
    ], "after_key": {"window": WINDOW, "d0": "alice", "d1": "192.0.2.1"}}}}
    client = FakeClient([mapping_response(), {"id": "pit"}, page, page, {"succeeded": True}])
    with pytest.raises(ElasticError, match="did not advance"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))


def test_unknown_or_mismatched_mapping_rejected_before_search():
    response = mapping_response()
    response[INDEX]["mappings"]["properties"]["source"]["properties"]["ip"]["type"] = "text"
    client = FakeClient([response])
    with pytest.raises(ElasticError, match="mapping differs"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert len(client.calls) == 1


def test_profile_schema_version_must_match():
    response = mapping_response()
    response[INDEX]["mappings"]["_meta"]["schema_version"] = 2
    client = FakeClient([response])
    with pytest.raises(ElasticError, match="mapping profile"):
        evaluate_index(client, INDEX, load_hunt(BRUTE))


def test_unsupported_predicate_fails_before_network():
    rule = load_hunt(BRUTE)
    rule["where"] = {"field": "event.code", "op": "contains", "value": "4625"}
    client = FakeClient([])
    with pytest.raises(ElasticError, match="only string eq/in"):
        evaluate_index(client, INDEX, rule)
    assert client.calls == []


def test_not_keeps_missing_field_unknown():
    query = predicate_query({"not": {"field": "event.code", "op": "eq", "value": "4625"}})
    assert query == {"bool": {"filter": [{"exists": {"field": "event.code"}}], "must_not": [{"term": {"event.code": "4625"}}]}}


def test_missing_and_empty_group_fields_excluded():
    query, _ = compile_hunt(load_hunt(BRUTE))
    filters = query["query"]["bool"]["filter"]
    assert {"exists": {"field": "target.user"}} in filters
    assert {"bool": {"must_not": [{"term": {"target.user": ""}}]}} in filters


def test_conflicting_input_duplicate_never_reaches_elasticsearch():
    client = FakeClient([])
    with pytest.raises(HuntError, match="conflicting duplicate"):
        ingest_events(client, INDEX, [event(), {**event(), "target.user": "bob"}])
    assert client.calls == []


def test_conflicting_stored_id_rejected_before_bulk_write():
    client = FakeClient([mapping_response(), {"docs": [{"_id": "one", "found": True, "_source": {**event(), "target.user": "bob"}}]}])
    with pytest.raises(ElasticError, match="Conflicting stored"):
        ingest_events(client, INDEX, [event()])
    assert all("_bulk" not in call[1] for call in client.calls)


@pytest.mark.parametrize("stored,incoming", [(True, 1), (1, 1.0)])
def test_stored_conflict_compares_json_types(stored, incoming):
    old = {**event(), "context": stored}
    new = {**event(), "context": incoming}
    client = FakeClient([mapping_response(), {"docs": [{"_id": "one", "found": True, "_source": old}]}])
    with pytest.raises(ElasticError, match="Conflicting stored"):
        ingest_events(client, INDEX, [new])


def test_identical_input_and_stored_duplicates_are_idempotent():
    client = FakeClient([
        mapping_response(), {"docs": [{"_id": "one", "found": True, "_source": event()}]},
        {"_shards": {"total": 1, "successful": 1, "failed": 0}},
    ])
    result = ingest_events(client, INDEX, [event(), event()])
    assert result["duplicate_events"] == 1
    assert result["inserted_events"] == 0
    assert result["existing_events"] == 1
    assert client.calls[-1] == ("POST", "/" + INDEX + "/_refresh", None)


def test_new_ingestion_refreshes_once_after_all_bulk_batches():
    client = FakeClient([
        mapping_response(),
        {"docs": [{"_id": "one", "found": False}]},
        {"docs": [{"_id": "two", "found": False}]},
        {"errors": False, "items": [{"create": {"status": 201}}]},
        {"errors": False, "items": [{"create": {"status": 201}}]},
        {"_shards": {"total": 2, "successful": 2, "failed": 0}},
    ])
    result = ingest_events(client, INDEX, [event("one"), event("two")], batch_size=1)
    assert result["inserted_events"] == 2 and result["existing_events"] == 0
    assert [call[1] for call in client.calls[3:]] == [
        "/" + INDEX + "/_bulk?refresh=false",
        "/" + INDEX + "/_bulk?refresh=false",
        "/" + INDEX + "/_refresh",
    ]


@pytest.mark.parametrize("response", [
    {},
    {"_shards": None},
    {"_shards": []},
    {"_shards": {"total": 1, "successful": 1}},
    {"_shards": {"total": 0, "successful": 0, "failed": 0}},
    {"_shards": {"total": 2, "successful": 1, "failed": 1}},
    {"_shards": {"total": 2, "successful": 1, "failed": 0}},
    {"_shards": {"total": 1, "successful": 2, "failed": 0}},
    {"_shards": {"total": True, "successful": True, "failed": 0}},
    {"_shards": {"total": "1", "successful": 1, "failed": 0}},
    {"_shards": {"total": 1, "successful": 1, "failed": 0, "failures": [{"reason": "failure"}]}},
    {"timed_out": True, "_shards": {"total": 1, "successful": 1, "failed": 0}},
    {"error": "failed", "_shards": {"total": 1, "successful": 1, "failed": 0}},
])
def test_existing_only_retry_does_not_acknowledge_incomplete_refresh(response):
    client = FakeClient([
        mapping_response(), {"docs": [{"_id": "one", "found": True, "_source": event()}]},
        response,
    ])
    with pytest.raises(ElasticError, match="visibility refresh"):
        ingest_events(client, INDEX, [event()])
    assert not any("_bulk" in call[1] for call in client.calls)


def test_refresh_transport_failure_propagates_to_keep_source_unacknowledged():
    client = FakeClient([
        mapping_response(), {"docs": [{"_id": "one", "found": True, "_source": event()}]},
        ElasticError("refresh response lost"),
    ])
    with pytest.raises(ElasticError, match="response lost"):
        ingest_events(client, INDEX, [event()])


@pytest.mark.parametrize("value", [42, ["alice"], {"name": "alice"}, True])
def test_ingest_rejects_elastic_keyword_coercion(value):
    client = FakeClient([])
    with pytest.raises(ElasticError, match="scalar string"):
        ingest_events(client, INDEX, [{**event(), "target.user": value}])
    assert client.calls == []


@pytest.mark.parametrize("value", ["   ", "\t", "\u00a0", "\u2003"])
def test_ingest_rejects_whitespace_group_keys(value):
    client = FakeClient([])
    with pytest.raises(ElasticError, match="whitespace-only"):
        ingest_events(client, INDEX, [{**event(), "target.user": value}])
    assert client.calls == []


@pytest.mark.parametrize("name", ["*", "_all", ".security", "a,b", "../other", "UPPER"])
def test_index_name_is_explicit_and_not_system(name):
    with pytest.raises(ElasticError):
        index_path(name)


@pytest.mark.parametrize("contents,error", [
    ("", "no events found"),
    (" \n\t\n", "no events found"),
    ('{"event.id":"first","event.id":"second"}\n', "duplicate JSON key"),
    ('{"event.id":\n', "cannot read events"),
])
def test_cli_rejects_invalid_input_before_any_network(tmp_path, monkeypatch, capsys, contents, error):
    path = tmp_path / "events.jsonl"
    path.write_text(contents)
    client = FakeClient([])
    monkeypatch.setattr(adapter, "ElasticClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(sys, "argv", ["elastic_adapter.py", "--index", INDEX, "ingest", str(path)])
    assert adapter.main() == 1
    assert client.calls == []
    output = capsys.readouterr()
    assert error in output.err
    assert output.out == ""


def settings_response(uuid="source-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def empty_search():
    return {"aggregations": {"events": {"buckets": []}}}


def test_event_time_query_is_half_open_and_normalized_to_utc():
    client = FakeClient([mapping_response(), {"id": "pit"}, empty_search(), {"succeeded": True}])
    result = evaluate_index(client, INDEX, load_hunt(BRUTE),
                            start="2026-01-01T03:00:00+03:00", end="2026-01-01T03:10:00+03:00")
    filters = client.calls[2][2]["query"]["bool"]["filter"]
    assert {"range": {"@timestamp": {"gte": "2026-01-01T00:00:00Z", "lt": "2026-01-01T00:10:00Z"}}} in filters
    assert result["alerts"] == []


def test_unbounded_call_retains_previous_query_shape():
    client = FakeClient([mapping_response(), {"id": "pit"}, empty_search(), {"succeeded": True}])
    evaluate_index(client, INDEX, load_hunt(BRUTE))
    assert not any("range" in item for item in client.calls[2][2]["query"]["bool"]["filter"])


@pytest.mark.parametrize("start,end", [
    (None, "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:00Z", None),
    ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    ("2026-01-01T00:05:00Z", "2026-01-01T00:00:00Z"),
    ("2026-01-01T00:00:00", "2026-01-01T00:05:00Z"),
    ("malformed", "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:01Z", "2026-01-01T00:05:00Z"),
    ("2026-01-01T00:00:00Z", "2026-01-01T00:04:59Z"),
    ("2026-01-01T00:00:00.000001Z", "2026-01-01T00:05:00Z"),
    (datetime(2026, 1, 1), datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)),
    (0, "2026-01-01T00:05:00Z"),
])
def test_invalid_event_time_ranges_fail_before_network(start, end):
    client = FakeClient([])
    with pytest.raises(ElasticError):
        evaluate_index(client, INDEX, load_hunt(BRUTE), start=start, end=end)
    assert client.calls == []


def test_aware_datetime_and_negative_offset_bounds_are_normalized():
    rule = load_hunt(BRUTE)
    assert event_time_bounds(
        rule, datetime(2025, 12, 31, 21, tzinfo=timezone(timedelta(hours=-3))),
        "2026-01-01T00:05:00Z",
    ) == ("2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z")


def test_pre_epoch_aligned_ranges_use_integer_modulo():
    assert event_time_bounds(
        load_hunt(BRUTE), "1969-12-31T23:55:00Z", "1970-01-01T00:00:00Z",
    ) == ("1969-12-31T23:55:00Z", "1970-01-01T00:00:00Z")


def test_alignment_follows_selected_hunt_window():
    with pytest.raises(ElasticError, match="align"):
        event_time_bounds(load_hunt(SPRAY), "2026-01-01T00:05:00Z", "2026-01-01T00:10:00Z")


def test_source_identity_returns_concrete_name_and_uuid():
    client = FakeClient([settings_response()])
    assert get_index_identity(client, INDEX) == {"name": INDEX, "uuid": "source-uuid"}
    assert client.calls == [("GET", "/" + INDEX + "/_settings?flat_settings=true", None)]


@pytest.mark.parametrize("response", [
    {}, {"actual-index": {"settings": {"index.uuid": "id"}}},
    {INDEX: {"settings": {}}}, {INDEX: {"settings": {"index.uuid": ""}}},
    {INDEX: {"settings": {"index.uuid": "_na_"}}},
    {INDEX: {"settings": {"index.uuid": 42}}},
    {INDEX: {"settings": []}}, {INDEX: None},
])
def test_missing_or_aliased_source_identity_fails(response):
    with pytest.raises(ElasticError):
        get_index_identity(FakeClient([response]), INDEX)


def test_uuid_mismatch_refuses_search():
    client = FakeClient([settings_response("replacement")])
    with pytest.raises(ElasticError, match="UUID changed"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), expected_index_uuid="original")
    assert len(client.calls) == 1


def test_uuid_guard_is_rechecked_after_pit_closed():
    client = FakeClient([
        settings_response(), mapping_response(), {"id": "pit"}, empty_search(),
        {"succeeded": True}, settings_response(),
    ])
    assert evaluate_index(client, INDEX, load_hunt(BRUTE), expected_index_uuid="source-uuid")["alerts"] == []
    assert client.calls[-2] == ("DELETE", "/_pit", {"id": "pit"})
    assert client.calls[-1][1].endswith("/_settings?flat_settings=true")


def test_replacement_during_evaluation_discards_results():
    client = FakeClient([
        settings_response("original"), mapping_response(), {"id": "pit"}, empty_search(),
        {"succeeded": True}, settings_response("replacement"),
    ])
    with pytest.raises(ElasticError, match="during evaluation"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), expected_index_uuid="original")


@pytest.mark.parametrize("identifier", ["", " ", 42, False])
def test_invalid_expected_uuid_is_rejected_without_network(identifier):
    client = FakeClient([])
    with pytest.raises(ElasticError, match="UUID"):
        evaluate_index(client, INDEX, load_hunt(BRUTE), expected_index_uuid=identifier)
    assert client.calls == []
