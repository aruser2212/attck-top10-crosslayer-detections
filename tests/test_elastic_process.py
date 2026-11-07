"""Complete native-match replay protocol without replacing its validation logic."""
from copy import deepcopy
import json

import pytest
from sigma.rule import SigmaRule

from tools import elastic_process as adapter
from tools import process_detection as detector
from tools import elastic_rolling as auth

INDEX = "attck-test-process-unit"
RULE_ID = "d9c34981-e92c-4e9d-b74f-b97be56fddc0"


class Client:
    def __init__(self, replies):
        self.replies, self.calls = list(replies), []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.replies, (method, path)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def rules(selection=None):
    rule = SigmaRule.from_dict({
        "title": "Native matching fixture", "id": RULE_ID,
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {"selection": selection or {"Image|endswith": r"\cmd.exe"}, "condition": "selection"},
    })
    return {RULE_ID: rule}


def event(**changes):
    return {"@timestamp": "2026-01-01T00:00:00Z", "event.id": "process-1",
            "event.dataset": adapter.DATASET, "event.code": "1", "host.name": "host01",
            "process.guid": "00000001-0000-0000-0000-000000000001",
            "process.parent.guid": "00000002-0000-0000-0000-000000000002",
            "process.executable": r"C:\Windows\cmd.exe",
            "process.parent.executable": r"C:\Windows\explorer.exe",
            "process.command_line": "cmd.exe /c echo benign", **changes}


def mapping(path=adapter.MAPPING_PATH):
    return {INDEX: {"mappings": json.loads(path.read_text())["mappings"]}}


def identity(uuid="process-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def hit(item=None, ordinal=0, matches=None):
    source = deepcopy(item or event())
    return {"_index": INDEX, "_id": source["event.id"], "_source": source,
            "sort": [source["@timestamp"], ordinal], "matched_queries": [RULE_ID] if matches is None else matches}


def page(hits, **changes):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits}, **changes}


def client_for(hits, *, final_uuid="process-uuid"):
    return Client([mapping(), identity(), {"id": "pit-1"},
                   *[page([item]) for item in hits], page([]), {"succeeded": True}, identity(final_uuid)])


def failing_client(response, cleanup=None):
    return Client([mapping(), identity(), {"id": "pit-1"}, response,
                   {"succeeded": True} if cleanup is None else cleanup])


def test_all_events_are_read_and_named_queries_define_native_matches():
    a = event()
    b = event(**{"event.id": "benign", "process.executable": r"C:\Windows\notepad.exe"})
    client = client_for([hit(a, 0), hit(b, 1, [])])
    result = adapter.evaluate_index(client, INDEX, rules=rules(), page_size=1)
    assert result["alerts"] == detector.evaluate_events([a, b], rules=rules())["alerts"]
    assert result["summary"]["fetched_events"] == 2
    assert result["summary"]["filtered_events"] == 1
    assert result["summary"]["fetch_pages"] == 3
    searches = [body for _, path, body in client.calls if path.startswith("/_search")]
    query = searches[0]["query"]["bool"]
    assert query["filter"] == [{"term": {"event.dataset": adapter.DATASET}}]
    assert query["minimum_should_match"] == 0
    assert query["should"][0]["bool"]["_name"] == RULE_ID
    assert query["should"][0]["bool"]["filter"] == [detector.compile_rule(rules()[RULE_ID])]
    assert searches[1]["search_after"] == [a["@timestamp"], 0]
    assert client.calls[-2] == ("DELETE", "/_pit", {"id": "pit-1"})


def test_missing_named_queries_is_allowed_only_for_an_actual_nonmatch():
    source = event(**{"process.executable": r"C:\Windows\notepad.exe"})
    row = hit(source)
    row.pop("matched_queries")
    result = adapter.evaluate_index(client_for([row]), INDEX, rules=rules())
    assert not result["alerts"]
    row["_source"] = event()
    with pytest.raises(adapter.ElasticError, match="differ from"):
        adapter.evaluate_index(failing_client(page([row])), INDEX, rules=rules())


@pytest.mark.parametrize("matches", [["unknown"], [RULE_ID, RULE_ID], RULE_ID, {RULE_ID: 1.0}, [1], None])
def test_invalid_named_query_metadata_rejected(matches):
    row = hit()
    row["matched_queries"] = matches
    client = failing_client(page([row]))
    with pytest.raises(adapter.ElasticError, match="named process"):
        adapter.evaluate_index(client, INDEX, rules=rules())
    assert client.calls[-1][0] == "DELETE"


@pytest.mark.parametrize("source,matches", [
    (event(), []), (event(**{"process.executable": r"C:\Windows\notepad.exe"}), [RULE_ID]),
])
def test_native_false_negatives_and_false_positives_fail_the_complete_replay(source, matches):
    with pytest.raises(adapter.ElasticError, match="differ from"):
        adapter.evaluate_index(failing_client(page([hit(source, matches=matches)])), INDEX, rules=rules())


def test_nonmatching_record_is_still_validated():
    bad = event(**{"process.executable": r"C:\Windows\notepad.exe", "process.command_line": "caf\u00e9"})
    with pytest.raises(ValueError, match="ASCII"):
        adapter.evaluate_index(failing_client(page([hit(bad, matches=[])])), INDEX, rules=rules())


@pytest.mark.parametrize("change", [
    {"_index": "wrong-index"}, {"_id": "wrong-id"}, {"_source": []},
    {"sort": []}, {"sort": ["2026-01-01T00:00:00Z", True]},
    {"sort": ["2026-01-01T00:00:00.0000001Z", 0]},
])
def test_invalid_hit_identity_sort_or_precision_rejected(change):
    with pytest.raises(ValueError):
        adapter.evaluate_index(failing_client(page([{**hit(), **change}])), INDEX, rules=rules())


def test_noncanonical_source_is_rejected_even_if_profile_can_normalize_it():
    row = hit(event(**{"@timestamp": "2026-01-01T00:00:00+00:00"}))
    with pytest.raises(adapter.ElasticError, match="noncanonical"):
        adapter.evaluate_index(failing_client(page([row])), INDEX, rules=rules())


def test_page_sort_must_advance_and_ids_cannot_repeat():
    for second in (hit(ordinal=1), hit(event(**{"event.id": "other"}), 0)):
        client = Client([mapping(), identity(), {"id": "pit"}, page([hit()]), page([second]), {"succeeded": True}])
        with pytest.raises(adapter.ElasticError):
            adapter.evaluate_index(client, INDEX, rules=rules(), page_size=1)


@pytest.mark.parametrize("response", [
    page([hit()], timed_out=True), page([hit()], terminated_early=True),
    page([hit()], _shards={"total": 2, "successful": 1, "failed": 1}),
    page([hit()], pit_id=""), {"hits": {"hits": []}},
    page([hit(), hit(event(**{"event.id": "other"}), 1)]),
])
def test_incomplete_or_malformed_search_fails_and_closes_pit(response):
    client = failing_client(response)
    with pytest.raises(adapter.ElasticError):
        adapter.evaluate_index(client, INDEX, rules=rules(), page_size=1)
    assert client.calls[-1][0] == "DELETE"


def test_latest_pit_id_is_used_for_pagination_and_cleanup():
    client = Client([mapping(), identity(), {"id": "pit-1"}, page([hit()], pit_id="pit-2"),
                     page([], pit_id="pit-3"), {"succeeded": True}, identity()])
    adapter.evaluate_index(client, INDEX, rules=rules())
    assert client.calls[4][2]["pit"]["id"] == "pit-2"
    assert client.calls[5] == ("DELETE", "/_pit", {"id": "pit-3"})


def test_cleanup_failure_is_visible_but_does_not_mask_search_failure():
    client = Client([mapping(), identity(), {"id": "pit"}, page([]), {"succeeded": False}])
    with pytest.raises(adapter.ElasticError, match="cleanup"):
        adapter.evaluate_index(client, INDEX, rules=rules())
    client = failing_client(adapter.ElasticError("primary search failure"), adapter.ElasticError("cleanup failure"))
    with pytest.raises(adapter.ElasticError, match="primary"):
        adapter.evaluate_index(client, INDEX, rules=rules())


def test_bounds_include_start_exclude_end_and_keep_fractional_zeros():
    source = event()
    client = client_for([hit(source)])
    adapter.evaluate_index(client, INDEX, rules=rules(), start=source["@timestamp"], end="2026-01-01T00:00:00.000001Z")
    bounds = client.calls[3][2]["query"]["bool"]["filter"][1]["range"]["@timestamp"]
    assert bounds == {"gte": "2026-01-01T00:00:00.000000Z", "lt": "2026-01-01T00:00:00.000001Z"}
    with pytest.raises(adapter.ElasticError, match="bounds"):
        adapter.evaluate_index(failing_client(page([hit(source)])), INDEX, rules=rules(),
                               start="2026-01-01T00:00:00.000001Z", end="2026-01-01T00:00:01Z")


def test_expected_and_replaced_index_uuid_are_rejected():
    client = Client([mapping(), identity()])
    with pytest.raises(adapter.ElasticError, match="binding"):
        adapter.evaluate_index(client, INDEX, rules=rules(), expected_index_uuid="wrong")
    assert all(call[0] == "GET" for call in client.calls)
    with pytest.raises(adapter.ElasticError, match="replaced"):
        adapter.evaluate_index(client_for([hit()], final_uuid="replacement"), INDEX, rules=rules())


@pytest.mark.parametrize("options", [{"page_size": True}, {"page_size": 10001}, {"max_events": 0}, {"max_alerts": 0}, {"start": "2026-01-01T00:00:00Z"}])
def test_invalid_options_fail_before_network(options):
    client = Client([])
    with pytest.raises(ValueError):
        adapter.evaluate_index(client, INDEX, rules=rules(), **options)
    assert not client.calls


def test_unsupported_rule_fails_before_network():
    client = Client([])
    with pytest.raises(ValueError, match="Unsupported process Sigma field"):
        adapter.evaluate_index(client, INDEX, rules=rules({"ProcessId": "12"}))
    assert not client.calls


def test_event_and_alert_caps_fail_without_partial_results():
    items = [hit(), hit(event(**{"event.id": "second"}), 1)]
    for options, error in (({"max_events": 1}, "max_events"), ({"max_alerts": 1}, "max_alerts")):
        client = failing_client(page(items))
        with pytest.raises(adapter.ElasticError, match=error):
            adapter.evaluate_index(client, INDEX, rules=rules(), **options)


def test_wrong_mapping_and_invalid_ingest_do_not_write():
    client = Client([mapping(auth.MAPPING_PATH)])
    with pytest.raises(adapter.ElasticError, match="separate process-v1"):
        adapter.ingest_events(client, INDEX, [event()])
    assert all(call[0] == "GET" for call in client.calls)
    client = Client([])
    with pytest.raises(ValueError, match="unknown fields"):
        adapter.ingest_events(client, INDEX, [event(extra="unsupported")])
    assert not client.calls


def test_immutable_ingestion_retries_and_refreshes_after_native_confirmation():
    source = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": source["event.id"], "found": True, "_source": source}]},
                     identity(), {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = adapter.ingest_events(client, INDEX, [source, deepcopy(source)])
    assert result["inserted_events"] == 0 and result["existing_events"] == 1 and result["duplicate_events"] == 1
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)
