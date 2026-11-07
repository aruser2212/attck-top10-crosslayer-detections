"""Complete source reads and exact session evidence through the Basic transport."""
from copy import deepcopy
import json

import pytest

from tools import elastic_newcredentials as sessions
from tools import elastic_rolling as auth

INDEX = "attck-test-newcredentials-unit"


class Client:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.replies, (method, path)
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def mapping(path=sessions.MAPPING_PATH):
    return {INDEX: {"mappings": json.loads(path.read_text())["mappings"]}}


def identity(uuid="session-source-uuid"):
    return {INDEX: {"settings": {"index.uuid": uuid}}}


def event(code="4624", **changes):
    item = {"@timestamp": "2026-01-01T00:00:30Z", "event.id": "event-" + code,
            "event.dataset": sessions.DATASET, "event.code": code,
            "host.name": "host01", "host.boot.id": "trusted-boot-1",
            "session.id": "0xabc", "user.id": "S-1-5-21-100-200-300-1001"}
    item.update({"win.logon_type": 9, "win.logon_process": "seclogo"} if code == "4624"
                else {"win.privileges": ["SeDebugPrivilege"]})
    return {**item, **changes}


def hit(item, ordinal):
    return {"_index": INDEX, "_id": item["event.id"], "_source": deepcopy(item),
            "sort": [item["@timestamp"], ordinal]}


def page(hits):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits}}


def search_client(events, *, final_uuid="session-source-uuid"):
    return Client([mapping(), identity(), {"id": "sessions-pit"},
                   *[page([hit(item, i)]) for i, item in enumerate(events)], page([]),
                   {"succeeded": True}, identity(final_uuid)])


def test_complete_snapshot_retains_privileges_before_and_after_output_bounds():
    events = [event("4672", **{"@timestamp": "2026-01-01T00:00:00Z", "event.id": "before"}),
              event(), event("4672", **{"@timestamp": "2026-01-01T00:01:00Z", "event.id": "after",
                                        "win.privileges": ["SeImpersonatePrivilege"]})]
    client = search_client(events)
    result = sessions.evaluate_index(client, INDEX, page_size=1,
                                     start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:30.000001Z")
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["logon.event.id"] == "event-4624"
    assert alert["privilege.event.ids"] == ["before", "after"]
    assert alert["privilege.time_deltas_us"] == [-30_000_000, 30_000_000]
    assert alert["win.privileges"] == ["SeDebugPrivilege", "SeImpersonatePrivilege"]
    assert result["summary"]["fetched_events"] == 3
    assert result["summary"]["fetch_pages"] == 4
    searches = [body for _, path, body in client.calls if path.startswith("/_search")]
    assert all(body["query"]["bool"]["filter"] == [{"term": {"event.dataset": sessions.DATASET}}]
               for body in searches)
    assert searches[1]["search_after"] == [events[0]["@timestamp"], 0]
    assert client.replies == []


def test_out_of_bounds_duplicate_logon_cannot_be_hidden_by_a_time_query():
    events = [event(), event("4672"),
              event(**{"event.id": "other-logon", "@timestamp": "2026-01-02T00:00:00Z"})]
    client = search_client(events)
    with pytest.raises(ValueError, match="ambiguous session"):
        sessions.evaluate_index(client, INDEX, page_size=1,
                                start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:31Z")
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "sessions-pit"})


def test_conflicting_session_sid_fails_after_complete_pit_cleanup():
    client = search_client([event(), event("4672", **{"user.id": "S-1-5-21-100-200-300-1002"})])
    with pytest.raises(ValueError, match="contradictory SID"):
        sessions.evaluate_index(client, INDEX)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "sessions-pit"})


def test_reused_background_session_does_not_block_an_unrelated_anchor():
    background = [event(**{"event.id": f"background-{i}", "session.id": "0x3e7",
                           "win.logon_type": 5, "win.logon_process": "advapi"}) for i in range(2)]
    result = sessions.evaluate_index(search_client([*background, event(), event("4672")]), INDEX, page_size=1)
    assert [a["logon.event.id"] for a in result["alerts"]] == ["event-4624"]


@pytest.mark.parametrize("kwargs", [
    {"max_skew_seconds": -1}, {"max_skew_seconds": True}, {"max_skew_seconds": 86401},
    {"max_events": 0}, {"max_alerts": False}, {"page_size": 0}, {"page_size": 10001},
    {"page_size": True}, {"start": "2026-01-01T00:00:00Z"},
    {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
    {"start": "1969-01-01T00:00:00Z", "end": "1970-01-01T00:00:00Z"},
])
def test_invalid_configuration_fails_before_network(kwargs):
    client = Client([])
    with pytest.raises(ValueError):
        sessions.evaluate_index(client, INDEX, **kwargs)
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"host.boot.id": None}, {"session.id": "0x000abc"}, {"session.id": 2748},
    {"user.id": "S-1-0-0"}, {"user.id": "unmapped-account-name"},
    {"win.logon_type": "9"}, {"host": "alias"}, {"session.id.child": "alias"},
    {"host.name": "HOST01"}, {"_routing": "unsupported-metadata"},
])
def test_invalid_second_record_prevents_any_batch_write(changes):
    client = Client([])
    with pytest.raises(ValueError):
        sessions.ingest_events(client, INDEX, [event(), event(**{"event.id": "invalid", **changes})], batch_size=1)
    assert client.calls == []


@pytest.mark.parametrize("fault", ["timeout", "partial_shards", "id", "index", "sort", "source", "precision"])
def test_incomplete_or_corrupt_search_fails_and_closes_latest_pit(fault):
    response = page([hit(event(), 0)])
    response["pit_id"] = "sessions-pit-updated"
    if fault == "timeout":
        response["timed_out"] = True
    elif fault == "partial_shards":
        response["_shards"] = {"total": 2, "successful": 1, "failed": 1}
    elif fault == "id":
        response["hits"]["hits"][0]["_id"] = "different"
    elif fault == "index":
        response["hits"]["hits"][0]["_index"] = "different"
    elif fault == "sort":
        response["hits"]["hits"][0]["sort"] = ["2026-01-01T00:01:30Z", 0]
    elif fault == "source":
        response["hits"]["hits"][0]["_source"]["win.logon_type"] = True
    else:
        response["hits"]["hits"][0]["sort"] = ["2026-01-01T00:00:30.000000001Z", 0]
    client = Client([mapping(), identity(), {"id": "sessions-pit"}, response, {"succeeded": True}])
    with pytest.raises(ValueError):
        sessions.evaluate_index(client, INDEX)
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "sessions-pit-updated"})


def test_profile_isolation_checks_before_any_write():
    client = Client([mapping(auth.MAPPING_PATH)])
    with pytest.raises(sessions.ElasticError, match="separate newcredentials-v1"):
        sessions.ingest_events(client, INDEX, [event()])
    assert not any(method != "GET" for method, _, _ in client.calls)


def test_uuid_binding_is_checked_before_opening_pit():
    client = Client([mapping(), identity()])
    with pytest.raises(sessions.ElasticError, match="expected binding"):
        sessions.evaluate_index(client, INDEX, expected_index_uuid="different")
    assert all("/_pit" not in path for _, path, _ in client.calls)


def test_replaced_source_prevents_successful_result():
    client = search_client([event(), event("4672")], final_uuid="replacement")
    with pytest.raises(sessions.ElasticError, match="replaced during NewCredentials"):
        sessions.evaluate_index(client, INDEX)


def test_events_outside_anchor_bounds_count_toward_full_read_limit():
    events = [event(), event("4672", **{"@timestamp": "2026-01-01T00:01:00Z"})]
    client = Client([mapping(), identity(), {"id": "sessions-pit"},
                     page([hit(events[0], 0)]), page([hit(events[1], 1)]), {"succeeded": True}])
    with pytest.raises(sessions.ElasticError, match="max_events"):
        sessions.evaluate_index(client, INDEX, page_size=1, max_events=1,
                                start="2026-01-01T00:00:30Z", end="2026-01-01T00:00:31Z")
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "sessions-pit"})


def test_existing_event_conflict_does_not_overwrite_source():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                     "found": True, "_source": {**item, "host.boot.id": "different-boot"}}]}])
    with pytest.raises(sessions.ElasticError, match="Conflicting stored"):
        sessions.ingest_events(client, INDEX, [item])
    assert not any("_bulk" in path for _, path, _ in client.calls)


def test_retry_refreshes_existing_events_without_rewriting():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                     "found": True, "_source": item}]}, identity(),
                     {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = sessions.ingest_events(client, INDEX, [item, deepcopy(item)])
    assert (result["inserted_events"], result["existing_events"], result["duplicate_events"]) == (0, 1, 1)
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)
    assert not any("_bulk" in path for _, path, _ in client.calls)
