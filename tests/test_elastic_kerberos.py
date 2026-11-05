"""Profile separation and exact service-SID replay through shared transport."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from tools import elastic_kerberos as kerberos
from tools import elastic_rolling as auth
from tools.rolling_hunt import load_hunt

ROOT = Path(__file__).resolve().parents[1]
INDEX = "attck-test-kerberos-unit"
HUNT = ROOT / "techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml"


class Client:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def request(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, deepcopy(body)))
        assert self.replies, (method, path)
        value = self.replies.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def mapping(path=kerberos.MAPPING_PATH):
    return {INDEX: {"mappings": json.loads(path.read_text())["mappings"]}}


def identity():
    return {INDEX: {"settings": {"index.uuid": "kerberos-source-uuid"}}}


def event(i=1, **changes):
    return {
        "@timestamp": "2026-01-01T00:05:00Z", "event.id": f"request-{i}",
        "event.dataset": kerberos.DATASET, "event.code": "4769", "win.status": 0,
        "ticket.encryption_type": 23, "user.name": "alice", "user.domain": "lab.example",
        "source.ip": "192.0.2.10", "service.id": f"S-1-5-21-100-200-300-{1000+i}",
        "service.name": f"svc-{i}", "host.name": "dc01.lab.example", **changes,
    }


def expected(*, count=5):
    return [{
        "window.start": "2026-01-01T00:00:00Z", "window.end": "2026-01-01T00:05:00Z",
        "user.domain": "lab.example", "user.name": "alice", "source.ip": "192.0.2.10",
        "distinct_service_accounts": 5, "rc4_requests": count,
    }]


def hit(item, ordinal):
    return {"_index": INDEX, "_id": item["event.id"], "_source": deepcopy(item),
            "sort": [item["@timestamp"], ordinal]}


def page(hits):
    return {"timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": hits}}


def search_client(events, size=2):
    hits = [hit(item, i) for i, item in enumerate(events)]
    pages = [page(hits[offset:offset + size]) for offset in range(0, len(hits), size)]
    return Client([mapping(), identity(), {"id": "kerberos-pit"}, *pages, page([]),
                   {"succeeded": True}, identity()])


def test_create_uses_separate_kerberos_mapping():
    client = Client([{"acknowledged": True}])
    kerberos.create_index(client, INDEX)
    assert client.calls == [("PUT", "/" + INDEX, json.loads(kerberos.MAPPING_PATH.read_text()))]
    body = client.calls[0][2]
    assert body["mappings"]["_meta"]["profile"] == "attck-kerberos-v1"
    assert body["mappings"]["properties"]["@timestamp"]["type"] == "date_nanos"


def test_auth_mapping_is_never_reused_for_kerberos():
    client = Client([mapping(auth.MAPPING_PATH)])
    with pytest.raises(kerberos.ElasticError, match="separate kerberos-v1"):
        kerberos.ingest_events(client, INDEX, [event()])
    assert all(method == "GET" for method, _, _ in client.calls)


def test_auth_adapter_rejects_kerberos_mapping_and_hunt():
    client = Client([mapping()])
    with pytest.raises(kerberos.ElasticError, match="separate auth-v2"):
        auth.check_profile(client, INDEX)
    client = Client([])
    with pytest.raises(kerberos.ElasticError, match="supports only"):
        auth.evaluate_index(client, INDEX, load_hunt(HUNT))
    assert client.calls == []


def test_kerberos_adapter_rejects_logon_hunt_before_network():
    client = Client([])
    rule = load_hunt(ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml")
    with pytest.raises(kerberos.ElasticError, match="supports only"):
        kerberos.evaluate_index(client, INDEX, rule)
    assert client.calls == []


def test_atomic_service_sid_distinct_is_independent_of_names_and_dc_pages():
    events = [event(i, **{"service.name": "same-name", "host.name": f"dc{i}.lab.example"})
              for i in range(1, 6)]
    events.append(event(6, **{"service.id": events[0]["service.id"], "service.name": "alias"}))
    client = search_client(events)
    result = kerberos.evaluate_index(client, INDEX, load_hunt(HUNT), page_size=2)
    assert result["alerts"] == expected(count=6)
    assert result["profile"] == "attck-kerberos-v1"
    searches = [body for _, path, body in client.calls if path.startswith("/_search")]
    assert searches[0]["query"]["bool"]["filter"] == [{"term": {"event.dataset": kerberos.DATASET}}]
    assert searches[1]["search_after"] == [events[1]["@timestamp"], 1]
    assert client.replies == []


def test_failed_and_aes_requests_cannot_complete_rc4_threshold():
    events = [event(i) for i in range(1, 5)] + [event(5, **{"win.status": 6}),
                                               event(6, **{"ticket.encryption_type": 18})]
    client = search_client(events)
    assert kerberos.evaluate_index(client, INDEX, load_hunt(HUNT), page_size=2)["alerts"] == []


@pytest.mark.parametrize("changes", [
    {"win.status": "0"}, {"win.status": True}, {"ticket.encryption_type": "23"},
    {"user.name": "Alice"}, {"service.id": "S-1-0-0"}, {"source.ip": "::ffff:192.0.2.10"},
    {"event.code": 4769}, {"event.dataset": "windows.security.logons"},
])
def test_profile_rejects_bad_input_before_any_request(changes):
    client = Client([])
    with pytest.raises(ValueError):
        kerberos.ingest_events(client, INDEX, [event(**changes)])
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"win.status": "0"}, {"ticket.encryption_type": "23"}, {"service.id": "not-a-sid"},
    {"user.domain": ["lab.example"]}, {"@timestamp": "2026-01-01T03:05:00+03:00"},
])
def test_directly_written_noncanonical_source_is_rejected_and_pit_closed(changes):
    item = event(**changes)
    client = Client([mapping(), identity(), {"id": "kerberos-pit"}, page([hit(item, 0)]),
                     {"succeeded": True}])
    with pytest.raises(ValueError):
        kerberos.evaluate_index(client, INDEX, load_hunt(HUNT))
    assert client.calls[-1] == ("DELETE", "/_pit", {"id": "kerberos-pit"})


def test_existing_event_payload_conflict_is_rejected_without_write():
    item = event()
    stored = {**item, "service.id": "S-1-5-21-100-200-300-9999"}
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                                                      "found": True, "_source": stored}]}])
    with pytest.raises(kerberos.ElasticError, match="Conflicting stored"):
        kerberos.ingest_events(client, INDEX, [item])
    assert not any("_bulk" in path for _, path, _ in client.calls)


def test_duplicate_retry_refreshes_visibility_without_another_write():
    item = event()
    client = Client([mapping(), identity(), {"docs": [{"_index": INDEX, "_id": item["event.id"],
                                                      "found": True, "_source": item}]}, identity(),
                     {"_shards": {"total": 1, "successful": 1, "failed": 0}}, identity()])
    result = kerberos.ingest_events(client, INDEX, [item, item])
    assert result["inserted_events"] == 0
    assert result["existing_events"] == 1
    assert result["duplicate_events"] == 1
    assert not any("_bulk" in path for _, path, _ in client.calls)
    assert any(path.endswith("/_refresh") for _, path, _ in client.calls)
