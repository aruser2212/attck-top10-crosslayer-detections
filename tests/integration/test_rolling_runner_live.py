"""Durable rolling state and delivery against real Elasticsearch Basic.

Synthetic events exercise event-time/recovery contracts, not production recall.
Every test owns distinct source/sink indices and removes only those indices.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticHTTPError
from tools.elastic_rolling import ElasticClient, create_index, index_path, ingest_events
from tools.rolling_runner import RollingDetectionRunner, RunnerError, create_alert_index

ROOT = Path(__file__).resolve().parents[2]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run real Basic durable rolling tests")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"),
                           password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


@contextmanager
def indices(client):
    source = "attck-durable-rolling-source-" + uuid4().hex
    sink = "attck-durable-rolling-alerts-" + uuid4().hex
    create_index(client, source)
    try:
        create_alert_index(client, sink)
        yield source, sink
    finally:
        for index in (source, sink):
            try:
                client.request("DELETE", index_path(index))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def events(count, *, prefix="event", at="2026-01-01T00:04:59Z"):
    return [{"@timestamp": at, "event.id": f"{prefix}-{i}",
             "event.dataset": "windows.security.logons", "event.code": "4625",
             "source.ip": "192.0.2.10", "target.user": "lab\\alice"}
            for i in range(count)]


def make_runner(client, source, sink, state, now, **overrides):
    settings = {"source_client": client, "source_index": source, "alerts_index": sink,
                "state_path": state, "rule_paths": [BRUTE],
                "initial_start": "2026-01-01T00:05:00Z",
                "lookback": timedelta(minutes=10), "allowed_lateness": timedelta(0),
                "clock": lambda: now["value"], "page_size": 2}
    settings.update(overrides)
    return RollingDetectionRunner(**settings)


def documents(client, index):
    client.request("POST", index_path(index) + "/_refresh")
    result = client.request("POST", index_path(index) + "/_search",
                            {"size": 100, "track_total_hits": True,
                             "query": {"match_all": {}}})["hits"]
    assert result["total"]["relation"] == "eq"
    assert result["total"]["value"] == len(result["hits"])
    return sorted(result["hits"], key=lambda hit: hit["_id"])


def test_late_pre_start_context_updates_exact_anchor_after_restart(client, tmp_path):
    anchor = "2026-01-01T00:05:00.123456Z"
    now = {"value": timestamp("2026-01-01T00:05:00.123457Z")}
    with indices(client) as (source, sink):
        state = tmp_path / "rolling.sqlite"
        active = make_runner(client, source, sink, state, now, initial_start=anchor)
        ingest_events(client, source, [
            *events(8, prefix="history", at="2026-01-01T00:00:00.123457Z"),
            *events(1, prefix="excluded-left-edge", at="2026-01-01T00:00:00.123456Z"),
            *events(1, prefix="anchor", at=anchor),
        ])
        assert active.run_once()["alerts"]["created"] == 0
        assert documents(client, sink) == []

        # This event precedes the first eligible anchor but belongs to its window.
        ingest_events(client, source, events(1, prefix="late-context", at="2026-01-01T00:01:00Z"))
        assert active.run_once()["alerts"]["created"] == 1
        original = documents(client, sink)[0]
        assert original["_source"]["metrics"] == {"fails": 10}
        assert original["_source"]["window"] == {
            "start": "2026-01-01T00:00:00.123456Z", "end": anchor}

        ingest_events(client, source, events(1, prefix="late-update", at="2026-01-01T00:02:00Z"))
        restarted = make_runner(client, source, sink, state, now, initial_start=None)
        assert restarted.run_once()["alerts"]["updated"] == 1
        current = documents(client, sink)[0]
        assert current["_id"] == original["_id"]
        assert current["_source"]["revision"] == 2
        assert current["_source"]["metrics"] == {"fails": 11}
        assert current["_source"]["first_detected_at"] == original["_source"]["first_detected_at"]
        assert restarted.run_once()["alerts"]["unchanged"] == 1
        assert documents(client, sink) == [current]
        assert restarted.status()["pending_outbox"] == 0

        # The remote sink itself rejects a delayed older revision.
        path = index_path(sink) + "/_doc/" + original["_id"]
        with pytest.raises(ElasticHTTPError) as stale:
            client.request("PUT", path + "?version=1&version_type=external_gte&refresh=true", original["_source"])
        assert stale.value.status == 409
        retry = client.request("PUT", path + "?version=2&version_type=external_gte&refresh=true", current["_source"])
        assert retry["_version"] == 2
        assert documents(client, sink) == [current]


def test_one_microsecond_anchors_have_distinct_ids_and_native_dates(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:05:01.000003Z")}
    with indices(client) as (source, sink):
        ingest_events(client, source, [
            *events(9),
            *events(1, prefix="first", at="2026-01-01T00:05:01.000001Z"),
            *events(1, prefix="second", at="2026-01-01T00:05:01.000002Z"),
            *events(1, prefix="excluded-end", at="2026-01-01T00:05:01.000003Z"),
        ])
        active = make_runner(client, source, sink, tmp_path / "rolling.sqlite", now)
        assert active.run_once()["alerts"]["created"] == 2
        hits = documents(client, sink)
        assert len({hit["_id"] for hit in hits}) == 2
        ordered = sorted(hits, key=lambda hit: hit["_source"]["window"]["end"])
        assert [hit["_source"]["metrics"]["fails"] for hit in ordered] == [10, 11]
        native = client.request("POST", index_path(sink) + "/_search", {
            "_source": False, "sort": [{"window.end": {"order": "asc", "format": "strict_date_optional_time_nanos"}}],
            "query": {"match_all": {}}})["hits"]["hits"]
        assert timestamp(native[1]["sort"][0]) - timestamp(native[0]["sort"][0]) == timedelta(microseconds=1)
        assert set(active.status()["checkpoints"].values()) == {"2026-01-01T00:05:01.000003Z"}


def test_forward_chunks_progress_when_lookback_exceeds_chunk_span(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:03:00Z")}
    with indices(client) as (source, sink):
        ingest_events(client, source, events(10, at="2026-01-01T00:02:30Z"))
        active = make_runner(client, source, sink, tmp_path / "rolling.sqlite", now,
                             initial_start="2026-01-01T00:00:00Z", max_forward_span=timedelta(minutes=1))
        for minute in (1, 2, 3):
            result = active.run_once()
            assert set(result["checkpoints"].values()) == {f"2026-01-01T00:0{minute}:00Z"}
            assert result["caught_up"] is (minute == 3)
            assert result["alerts"]["created"] == (1 if minute == 3 else 0)
        assert len(documents(client, sink)) == 1


@pytest.mark.parametrize("limit", [{"max_events": 9}, {"max_alerts": 1}], ids=["events", "alerts"])
def test_native_cap_failure_preserves_previous_checkpoint_and_outbox(client, tmp_path, limit):
    now = {"value": timestamp("2026-01-01T00:05:00Z")}
    with indices(client) as (source, sink):
        active = make_runner(client, source, sink, tmp_path / "rolling.sqlite", now,
                             initial_start="2026-01-01T00:04:58Z", **limit)
        active.run_once()
        before = active.status()
        ingest_events(client, source, [
            *events(9),
            *events(1, prefix="first", at="2026-01-01T00:05:01Z"),
            *events(1, prefix="second", at="2026-01-01T00:05:02Z"),
        ])
        now["value"] = timestamp("2026-01-01T00:05:03Z")
        with pytest.raises(ValueError, match="max_events|max_alerts"):
            active.run_once()
        assert active.status() == before
        assert documents(client, sink) == []


def test_combined_rule_alert_cap_is_atomic_and_can_be_raised_on_restart(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:05:00.000001Z")}
    with indices(client) as (source, sink):
        state = tmp_path / "rolling.sqlite"
        active = make_runner(client, source, sink, state, now, rule_paths=None, max_alerts=1)
        active.run_once()
        before = active.status()
        assert len(before["checkpoints"]) == 2
        # Exactly one brute-force anchor and one password-spray anchor. Each
        # individual query fits max_alerts=1, but their combined pass does not.
        population = events(10, at="2026-01-01T00:05:00Z")
        population.extend({**events(1, prefix=f"distinct-{i}", at="2026-01-01T00:05:00Z")[0],
                           "target.user": f"lab\\user-{i}"} for i in range(14))
        ingest_events(client, source, population)
        with pytest.raises(RunnerError, match="max_alerts"):
            active.run_once()
        assert active.status() == before
        assert documents(client, sink) == []
        restarted = make_runner(client, source, sink, state, now, initial_start=None,
                                 rule_paths=None, max_alerts=2)
        result = restarted.run_once()
        assert result["alerts"]["created"] == 2
        assert len(documents(client, sink)) == 2
        assert restarted.status()["pending_outbox"] == 0


@pytest.mark.parametrize("stage", ["before_commit", "after_commit", "after_delivery"])
def test_native_transaction_and_outbox_crash_recovery(client, tmp_path, stage):
    now = {"value": timestamp("2026-01-01T00:05:01.000001Z")}
    with indices(client) as (source, sink):
        ingest_events(client, source, [*events(9), *events(1, prefix="anchor", at="2026-01-01T00:05:01Z")])
        state = tmp_path / "rolling.sqlite"

        def crash(current_stage, _context):
            if current_stage == stage:
                raise RuntimeError("injected native rolling crash")

        active = make_runner(client, source, sink, state, now, fault_hook=crash)
        with pytest.raises(RuntimeError, match="injected native"):
            active.run_once()
        before = documents(client, sink)
        assert len(before) == (1 if stage == "after_delivery" else 0)
        status = active.status()
        assert status["pending_outbox"] == (0 if stage == "before_commit" else 1)
        expected_checkpoint = "2026-01-01T00:05:00Z" if stage == "before_commit" else "2026-01-01T00:05:01.000001Z"
        assert set(status["checkpoints"].values()) == {expected_checkpoint}

        restarted = make_runner(client, source, sink, state, now, initial_start=None)
        restarted.run_once()
        after = documents(client, sink)
        assert len(after) == 1
        assert after[0]["_source"]["revision"] == 1
        assert after[0]["_source"]["metrics"] == {"fails": 10}
        assert restarted.status()["pending_outbox"] == 0
        if before:
            assert before == after


def test_anchor_deletion_retracts_and_reactivation_preserves_logical_id(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:05:00.000001Z")}
    anchor = events(1, prefix="anchor", at="2026-01-01T00:05:00Z")
    with indices(client) as (source, sink):
        ingest_events(client, source, [*events(9), *anchor])
        active = make_runner(client, source, sink, tmp_path / "rolling.sqlite", now)
        active.run_once()
        original = documents(client, sink)[0]
        # The alert's window.start is earlier than initial_start. Replay must
        # select persisted alerts by window.end, including a deleted anchor.
        client.request("DELETE", index_path(source) + "/_doc/anchor-0?refresh=true")
        assert active.run_once()["alerts"]["retracted"] == 1
        retracted = documents(client, sink)[0]
        assert retracted["_id"] == original["_id"]
        assert retracted["_source"]["status"] == "retracted"
        assert retracted["_source"]["revision"] == 2
        ingest_events(client, source, anchor)
        active.run_once()
        revived = documents(client, sink)[0]
        assert revived["_id"] == original["_id"]
        assert revived["_source"]["status"] == "active"
        assert revived["_source"]["revision"] == 3
        assert revived["_source"]["first_detected_at"] == original["_source"]["first_detected_at"]


def test_recreated_source_does_not_advance_bound_state(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:05:01Z")}
    with indices(client) as (source, sink):
        active = make_runner(client, source, sink, tmp_path / "rolling.sqlite", now)
        active.run_once()
        before = active.status()
        client.request("DELETE", index_path(source))
        create_index(client, source)
        ingest_events(client, source, events(10, at="2026-01-01T00:05:00Z"))
        with pytest.raises(RunnerError, match="scope|UUID|binding"):
            active.run_once()
        assert active.status() == before
        assert documents(client, sink) == []


def test_recreated_sink_receives_no_old_pending_outbox(client, tmp_path):
    now = {"value": timestamp("2026-01-01T00:05:01Z")}
    with indices(client) as (source, sink):
        ingest_events(client, source, events(10, at="2026-01-01T00:05:00Z"))

        def crash(stage, _context):
            if stage == "after_commit":
                raise RuntimeError("leave pending outbox")

        state = tmp_path / "rolling.sqlite"
        active = make_runner(client, source, sink, state, now, fault_hook=crash)
        with pytest.raises(RuntimeError, match="pending outbox"):
            active.run_once()
        before = active.status()
        assert before["pending_outbox"] == 1
        client.request("DELETE", index_path(sink))
        create_alert_index(client, sink)
        restarted = make_runner(client, source, sink, state, now, initial_start=None)
        with pytest.raises(RunnerError, match="scope|UUID|binding"):
            restarted.run_once()
        assert restarted.status() == before
        assert documents(client, sink) == []
