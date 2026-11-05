"""Episode projection from real rolling state to Elasticsearch Basic.

Raw alerts are produced by the actual auth-v2 adapter/runner. Expected grouping,
topology and revision behavior is declared here independently of the episode
engine. All records and indices are synthetic and owned by these tests.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

import pytest

from tools.elastic_adapter import ElasticHTTPError
from tools.elastic_rolling import ElasticClient, create_index, index_path, ingest_events
from tools.episode_runner import EpisodeRunner, create_episode_index
from tools.rolling_runner import RollingDetectionRunner, create_alert_index

ROOT = Path(__file__).resolve().parents[2]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run real Basic episode tests")
    result = ElasticClient(url, api_key=os.environ.get("ELASTIC_API_KEY"),
                           username=os.environ.get("ELASTIC_USERNAME"),
                           password=os.environ.get("ELASTIC_PASSWORD"))
    license = result.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return result


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def events(count, *, prefix="event", at="2026-01-01T00:05:00Z", user="lab\\alice"):
    return [{"@timestamp": at, "event.id": f"{prefix}-{number}",
             "event.dataset": "windows.security.logons", "event.code": "4625",
             "source.ip": "192.0.2.10", "target.user": user}
            for number in range(count)]


def documents(client, index):
    client.request("POST", index_path(index) + "/_refresh")
    result = client.request("POST", index_path(index) + "/_search", {
        "size": 100, "track_total_hits": True, "query": {"match_all": {}}})["hits"]
    assert result["total"]["relation"] == "eq"
    assert result["total"]["value"] == len(result["hits"])
    return {hit["_id"]: hit["_source"] for hit in result["hits"]}


def state_dump(path):
    with sqlite3.connect(path) as connection:
        return "\n".join(connection.iterdump())


class Lab:
    def __init__(self, client, path):
        self.client = client
        self.source = "attck-episode-source-" + uuid4().hex
        self.raw_sink = "attck-episode-raw-" + uuid4().hex
        self.sink = "attck-episode-projection-" + uuid4().hex
        self.raw_state = path / "raw.sqlite"
        self.state = path / "episodes.sqlite"
        self.now = timestamp("2026-01-01T00:06:00Z")

    def raw_runner(self, **overrides):
        settings = {"source_client": self.client, "source_index": self.source,
                    "alerts_index": self.raw_sink, "state_path": self.raw_state,
                    "initial_start": "2026-01-01T00:04:00Z", "rule_paths": [BRUTE],
                    "lookback": timedelta(minutes=30), "allowed_lateness": timedelta(0),
                    "clock": lambda: self.now, "page_size": 2}
        settings.update(overrides)
        return RollingDetectionRunner(**settings)

    def projector(self, **overrides):
        settings = {"source_state": self.raw_state, "state_path": self.state,
                    "sink_client": self.client, "episodes_index": self.sink,
                    "gap": timedelta(seconds=10),
                    "clock": lambda: timestamp("2026-01-01T01:00:00Z")}
        settings.update(overrides)
        return EpisodeRunner(**settings)

    def ingest(self, rows):
        return ingest_events(self.client, self.source, rows)


@contextmanager
def lab(client, path):
    instance = Lab(client, path)
    try:
        create_index(client, instance.source)
        create_alert_index(client, instance.raw_sink)
        create_episode_index(client, instance.sink)
        yield instance
    finally:
        for name in (instance.source, instance.raw_sink, instance.sink):
            try:
                client.request("DELETE", index_path(name))
            except ElasticHTTPError as exc:
                if exc.status != 404:
                    raise


def test_groups_rules_and_peak_metrics_preserve_every_raw_alert(client, tmp_path):
    with lab(client, tmp_path) as system:
        rows = [*events(10), *events(1, prefix="next", at="2026-01-01T00:05:01Z"),
                *events(1, prefix="last", at="2026-01-01T00:05:02Z"),
                *events(10, prefix="bob", user="lab\\bob")]
        for number in range(13):
            rows.extend(events(1, prefix=f"spray-{number}", user=f"lab\\other-{number}"))
        system.ingest(rows)
        system.raw_runner(rule_paths=None).run_once()
        raw_before = documents(client, system.raw_sink)
        assert len(raw_before) == 7  # Alice 3, Bob 1, spraying 3.
        projection = system.projector()
        assert projection.run_once()["ok"]
        projected = documents(client, system.sink)
        assert len(projected) == 3
        assert sum(item["anchor_count"] for item in projected.values()) == 7
        assert {member for item in projected.values() for member in item["member_alert_ids"]} == set(raw_before)
        alice = next(item for item in projected.values() if item["group"].get("target.user") == "lab\\alice")
        bob = next(item for item in projected.values() if item["group"].get("target.user") == "lab\\bob")
        spray = next(item for item in projected.values() if "target.user" not in item["group"])
        assert alice["anchor_count"] == 3 and alice["peak_metrics"] == {"fails": 12}
        assert bob["peak_metrics"] == {"fails": 10}
        assert spray["anchor_count"] == 3 and spray["peak_metrics"] == {"distinct_users": 15}
        assert all(item["revision"] == 1 for item in projected.values())
        assert projection.run_once()["ok"]
        assert documents(client, system.sink) == projected
        assert documents(client, system.raw_sink) == raw_before


def test_late_bridge_merges_then_retraction_splits_and_reactivates_ids(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(10), *events(1, prefix="later", at="2026-01-01T00:05:20Z")])
        system.raw_runner().run_once()
        system.projector().run_once()
        initial = documents(client, system.sink)
        assert len(initial) == 2
        earliest = min(initial, key=lambda key: timestamp(initial[key]["first_anchor"]))
        later = next(key for key in initial if key != earliest)

        system.ingest(events(1, prefix="bridge", at="2026-01-01T00:05:10Z"))
        system.raw_runner().run_once()
        system.projector().run_once()
        merged = documents(client, system.sink)
        assert set(merged) == set(initial)
        assert merged[earliest]["anchor_count"] == 3
        assert merged[earliest]["peak_metrics"] == {"fails": 12}
        assert merged[later]["status"] == "retracted"
        assert merged[later]["replacement_episode_ids"] == [earliest]
        assert {item["revision"] for item in merged.values()} == {2}

        client.request("DELETE", index_path(system.source) + "/_doc/bridge-0?refresh=true")
        system.raw_runner().run_once()
        system.projector().run_once()
        split = documents(client, system.sink)
        assert set(split) == set(initial)
        assert all(item["status"] == "closed" for item in split.values())
        assert all(item["anchor_count"] == 1 for item in split.values())
        assert all(item["revision"] == 3 for item in split.values())
        assert split[later]["replacement_episode_ids"] == []
        assert split[later]["first_detected_at"] == initial[later]["first_detected_at"]
        raw = documents(client, system.raw_sink)
        assert len(raw) == 3 and sum(item["status"] == "retracted" for item in raw.values()) == 1
        with pytest.raises(ElasticHTTPError) as stale:
            client.request("PUT", index_path(system.sink) + "/_doc/" + later
                           + "?version=2&version_type=external_gte&refresh=true", merged[later])
        assert stale.value.status == 409
        assert documents(client, system.sink) == split


def test_late_earlier_anchor_rekeys_with_explicit_replacement(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))
        system.raw_runner().run_once()
        system.projector().run_once()
        initial = documents(client, system.sink)
        old_id = next(iter(initial))
        system.ingest(events(10, prefix="earlier", at="2026-01-01T00:04:59Z"))
        system.raw_runner().run_once()
        system.projector().run_once()
        current = documents(client, system.sink)
        new_id = next(key for key in current if key != old_id)
        assert current[old_id]["status"] == "retracted"
        assert current[old_id]["replacement_episode_ids"] == [new_id]
        assert current[new_id]["first_anchor"] == "2026-01-01T00:04:59Z"
        assert current[new_id]["last_anchor"] == "2026-01-01T00:05:00Z"
        assert current[new_id]["anchor_count"] == 2
        assert current[new_id]["peak_metrics"] == {"fails": 20}


def test_closure_is_strictly_after_gap_and_late_member_reopens(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.now = timestamp("2026-01-01T00:05:10Z")
        system.ingest(events(10))
        system.raw_runner().run_once()
        system.projector().run_once()
        opened = documents(client, system.sink)
        identifier = next(iter(opened))
        assert opened[identifier]["status"] == "open"
        system.now += timedelta(microseconds=1)
        system.raw_runner().run_once()
        system.projector().run_once()
        closed = documents(client, system.sink)
        assert closed[identifier]["status"] == "closed" and closed[identifier]["revision"] == 2
        system.ingest(events(1, prefix="late", at="2026-01-01T00:05:09Z"))
        system.raw_runner().run_once()
        system.projector().run_once()
        reopened = documents(client, system.sink)
        assert set(reopened) == {identifier}
        assert reopened[identifier]["status"] == "open"
        assert reopened[identifier]["anchor_count"] == 2 and reopened[identifier]["revision"] == 3
        assert reopened[identifier]["last_anchor"] == "2026-01-01T00:05:09Z"


@pytest.mark.parametrize("limits", [{"max_source_alerts": 2}, {"max_changes": 1}], ids=["source", "changes"])
def test_cap_failure_preserves_complete_projection_and_source_baseline(client, tmp_path, limits):
    with lab(client, tmp_path) as system:
        system.now = timestamp("2026-01-01T00:05:00Z")
        system.raw_runner().run_once()
        system.projector(gap=timedelta(seconds=5)).run_once()
        before = state_dump(system.state)
        system.ingest([*events(10), *events(1, prefix="near", at="2026-01-01T00:05:01Z"),
                       *events(1, prefix="far", at="2026-01-01T00:05:10Z")])
        system.now = timestamp("2026-01-01T00:05:11Z")
        system.raw_runner().run_once()
        with pytest.raises(ValueError):
            system.projector(gap=timedelta(seconds=5), **limits).run_once()
        assert state_dump(system.state) == before
        assert documents(client, system.sink) == {}
        assert system.projector(gap=timedelta(seconds=5)).run_once()["ok"]
        assert len(documents(client, system.sink)) == 2


class InjectedCrash(RuntimeError):
    pass


@pytest.mark.parametrize("stage,remote_count", [("before_commit", 0), ("after_commit", 0), ("after_delivery", 1)])
def test_committed_episode_outbox_recovers_each_crash_boundary(client, tmp_path, stage, remote_count):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))
        system.raw_runner().run_once()

        def fail(current, _context):
            if current == stage:
                raise InjectedCrash(stage)

        with pytest.raises(InjectedCrash):
            system.projector(fault_hook=fail).run_once()
        assert len(documents(client, system.sink)) == remote_count
        restarted = system.projector()
        assert restarted.run_once()["ok"]
        current = documents(client, system.sink)
        assert len(current) == 1 and next(iter(current.values()))["revision"] == 1
        assert restarted.status()["pending_outbox"] == 0
        assert restarted.run_once()["ok"]
        assert documents(client, system.sink) == current


def test_pending_raw_delivery_gates_projection_until_raw_restart(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))

        def fail(stage, _context):
            if stage == "after_commit":
                raise InjectedCrash(stage)

        with pytest.raises(InjectedCrash):
            system.raw_runner(fault_hook=fail).run_once()
        assert documents(client, system.raw_sink) == {}
        waiting = system.projector().run_once()
        assert waiting["ok"] is False and waiting["status"] == "waiting_for_raw_delivery"
        assert documents(client, system.sink) == {}
        system.raw_runner().run_once()
        assert system.projector().run_once()["ok"]
        assert len(documents(client, system.raw_sink)) == len(documents(client, system.sink)) == 1


def test_recreated_episode_sink_receives_no_old_outbox(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))
        system.raw_runner().run_once()

        def fail(stage, _context):
            if stage == "after_commit":
                raise InjectedCrash(stage)

        with pytest.raises(InjectedCrash):
            system.projector(fault_hook=fail).run_once()
        assert system.projector().status()["pending_outbox"] == 1
        client.request("DELETE", index_path(system.sink))
        create_episode_index(client, system.sink)
        with pytest.raises(ValueError):
            system.projector(initialize_index=True).run_once()
        assert documents(client, system.sink) == {}
        assert system.projector().status()["pending_outbox"] == 1


def test_missing_raw_history_is_an_error_not_an_episode_retraction(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest([*events(10), *events(1, prefix="next", at="2026-01-01T00:05:01Z")])
        system.raw_runner().run_once()
        system.projector().run_once()
        before = state_dump(system.state)
        original = documents(client, system.sink)
        with sqlite3.connect(system.raw_state) as connection:
            connection.execute("DELETE FROM alerts WHERE alert_id=(SELECT alert_id FROM alerts ORDER BY window_end LIMIT 1)")
        with pytest.raises(ValueError):
            system.projector().run_once()
        assert state_dump(system.state) == before
        assert documents(client, system.sink) == original


def test_source_database_replacement_is_rejected_even_with_identical_contents(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))
        system.raw_runner().run_once()
        system.projector().run_once()
        original = documents(client, system.sink)
        before = state_dump(system.state)
        replacement = tmp_path / "replacement.sqlite"
        with sqlite3.connect(system.raw_state) as source, sqlite3.connect(replacement) as target:
            source.backup(target)
        replacement.replace(system.raw_state)
        with pytest.raises(ValueError):
            system.projector().run_once()
        assert state_dump(system.state) == before
        assert documents(client, system.sink) == original


def test_fresh_state_cannot_adopt_a_nonempty_episode_sink(client, tmp_path):
    with lab(client, tmp_path) as system:
        system.ingest(events(10))
        system.raw_runner().run_once()
        system.projector().run_once()
        original = documents(client, system.sink)
        assert len(original) == 1 and next(iter(original.values()))["revision"] == 1
        bound_state = state_dump(system.state)

        # Same deterministic ID + external_gte revision 1 could otherwise
        # replace the immutable payload from the original state's revision 1.
        with pytest.raises(ValueError):
            system.projector(state_path=tmp_path / "fresh-episodes.sqlite",
                             initialize_index=True,
                             clock=lambda: timestamp("2026-01-01T02:00:00Z")).run_once()
        assert documents(client, system.sink) == original
        assert state_dump(system.state) == bound_state

        # Existing bound state still resumes with the same nonempty sink.
        assert system.projector().run_once()["ok"]
        assert documents(client, system.sink) == original
