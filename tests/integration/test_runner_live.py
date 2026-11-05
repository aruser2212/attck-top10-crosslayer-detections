"""Real Elasticsearch Basic checks for bounded evaluation and durable delivery."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from tools.elastic_adapter import (
    ElasticClient, ElasticError, ElasticHTTPError, create_index, evaluate_index, get_index_identity,
    index_path, ingest_events,
)
from tools.hunt_engine import load_hunt
from tools.detection_runner import DetectionRunner, RunnerError

ROOT = Path(__file__).resolve().parents[2]
BRUTE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml"
pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def client():
    url = os.environ.get("ELASTIC_URL")
    if not url:
        pytest.skip("Set ELASTIC_URL to run the real Elasticsearch runner suite")
    connection = ElasticClient(
        url, api_key=os.environ.get("ELASTIC_API_KEY"),
        username=os.environ.get("ELASTIC_USERNAME"), password=os.environ.get("ELASTIC_PASSWORD"),
    )
    license = connection.request("GET", "/_license")["license"]
    assert license["type"] == "basic" and license["status"] == "active"
    return connection


@contextmanager
def source_index(client):
    name = "attck-runner-test-" + uuid4().hex
    create_index(client, name)
    try:
        yield name
    finally:
        client.request("DELETE", index_path(name))


def events(count, *, prefix="source", timestamp="2026-01-01T00:01:00Z"):
    return [
        {"@timestamp": timestamp, "event.id": f"{prefix}-{i}",
         "event.dataset": "windows.security.logons", "event.code": "4625",
         "source.ip": "192.0.2.10", "target.user": "alice"}
        for i in range(count)
    ]


@contextmanager
def alert_index(client):
    name = "attck-runner-alerts-" + uuid4().hex
    mapping = json.loads((ROOT / "profiles/elastic/alerts-v1.mapping.json").read_text())
    client.request("PUT", index_path(name), mapping)
    try:
        yield name
    finally:
        client.request("DELETE", index_path(name))


def runner(client, source, sink, state_path, now, **overrides):
    settings = {
        "source_client": client, "source_index": source, "alerts_index": sink,
        "state_path": state_path, "rule_paths": [BRUTE],
        "initial_start": "2026-01-01T00:00:00Z",
        "lookback": timedelta(minutes=10), "allowed_lateness": timedelta(0),
        "clock": lambda: now["value"],
    }
    settings.update(overrides)
    return DetectionRunner(**settings)


def documents(client, index):
    response = client.request(
        "POST", index_path(index) + "/_search",
        {"size": 100, "track_total_hits": True, "query": {"match_all": {}}},
    )
    assert response["hits"]["total"]["value"] == len(response["hits"]["hits"])
    return response["hits"]["hits"]


def clock(minute=5):
    return {"value": datetime(2026, 1, 1, 0, minute, tzinfo=timezone.utc)}


def test_native_bounded_replay_excludes_neighbor_windows(client):
    with source_index(client) as index:
        ingest_events(client, index, [
            *events(10, prefix="before"),
            *events(10, prefix="selected", timestamp="2026-01-01T00:05:00Z"),
            *events(10, prefix="after", timestamp="2026-01-01T00:10:00Z"),
        ])
        identity = get_index_identity(client, index)
        result = evaluate_index(
            client, index, load_hunt(BRUTE), start="2026-01-01T00:05:00Z",
            end="2026-01-01T00:10:00Z", expected_index_uuid=identity["uuid"], page_size=2,
        )
        assert result["alerts"] == [{
            "window.start": "2026-01-01T00:05:00Z", "window.end": "2026-01-01T00:10:00Z",
            "source.ip": "192.0.2.10", "target.user": "alice", "fails": 10,
        }]


def test_native_recreated_source_cannot_reuse_identity(client):
    with source_index(client) as index:
        previous = get_index_identity(client, index)
        client.request("DELETE", index_path(index))
        create_index(client, index)
        current = get_index_identity(client, index)
        assert previous["name"] == current["name"] and previous["uuid"] != current["uuid"]
        with pytest.raises(ElasticError, match="UUID changed"):
            evaluate_index(client, index, load_hunt(BRUTE), expected_index_uuid=previous["uuid"])


def test_runner_late_threshold_replay_metric_update_and_sqlite_restart(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        state = tmp_path / "runner.sqlite"
        active = runner(client, source, sink, state, now)
        ingest_events(client, source, events(9))
        first = active.run_once()
        assert first["alerts"]["created"] == 0
        assert set(first["checkpoints"].values()) == {"2026-01-01T00:05:00Z"}
        assert documents(client, sink) == []

        # This event arrives after its event-time window has closed.
        ingest_events(client, source, events(1, prefix="late-threshold"))
        now["value"] += timedelta(minutes=1)
        assert active.run_once()["alerts"]["created"] == 1
        original = documents(client, sink)
        assert len(original) == 1
        assert original[0]["_source"]["metrics"] == {"fails": 10}
        assert original[0]["_source"]["revision"] == 1
        assert active.run_once()["alerts"]["unchanged"] == 1
        assert documents(client, sink) == original

        # More late evidence updates metrics, retaining the logical alert ID.
        ingest_events(client, source, events(1, prefix="late-update"))
        now["value"] += timedelta(minutes=1)
        assert active.run_once()["alerts"]["updated"] == 1
        updated = documents(client, sink)
        assert len(updated) == 1 and updated[0]["_id"] == original[0]["_id"]
        assert updated[0]["_source"]["metrics"] == {"fails": 11}
        assert updated[0]["_source"]["revision"] == 2
        assert updated[0]["_source"]["first_detected_at"] == original[0]["_source"]["first_detected_at"]

        restarted = runner(client, source, sink, state, now, initial_start=None)
        assert restarted.status()["logical_alerts"] == 1
        assert restarted.run_once()["alerts"]["unchanged"] == 1
        assert restarted.status()["pending_outbox"] == 0
        assert documents(client, sink) == updated


def test_runner_reports_late_horizon_limit_without_synthetic_zero_claim(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        active = runner(client, source, sink, tmp_path / "runner.sqlite", now)
        ingest_events(client, source, events(9))
        active.run_once()
        now["value"] += timedelta(minutes=20)
        active.run_once()
        ingest_events(client, source, events(1, prefix="too-late"))
        result = active.run_once()
        assert result["ranges"][0]["start"] == "2026-01-01T00:15:00Z"
        assert result["late_arrivals_observable"] is False
        assert result["late_arrivals_before_replay_horizon"] is None
        assert documents(client, sink) == []


def test_runner_before_commit_failure_keeps_previous_checkpoint(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        active = runner(client, source, sink, tmp_path / "runner.sqlite", now)
        ingest_events(client, source, events(9))
        active.run_once()
        before = active.status()
        ingest_events(client, source, events(1, prefix="late"))
        now["value"] += timedelta(minutes=5)

        def fail(stage, _context):
            if stage == "before_commit":
                raise RuntimeError("injected pre-commit crash")

        active.fault_hook = fail
        with pytest.raises(RuntimeError, match="pre-commit"):
            active.run_once()
        assert active.status() == before
        assert documents(client, sink) == []
        active.fault_hook = lambda *_: None
        assert active.run_once()["alerts"]["created"] == 1
        assert set(active.status()["checkpoints"].values()) == {"2026-01-01T00:10:00Z"}
        assert len(documents(client, sink)) == 1


class FailingDelivery:
    """Actual Elasticsearch for every operation except an injected sink failure."""

    def __init__(self, client, sink):
        self.client = client
        self.sink = sink
        self.fail = True

    def request(self, method, path, body=None, **kwargs):
        if self.fail and method == "PUT" and path.startswith(index_path(self.sink) + "/_doc/"):
            raise ElasticError("injected delivery outage")
        return self.client.request(method, path, body, **kwargs)


def test_runner_sink_failure_retries_durable_outbox_after_restart(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        delivery = FailingDelivery(client, sink)
        state = tmp_path / "runner.sqlite"
        active = runner(client, source, sink, state, now, alerts_client=delivery)
        ingest_events(client, source, events(10))
        with pytest.raises(RunnerError, match="delivery failed"):
            active.run_once()
        status = active.status()
        assert status["pending_outbox"] == 1 and status["logical_alerts"] == 1
        assert set(status["checkpoints"].values()) == {"2026-01-01T00:05:00Z"}
        assert documents(client, sink) == []

        delivery.fail = False
        now["value"] += timedelta(minutes=25)
        restarted = runner(client, source, sink, state, now, initial_start=None, alerts_client=delivery)
        assert restarted.run_once()["outbox_delivered"] == 1
        assert restarted.status()["pending_outbox"] == 0
        delivered = documents(client, sink)
        assert len(delivered) == 1 and delivered[0]["_source"]["metrics"] == {"fails": 10}


@pytest.mark.parametrize("crash_stage", ["after_commit", "after_delivery"])
def test_runner_crash_after_commit_or_remote_write_is_idempotent(client, tmp_path, crash_stage):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        state = tmp_path / "runner.sqlite"

        def fail(stage, _context):
            if stage == crash_stage:
                raise RuntimeError("injected crash")

        active = runner(client, source, sink, state, now, fault_hook=fail)
        ingest_events(client, source, events(10))
        with pytest.raises(RuntimeError, match="injected"):
            active.run_once()
        assert active.status()["pending_outbox"] == 1
        assert set(active.status()["checkpoints"].values()) == {"2026-01-01T00:05:00Z"}
        before = documents(client, sink)
        assert len(before) == (1 if crash_stage == "after_delivery" else 0)

        restarted = runner(client, source, sink, state, now, initial_start=None)
        assert restarted.run_once()["outbox_delivered"] == 1
        after = documents(client, sink)
        assert len(after) == 1
        assert after[0]["_source"]["revision"] == 1
        if before:
            assert after[0]["_id"] == before[0]["_id"]
            assert after[0]["_source"] == before[0]["_source"]
        assert restarted.status()["pending_outbox"] == 0


def test_runner_rejects_recreated_source_without_reusing_checkpoint(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        active = runner(client, source, sink, tmp_path / "runner.sqlite", now)
        ingest_events(client, source, events(9))
        active.run_once()
        previous = active.status()
        client.request("DELETE", index_path(source))
        create_index(client, source)
        ingest_events(client, source, events(10))
        with pytest.raises(RunnerError, match="scope mismatch"):
            active.run_once()
        assert active.status() == previous
        assert documents(client, sink) == []


def test_native_alert_versions_reject_delayed_stale_write_and_allow_same_revision_retry(client, tmp_path):
    now = clock()
    with source_index(client) as source, alert_index(client) as sink:
        active = runner(client, source, sink, tmp_path / "runner.sqlite", now)
        ingest_events(client, source, events(10))
        active.run_once()
        first = documents(client, sink)[0]
        assert first["_source"]["revision"] == 1
        ingest_events(client, source, events(1, prefix="late-next-revision"))
        now["value"] += timedelta(minutes=1)
        active.run_once()
        second = documents(client, sink)[0]
        assert second["_id"] == first["_id"]
        assert second["_source"]["revision"] == 2
        assert second["_source"]["metrics"] == {"fails": 11}

        # A timed-out revision-1 request may arrive after revision 2. The sink,
        # not merely local scheduling order, must reject that stale mutation.
        path = index_path(sink) + "/_doc/" + first["_id"]
        with pytest.raises(ElasticHTTPError) as stale:
            client.request("PUT", path + "?version=1&version_type=external_gte&refresh=wait_for", first["_source"])
        assert stale.value.status == 409
        assert documents(client, sink) == [second]

        result = client.request("PUT", path + "?version=2&version_type=external_gte&refresh=wait_for", second["_source"])
        assert result["_version"] == 2
        assert documents(client, sink) == [second]
