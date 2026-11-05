"""Durability and finite event-time scheduling tests with explicit fault injection."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
from threading import Event
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from tools.rolling_runner import (
    DEFAULT_RULES, RollingDetectionRunner, MAPPING_PATH, RunnerBusy, RunnerError,
    create_alert_index,
)
from tools.elastic_adapter import ElasticError, ElasticHTTPError
from tools.hunt_engine import parse_timestamp, window_seconds
from tools.rolling_hunt import evaluate_hunt
from tools.elastic_rolling import MAPPING_PATH as SOURCE_MAPPING_PATH

ROOT = Path(__file__).resolve().parents[1]
INITIAL = "2026-01-01T00:00:00Z"


class MemoryElastic:
    def __init__(self):
        self.uuids = {"auth-source": "source-uuid"}
        self.mappings = {"auth-source": json.loads(SOURCE_MAPPING_PATH.read_text())["mappings"]}
        self.documents = {}
        self.calls = []
        self.write_failure = False
        self.partial_write = False
        self.delay_next_write = False
        self.delayed = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        index = path.split("/")[1]
        if path.endswith("/_settings?flat_settings=true"):
            return {index: {"settings": {"index.uuid": self.uuids[index]}}}
        if path.endswith("/_mapping"):
            if index not in self.mappings:
                raise ElasticHTTPError(404, "missing index")
            return {index: {"mappings": deepcopy(self.mappings[index])}}
        if method == "PUT" and "/_doc/" not in path:
            assert index not in self.mappings
            self.mappings[index] = deepcopy(body["mappings"])
            self.uuids[index] = "sink-uuid"
            return {"acknowledged": True}
        if method == "PUT" and "/_doc/" in path:
            if self.write_failure:
                raise ElasticHTTPError(503, "simulated sink outage")
            if self.delay_next_write:
                self.delay_next_write = False
                self.delayed.append((method, path, deepcopy(body)))
                raise ElasticError("Client timed out; server may still complete the write")
            identifier = path.split("/_doc/")[1].split("?")[0]
            options = parse_qs(urlparse(path).query)
            assert options["version_type"] == ["external_gte"]
            assert int(options["version"][0]) == body["revision"]
            existed = identifier in self.documents
            if existed and self.documents[identifier]["revision"] > body["revision"]:
                raise ElasticHTTPError(409, "stale external revision")
            self.documents[identifier] = deepcopy(body)
            return {"_id": identifier, "_index": index, "_version": body["revision"], "result": "updated" if existed else "created", "_shards": {"failed": 1 if self.partial_write else 0}}
        raise AssertionError((method, path))


class ReplayEvaluator:
    """Executes the real Hunt rules, restricted to the runner's requested range."""
    def __init__(self, events=()):
        self.events = deepcopy(list(events))
        self.calls = []
        self.failure = None
        self.after_evaluate = None

    def __call__(self, client, index, rule, *, start, end, expected_index_uuid, page_size, max_events, max_alerts):
        assert client.uuids[index] == expected_index_uuid
        self.calls.append({"start": start, "end": end, "rule": deepcopy(rule)})
        if self.failure:
            raise self.failure
        lower = parse_timestamp(start) - timedelta(seconds=window_seconds(rule["aggregate"]["window"]))
        events = [event for event in self.events if lower < parse_timestamp(event["@timestamp"]) < parse_timestamp(end)]
        result = evaluate_hunt(rule, events, start=start, end=end, max_events=max_events, max_alerts=max_alerts)
        if self.after_evaluate:
            self.after_evaluate(client)
        return result


def events(count=10, *, at="2026-01-01T00:01:00Z", user="alice"):
    return [{"event.id": f"event-{i}", "event.dataset": "windows.security.logons", "event.code": "4625", "@timestamp": at, "source.ip": "192.0.2.1", "target.user": user} for i in range(count)]


def make_runner(tmp_path, *, client=None, evaluator=None, now="2026-01-01T00:12:00Z", **kwargs):
    client = client or MemoryElastic()
    evaluator = evaluator or ReplayEvaluator(events())
    config = dict(source_client=client, source_index="auth-source", alerts_index="auth-alerts",
                  state_path=tmp_path / "state.sqlite", initial_start=INITIAL,
                  clock=lambda: parse_timestamp(now), evaluator=evaluator, initialize_alerts=True)
    config.update(kwargs)
    return RollingDetectionRunner(**config), client, evaluator


def only_alert(client):
    assert len(client.documents) == 1
    return next(iter(client.documents.values()))




def test_closed_windows_empty_results_and_wal_checkpoint(tmp_path):
    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator([]))
    result = runner.run_once()
    assert {call["end"] for call in evaluator.calls} == {"2026-01-01T00:10:00Z"}
    assert {call["start"] for call in evaluator.calls} == {INITIAL}
    assert set(result["checkpoints"].values()) == {"2026-01-01T00:10:00Z"}
    assert result["alerts"]["created"] == 0
    assert runner.status()["pending_outbox"] == 0
    with sqlite3.connect(runner.state_path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"

def test_overlap_restart_and_metric_updates_keep_logical_id(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    first = runner.run_once()
    old = deepcopy(only_alert(client))
    assert first["alerts"]["created"] == 1
    second = runner.run_once()
    assert second["alerts"]["unchanged"] == 1
    assert second["outbox_delivered"] == 0
    assert only_alert(client) == old
    evaluator.events = events(11)
    restarted, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, initial_start=None, now="2026-01-01T00:16:00Z")
    updated = restarted.run_once()
    alert = only_alert(client)
    assert updated["alerts"]["updated"] == 1
    assert alert["alert_id"] == old["alert_id"]
    assert alert["revision"] == 2
    assert alert["metrics"] == {"fails": 11}
    assert alert["first_detected_at"] == old["first_detected_at"]

def test_late_event_within_overlap_crosses_threshold(tmp_path):
    evaluator = ReplayEvaluator(events(9))
    runner, client, _ = make_runner(tmp_path, evaluator=evaluator)
    runner.run_once()
    assert client.documents == {}
    evaluator.events = events(10)
    runner.run_once()
    assert only_alert(client)["metrics"] == {"fails": 10}

def test_too_old_arrivals_not_claimed_observable(tmp_path):
    evaluator = ReplayEvaluator(events(9))
    runner, client, _ = make_runner(tmp_path, evaluator=evaluator, lookback=timedelta(0))
    runner.run_once()
    evaluator.events = events(10)
    later, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, now="2026-01-01T00:22:00Z", lookback=timedelta(0))
    result = later.run_once()
    assert client.documents == {}
    assert {item["start"] for item in result["ranges"]} == {"2026-01-01T00:10:00Z"}
    assert result["late_arrivals_observable"] is False
    assert result["late_arrivals_before_replay_horizon"] is None

def test_replay_retracts_then_reactivates_same_alert(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    runner.run_once()
    identifier = only_alert(client)["alert_id"]
    evaluator.events = events(9)
    assert runner.run_once()["alerts"]["retracted"] == 1
    assert only_alert(client)["status"] == "retracted"
    evaluator.events = events(12)
    runner.run_once()
    assert only_alert(client)["status"] == "active"
    assert only_alert(client)["revision"] == 3
    assert only_alert(client)["alert_id"] == identifier

def test_search_failure_keeps_all_checkpoints_and_outbox_unchanged(tmp_path):
    evaluator = ReplayEvaluator(events())
    evaluator.failure = ElasticError("Search was incomplete: failed shard")
    runner, client, _ = make_runner(tmp_path, evaluator=evaluator)
    with pytest.raises(ElasticError, match="incomplete"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["pending_outbox"] == 0
    assert client.documents == {}

def test_second_rule_failure_cannot_commit_first_rule(tmp_path):
    evaluator = ReplayEvaluator(events())
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ElasticError("second rule unavailable")
        return evaluator(*args, **kwargs)

    runner, client, _ = make_runner(tmp_path, evaluator=fail_second)
    with pytest.raises(ElasticError):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["logical_alerts"] == 0

@pytest.mark.parametrize("stage,committed,remote_count", [("before_commit", False, 0), ("after_commit", True, 0), ("after_delivery", True, 1)])
def test_crash_boundaries_recover_without_duplicate_alerts(tmp_path, stage, committed, remote_count):
    def crash(current, context):
        if current == stage:
            raise RuntimeError("simulated process death")

    runner, client, evaluator = make_runner(tmp_path, fault_hook=crash)
    with pytest.raises(RuntimeError, match="process death"):
        runner.run_once()
    status = runner.status()
    assert set(status["checkpoints"].values()) == {"2026-01-01T00:10:00Z" if committed else INITIAL}
    assert status["pending_outbox"] == (1 if committed else 0)
    assert len(client.documents) == remote_count
    resumed, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, initial_start=None)
    resumed.run_once()
    assert resumed.status()["pending_outbox"] == 0
    assert only_alert(client)["metrics"] == {"fails": 10}
    assert only_alert(client)["revision"] == 1

def test_sink_outage_retains_committed_outbox_then_retries(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    client.write_failure = True
    with pytest.raises(RunnerError, match="durable outbox"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {"2026-01-01T00:10:00Z"}
    assert runner.status()["pending_outbox"] == 1
    client.write_failure = False
    resumed, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, initial_start=None)
    resumed.run_once()
    assert resumed.status()["pending_outbox"] == 0
    assert len(client.documents) == 1

def test_partial_sink_write_is_not_acknowledged(tmp_path):
    runner, client, _ = make_runner(tmp_path)
    client.partial_write = True
    with pytest.raises(RunnerError, match="delivery failed"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1
    client.partial_write = False
    runner.run_once()
    assert runner.status()["pending_outbox"] == 0
    assert len(client.documents) == 1

def test_timed_out_old_delivery_cannot_overwrite_new_revision(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    client.delay_next_write = True
    with pytest.raises(RunnerError, match="durable outbox"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1
    assert client.documents == {}
    runner.run_once()  # Retry of the exact revision-1 payload is acknowledged.
    assert only_alert(client)["revision"] == 1
    evaluator.events = events(11)
    runner.run_once()
    latest = deepcopy(only_alert(client))
    assert latest["revision"] == 2
    assert latest["metrics"] == {"fails": 11}
    with pytest.raises(ElasticHTTPError) as error:
        client.request(*client.delayed.pop())  # Original revision-1 request finally arrives.
    assert error.value.status == 409
    assert only_alert(client) == latest
    assert runner.status()["pending_outbox"] == 0

def test_crash_after_second_delivery_preserves_only_unacknowledged_item(tmp_path):
    batch = events() + [{**item, "event.id": "bob-" + item["event.id"]} for item in events(user="bob")]
    count = 0

    def crash_after_second(stage, context):
        nonlocal count
        if stage == "after_delivery":
            count += 1
            if count == 2:
                raise RuntimeError("second delivery crash")

    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator(batch), fault_hook=crash_after_second)
    with pytest.raises(RuntimeError, match="second delivery"):
        runner.run_once()
    assert len(client.documents) == 2
    assert runner.status()["pending_outbox"] == 1
    resumed, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, initial_start=None)
    assert resumed.run_once()["outbox_delivered"] == 1
    assert resumed.status()["pending_outbox"] == 0
    assert len(client.documents) == 2

def test_sink_replacement_during_write_withholds_acknowledgement(tmp_path):
    client = MemoryElastic()
    request = client.request

    def replace_during_write(method, path, body=None):
        response = request(method, path, body)
        if "/_doc/" in path:
            client.uuids["auth-alerts"] = "recreated-during-write"
        return response

    client.request = replace_during_write
    runner, _, _ = make_runner(tmp_path, client=client)
    with pytest.raises(RunnerError, match="durable outbox"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1
    with pytest.raises(RunnerError, match="scope mismatch"):
        runner.run_once()

@pytest.mark.parametrize("index", ["auth-source", "auth-alerts"])
def test_recreated_index_rejects_state_reuse(tmp_path, index):
    runner, client, _ = make_runner(tmp_path)
    runner.run_once()
    previous = runner.status()
    client.uuids[index] += "-recreated"
    with pytest.raises(RunnerError, match="scope mismatch"):
        runner.run_once()
    assert runner.status() == previous

def test_source_replaced_during_evaluation_prevents_commit(tmp_path):
    evaluator = ReplayEvaluator(events())
    # Use one rule so the explicit final UUID guard is exercised.
    evaluator.after_evaluate = lambda client: client.uuids.update({"auth-source": "replacement"})
    runner, client, _ = make_runner(tmp_path, evaluator=evaluator, rule_paths=[DEFAULT_RULES[0]])
    with pytest.raises(RunnerError, match="changed before checkpoint"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert client.documents == {}

def test_source_replacement_immediately_before_commit_rolls_back(tmp_path):
    client = MemoryElastic()

    def replace_source(stage, context):
        if stage == "before_commit":
            client.uuids["auth-source"] = "replacement"

    runner, _, _ = make_runner(tmp_path, client=client, fault_hook=replace_source)
    with pytest.raises(RunnerError, match="changed before checkpoint"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["logical_alerts"] == 0
    assert runner.status()["pending_outbox"] == 0

def test_rule_semantics_reject_reuse_but_notes_and_path_do_not(tmp_path):
    first_rule = tmp_path / "copy.yaml"
    rule = yaml.safe_load(DEFAULT_RULES[0].read_text())
    first_rule.write_text(yaml.safe_dump(rule))
    runner, client, evaluator = make_runner(tmp_path, rule_paths=[first_rule])
    runner.run_once()
    renamed = tmp_path / "renamed.yaml"
    rule["notes"] = "Editorial-only change"
    renamed.write_text(yaml.safe_dump(rule))
    moved, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, rule_paths=[renamed])
    assert moved.run_once()["alerts"]["unchanged"] == 1
    rule["having"][0]["value"] = 11
    renamed.write_text(yaml.safe_dump(rule))
    with pytest.raises(RunnerError, match="semantics changed"):
        moved.run_once()
    new_runner, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, rule_paths=[renamed])
    with pytest.raises(RunnerError, match="scope mismatch"):
        new_runner.run_once()

def test_scheduling_configuration_cannot_silently_change(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    runner.run_once()
    changed, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, lookback=timedelta(hours=2))
    with pytest.raises(RunnerError, match="scope mismatch"):
        changed.run_once()

def test_future_start_is_a_no_op_until_closed_history_exists(tmp_path):
    runner, client, evaluator = make_runner(tmp_path, initial_start="2026-01-01T01:00:00Z")
    result = runner.run_once()
    assert result["ranges"] == []
    assert evaluator.calls == []
    assert set(result["checkpoints"].values()) == {"2026-01-01T01:00:00Z"}
    assert client.documents == {}

def test_clock_backwards_cannot_advance_or_deliver(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    runner.run_once()
    previous = runner.status()
    earlier, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, now="2026-01-01T00:11:59Z")
    with pytest.raises(RunnerError, match="Clock moved backwards"):
        earlier.run_once()
    assert earlier.status() == previous

def test_single_process_lock_is_released_after_failure(tmp_path):
    runner, client, evaluator = make_runner(tmp_path)
    other, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator)
    with runner._state():
        with pytest.raises(RunnerBusy):
            other.run_once()
    other.run_once()
    assert other.status()["logical_alerts"] == 1

def test_corrupt_database_is_preserved_and_fails(tmp_path):
    state = tmp_path / "state.sqlite"
    state.write_bytes(b"this is not a SQLite database")
    runner, client, _ = make_runner(tmp_path)
    with pytest.raises(RunnerError, match="SQLite state operation"):
        runner.run_once()
    assert state.read_bytes() == b"this is not a SQLite database"
    assert client.calls == []

def test_unknown_existing_schema_is_not_reused(tmp_path):
    state = tmp_path / "state.sqlite"
    with sqlite3.connect(state) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
    runner, client, _ = make_runner(tmp_path)
    with pytest.raises(RunnerError, match="Unknown SQLite state"):
        runner.run_once()
    with sqlite3.connect(state) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("unrelated",)]

def test_sink_creation_requires_opt_in_and_never_overwrites_profile(tmp_path):
    runner, client, _ = make_runner(tmp_path, initialize_alerts=False)
    with pytest.raises(ElasticHTTPError):
        runner.run_once()
    assert not any(method == "PUT" for method, _, _ in client.calls)
    create_alert_index(client, "auth-alerts")
    runner.run_once()
    client.mappings["auth-alerts"]["_meta"]["profile"] = "unrelated"
    with pytest.raises(RunnerError, match="dedicated alerts-v2"):
        runner.run_once()

def test_zero_lookback_with_no_new_closed_window_does_not_query_again(tmp_path):
    runner, _, evaluator = make_runner(tmp_path, lookback=timedelta(0))
    runner.run_once()
    calls = len(evaluator.calls)
    result = runner.run_once()
    assert len(evaluator.calls) == calls
    assert result["ranges"] == []

def test_no_credentials_or_client_urls_are_saved(tmp_path):
    runner, client, _ = make_runner(tmp_path)
    client.headers = {"Authorization": "ApiKey sensitive-test-value"}
    client.url = "https://example.test/secret-like-path"
    runner.run_once()
    with sqlite3.connect(runner.state_path) as connection:
        dump = "\n".join(connection.iterdump())
    assert "sensitive-test-value" not in dump
    assert "secret-like-path" not in dump


def test_arbitrary_microsecond_start_context_and_half_open_cutoff(tmp_path):
    start = "2026-01-01T00:05:00.123456Z"
    at = "2026-01-01T00:05:00.123457Z"
    batch = events(9, at="2026-01-01T00:00:00.123457Z")
    batch += [{**events(1, at=start)[0], "event.id": "anchor"}]
    batch += [{**events(1, at=at)[0], "event.id": "exclusive-end"}]
    runner, client, _ = make_runner(tmp_path, evaluator=ReplayEvaluator(batch), initial_start=start,
                                  now=at, allowed_lateness=timedelta(0))
    result = runner.run_once()
    assert result["alerts"]["created"] == 1
    assert only_alert(client)["window"] == {"start": "2026-01-01T00:00:00.123456Z", "end": start}
    assert only_alert(client)["metrics"] == {"fails": 10}
    assert set(result["checkpoints"].values()) == {at}
    with sqlite3.connect(runner.state_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert {row[0] % 1_000_000 for row in db.execute("SELECT watermark FROM checkpoints")} == {123457}


def test_adjacent_microsecond_anchors_have_distinct_stable_ids(tmp_path):
    batch = events(10, at="2026-01-01T00:01:00.000001Z")
    batch += [{**events(1, at="2026-01-01T00:01:00.000002Z")[0], "event.id": "later"}]
    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator(batch))
    result = runner.run_once()
    assert result["alerts"]["created"] == 2
    assert len(client.documents) == 2
    previous = deepcopy(client.documents)
    assert {v["metrics"]["fails"] for v in previous.values()} == {10, 11}
    resumed, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator,
                                page_size=1, max_events=20, max_alerts=3, max_forward_span=timedelta(seconds=1))
    assert resumed.run_once()["alerts"]["unchanged"] == 2
    assert client.documents == previous


def test_forward_chunks_progress_even_when_lookback_exceeds_span(tmp_path):
    runner, _, _ = make_runner(tmp_path, evaluator=ReplayEvaluator([]),
                                max_forward_span=timedelta(minutes=1), lookback=timedelta(hours=1))
    for minute in range(1, 11):
        result = runner.run_once()
        assert set(result["checkpoints"].values()) == {f"2026-01-01T00:{minute:02}:00Z"}
        assert {r["start"] for r in result["ranges"]} == {INITIAL}
        assert result["caught_up"] is (minute == 10)


def test_late_context_before_replayed_anchors_can_cross_threshold(tmp_path):
    # C=00:10, lookback=5min => replay anchors >=00:05, including history
    # after00:00. A latecontext event at00:01 modifies the existing00:05anchor.
    batch = events(8, at="2026-01-01T00:01:00Z")
    batch += [{**events(1, at="2026-01-01T00:05:00Z")[0], "event.id": "anchor"}]
    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator(batch), lookback=timedelta(minutes=5))
    runner.run_once()
    assert not client.documents
    evaluator.events.append({**events(1, at="2026-01-01T00:01:00Z")[0], "event.id": "late-context"})
    result = runner.run_once()
    assert result["alerts"]["created"] == 1
    assert only_alert(client)["window"]["end"] == "2026-01-01T00:05:00Z"
    assert {r["start"] for r in result["ranges"]} == {"2026-01-01T00:05:00Z"}


def test_retraction_uses_inclusive_anchor_start_not_window_start(tmp_path):
    batch = events(10, at="2026-01-01T00:05:00Z")
    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator(batch), lookback=timedelta(minutes=5))
    runner.run_once()
    identifier = only_alert(client)["alert_id"]
    evaluator.events = batch[:9]
    result = runner.run_once()
    assert result["alerts"]["retracted"] == 1
    assert only_alert(client)["alert_id"] == identifier
    assert only_alert(client)["status"] == "retracted"
    evaluator.events = batch
    runner.run_once()
    assert only_alert(client)["revision"] == 3
    assert only_alert(client)["status"] == "active"


def test_retractions_do_not_touch_old_anchors_outside_replay(tmp_path):
    runner, client, evaluator = make_runner(tmp_path, lookback=timedelta(minutes=5))
    runner.run_once()
    previous = deepcopy(only_alert(client))
    evaluator.events = []
    assert runner.run_once()["alerts"]["retracted"] == 0
    assert only_alert(client) == previous


def test_total_alert_cap_across_rules_rolls_back_all_rules(tmp_path):
    batch = events(10)  # Brute alert foralice.
    batch += [{**events(1, user=f"user-{i}")[0], "event.id": f"spray-{i}"} for i in range(14)]
    runner, client, _ = make_runner(tmp_path, evaluator=ReplayEvaluator(batch), max_alerts=1)
    with pytest.raises(RunnerError, match="max_alerts exceeded across"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["logical_alerts"] == 0
    assert client.documents == {}


def test_retraction_cap_rolls_back_prior_updates_and_checkpoint(tmp_path):
    batch = events(10) + [{**e, "event.id": "bob-" + e["event.id"]} for e in events(user="bob")]
    runner, client, evaluator = make_runner(tmp_path, evaluator=ReplayEvaluator(batch))
    runner.run_once()
    previous = deepcopy(client.documents)
    state_before = runner.status()
    evaluator.events = []
    limited, _, _ = make_runner(tmp_path, client=client, evaluator=evaluator, max_alerts=1,
                                now="2026-01-01T00:13:00Z")
    with pytest.raises(RunnerError, match="candidates and retractions"):
        limited.run_once()
    assert limited.status() == state_before
    assert client.documents == previous
    with sqlite3.connect(runner.state_path) as db:
        assert {json.loads(row[0])["status"] for row in db.execute("SELECT payload FROM alerts")} == {"active"}


def test_event_cap_fails_without_advancing_checkpoint(tmp_path):
    runner, client, _ = make_runner(tmp_path, max_events=9)
    with pytest.raises(ValueError, match="max_events"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert not client.documents


def test_sink_known_replaced_after_commit_is_not_written(tmp_path):
    client = MemoryElastic()
    def replace(stage, _context):
        if stage == "after_commit":
            client.uuids["auth-alerts"] = "new-sink"
    runner, _, _ = make_runner(tmp_path, client=client, fault_hook=replace)
    with pytest.raises(RunnerError, match="durable outbox"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1
    assert client.documents == {}
    assert not any("/_doc/" in path for _, path, _ in client.calls)


def test_sink_replaced_before_commit_rolls_back(tmp_path):
    client = MemoryElastic()
    def replace(stage, _context):
        if stage == "before_commit":
            client.uuids["auth-alerts"] = "new-sink"
    runner, _, _ = make_runner(tmp_path, client=client, fault_hook=replace)
    with pytest.raises(RunnerError, match="Alerts index changed before checkpoint"):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["logical_alerts"] == 0


def test_missing_bound_sink_is_never_recreated(tmp_path):
    runner, client, _ = make_runner(tmp_path)
    runner.run_once()
    del client.mappings["auth-alerts"]
    client.calls.clear()
    with pytest.raises(ElasticHTTPError):
        runner.run_once()
    assert not any(method == "PUT" for method, _, _ in client.calls)


def test_v1_database_rejected_without_migration_or_network(tmp_path):
    from tools.detection_runner import DetectionRunner
    v1 = DetectionRunner(source_client=MemoryElastic(), source_index="auth-source", alerts_index="auth-alerts",
                         state_path=tmp_path / "state.sqlite", initial_start=INITIAL)
    with v1._state():
        pass
    before = v1.state_path.read_bytes()
    runner, client, _ = make_runner(tmp_path)
    with pytest.raises(RunnerError, match="schema/version"):
        runner.run_once()
    assert runner.state_path.read_bytes() == before
    assert client.calls == []


def test_first_run_requires_start_before_network(tmp_path):
    runner, client, _ = make_runner(tmp_path, initial_start=None)
    with pytest.raises(RunnerError, match="explicit initial_start"):
        runner.run_once()
    assert client.calls == []


@pytest.mark.parametrize("start", ["1970-01-01T00:09:59.999999Z", "1969-12-31T23:59:59Z", "2262-04-11T23:47:16.854776Z"])
def test_unrepresentable_initial_start_rejected_before_state(tmp_path, start):
    client = MemoryElastic()
    with pytest.raises(ValueError):
        make_runner(tmp_path, client=client, initial_start=start)
    assert client.calls == []
    assert not (tmp_path / "state.sqlite").exists()


def test_smallest_supported_start_preserves_epoch_window_start(tmp_path):
    at = "1970-01-01T00:05:00Z"
    runner, client, _ = make_runner(tmp_path, evaluator=ReplayEvaluator(events(at=at)), initial_start=at,
                                   now="1970-01-01T00:05:00.000001Z", allowed_lateness=timedelta(0),
                                   rule_paths=[DEFAULT_RULES[0]])
    runner.run_once()
    assert only_alert(client)["window"]["start"] == "1970-01-01T00:00:00Z"


@pytest.mark.parametrize("kwargs", [
    {"max_forward_span": timedelta(0)}, {"max_forward_span": timedelta(seconds=-1)},
    {"lookback": timedelta(microseconds=-1)}, {"allowed_lateness": timedelta(microseconds=-1)},
    {"page_size": True}, {"page_size": 10001}, {"max_events": 0}, {"max_alerts": 1.5},
])
def test_invalid_limits_rejected_before_state_or_network(tmp_path, kwargs):
    client = MemoryElastic()
    with pytest.raises(RunnerError):
        make_runner(tmp_path, client=client, **kwargs)
    assert client.calls == []
    assert not (tmp_path / "state.sqlite").exists()


def test_microsecond_span_and_lateness_are_exact(tmp_path):
    runner, _, _ = make_runner(tmp_path, evaluator=ReplayEvaluator([]),
                                initial_start="2026-01-01T00:00:00.000001Z",
                                now="2026-01-01T00:00:00.000004Z",
                                allowed_lateness=timedelta(microseconds=1), max_forward_span=timedelta(microseconds=1))
    assert set(runner.run_once()["checkpoints"].values()) == {"2026-01-01T00:00:00.000002Z"}
    result = runner.run_once()
    assert set(result["checkpoints"].values()) == {"2026-01-01T00:00:00.000003Z"}
    assert result["caught_up"] is True


@pytest.mark.parametrize("mutate", [
    lambda alert: alert.update({"window.end": "2026-01-01T00:10:00Z", "window.start": "2026-01-01T00:05:00Z"}),
    lambda alert: alert.update({"window.start": "2025-12-31T23:55:00Z"}),
    lambda alert: alert.update({"fails": True}),
    lambda alert: alert.update({"fails": 9}),
    lambda alert: alert.update({"target.user": ["alice"]}),
    lambda alert: alert.update({"extra": "not projected"}),
])
def test_invalid_candidates_fail_whole_transaction(tmp_path, mutate):
    candidate = {"window.start": "2025-12-31T23:56:00Z", "window.end": "2026-01-01T00:01:00Z",
                 "source.ip": "192.0.2.1", "target.user": "alice", "fails": 10}
    mutate(candidate)
    runner, client, _ = make_runner(tmp_path, evaluator=lambda *a, **k: {"alerts": [candidate]},
                                    rule_paths=[DEFAULT_RULES[0]])
    with pytest.raises(RunnerError):
        runner.run_once()
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}
    assert runner.status()["logical_alerts"] == 0
    assert not client.documents


def test_duplicate_candidate_rolls_back(tmp_path):
    replay = ReplayEvaluator(events())
    def duplicate(*args, **kwargs):
        result = replay(*args, **kwargs)
        result["alerts"] *= 2
        return result
    runner, _, _ = make_runner(tmp_path, evaluator=duplicate, rule_paths=[DEFAULT_RULES[0]])
    with pytest.raises(RunnerError, match="duplicate logical alerts"):
        runner.run_once()
    assert runner.status()["logical_alerts"] == 0
    assert set(runner.status()["checkpoints"].values()) == {INITIAL}


def test_empty_v1_version_stamp_is_rejected(tmp_path):
    state = tmp_path / "state.sqlite"
    with sqlite3.connect(state) as db:
        db.execute("PRAGMA user_version=1")
    runner, client, _ = make_runner(tmp_path)
    with pytest.raises(RunnerError, match="schema/version"):
        runner.run_once()
    assert not client.calls


def test_clock_upper_bound_and_large_duration_do_not_overflow(tmp_path):
    runner, _, _ = make_runner(tmp_path, evaluator=ReplayEvaluator([]),
                                initial_start="2262-04-11T23:47:16.854774Z",
                                now="2262-04-11T23:47:16.854775Z", allowed_lateness=timedelta(0),
                                max_forward_span=timedelta(days=999999999))
    result = runner.run_once()
    assert result["caught_up"] is True
    assert set(result["checkpoints"].values()) == {"2262-04-11T23:47:16.854775Z"}
