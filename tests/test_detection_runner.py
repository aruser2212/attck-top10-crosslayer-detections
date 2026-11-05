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

from tools.detection_runner import (
    DEFAULT_RULES, DetectionRunner, MAPPING_PATH, RunnerBusy, RunnerError,
    create_alert_index,
)
from tools.elastic_adapter import ElasticError, ElasticHTTPError
from tools.hunt_engine import evaluate_hunt, parse_timestamp

ROOT = Path(__file__).resolve().parents[1]
INITIAL = "2026-01-01T00:00:00Z"


class MemoryElastic:
    def __init__(self):
        self.uuids = {"auth-source": "source-uuid"}
        self.mappings = {}
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

    def __call__(self, client, index, rule, *, start, end, expected_index_uuid):
        assert client.uuids[index] == expected_index_uuid
        self.calls.append({"start": start, "end": end, "rule": deepcopy(rule)})
        if self.failure:
            raise self.failure
        events = [event for event in self.events if parse_timestamp(start) <= parse_timestamp(event["@timestamp"]) < parse_timestamp(end)]
        result = evaluate_hunt(rule, events)
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
    return DetectionRunner(**config), client, evaluator


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


def test_first_run_requires_explicit_aligned_start(tmp_path):
    runner, client, _ = make_runner(tmp_path, initial_start=None)
    with pytest.raises(RunnerError, match="explicit initial_start"):
        runner.run_once()
    assert client.calls == []
    runner, _, _ = make_runner(tmp_path, initial_start="2026-01-01T00:01:00Z")
    with pytest.raises(RunnerError, match="align"):
        runner.run_once()


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
    with pytest.raises(RunnerError, match="dedicated alerts-v1"):
        runner.run_once()


def test_watch_stops_gracefully_and_retry_does_not_busy_loop(tmp_path):
    runner, _, evaluator = make_runner(tmp_path)
    stop = Event()
    results = []

    def complete(result):
        results.append(result)
        stop.set()

    runner.watch(interval=60, stop_event=stop, on_result=complete)
    assert len(results) == 1
    stop = Event()
    evaluator.failure = ElasticError("unavailable")
    errors = []

    def failed(error):
        errors.append(error)
        stop.set()

    runner.watch(interval=60, stop_event=stop, on_error=failed)
    assert len(errors) == 1


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


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf"), True])
def test_watch_rejects_nonfinite_or_invalid_interval(tmp_path, interval):
    runner, _, _ = make_runner(tmp_path)
    with pytest.raises(RunnerError, match="interval"):
        runner.watch(interval=interval)
