"""Durable downstream episode projection with real SQLite and explicit faults."""
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest

from tools.detection_runner import canonical
from tools.elastic_adapter import ElasticError, ElasticHTTPError
from tools.elastic_rolling import MAPPING_PATH as RAW_MAPPING
from tools.episode_runner import EpisodeBusy, EpisodeError, EpisodeRunner, MAPPING_PATH, create_episode_index
from tools.hunt_engine import parse_timestamp
from tools.rolling_hunt import evaluate_hunt
from tools.rolling_runner import RollingDetectionRunner

ROOT = Path(__file__).resolve().parents[1]
RULE = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"


class MemoryElastic:
    def __init__(self):
        self.mappings = {"raw-source": json.loads(RAW_MAPPING.read_text())["mappings"]}
        self.uuids = {"raw-source": "source-uuid"}
        self.documents = {}
        self.calls = []
        self.failure = False
        self.bad_ack = None
        self.delay = False
        self.delayed = None
        self.count_response = None

    def request(self, method, path, body=None):
        self.calls.append((method, path, deepcopy(body)))
        index = path.split("/")[1]
        if path.endswith("/_mapping"):
            if index not in self.mappings:
                raise ElasticHTTPError(404, "missing index")
            return {index: {"mappings": deepcopy(self.mappings[index])}}
        if path.endswith("/_settings?flat_settings=true"):
            if index not in self.uuids:
                raise ElasticHTTPError(404, "missing index")
            return {index: {"settings": {"index.uuid": self.uuids[index]}}}
        if method == "POST" and path.endswith("/_refresh"):
            return {"_shards": {"total": 1, "successful": 1, "failed": 0}}
        if method == "GET" and path.endswith("/_count"):
            return self.count_response or {"count": len(self.documents.get(index, {})),
                                           "_shards": {"total": 1, "successful": 1, "failed": 0}}
        if method == "PUT" and "/_doc/" not in path:
            assert index not in self.mappings
            self.mappings[index] = deepcopy(body["mappings"])
            self.uuids[index] = index + "-uuid"
            return {"acknowledged": True}
        if method == "PUT" and "/_doc/" in path:
            if index == "episodes" and self.failure:
                raise ElasticHTTPError(503, "sink unavailable")
            if index == "episodes" and self.delay:
                self.delay = False
                self.delayed = method, path, deepcopy(body)
                raise ElasticError("request timed out")
            identifier = path.split("/_doc/")[1].split("?")[0]
            options = parse_qs(urlparse(path).query)
            assert options["version_type"] == ["external_gte"]
            assert int(options["version"][0]) == body["revision"]
            documents = self.documents.setdefault(index, {})
            previous = documents.get(identifier)
            if previous and previous["revision"] > body["revision"]:
                raise ElasticHTTPError(409, "stale revision")
            documents[identifier] = deepcopy(body)
            response = {"_id": identifier, "_index": index, "_version": body["revision"],
                        "result": "updated" if previous else "created", "_shards": {"failed": 0}}
            if index == "episodes" and self.bad_ack:
                response.update(self.bad_ack)
            return response
        raise AssertionError((method, path))


def events(at="2026-01-01T00:01:00Z", *, count=10, user="alice", prefix="event"):
    return [{"event.id": f"{prefix}-{at}-{user}-{number}", "event.dataset": "windows.security.logons",
             "event.code": "4625", "@timestamp": at, "target.user": user, "source.ip": "192.0.2.1"}
            for number in range(count)]


class Evaluator:
    def __init__(self, source):
        self.events = deepcopy(source)

    def __call__(self, _client, _index, rule, *, start, end, expected_index_uuid, page_size, max_events, max_alerts):
        return evaluate_hunt(rule, self.events, start=start, end=end, max_events=max_events, max_alerts=max_alerts)


def setup(tmp_path, *, source=None, raw_now="2026-01-01T00:02:00Z", **options):
    client = MemoryElastic()
    evaluator = Evaluator(events() if source is None else source)
    raw = RollingDetectionRunner(source_client=client, source_index="raw-source", alerts_index="raw-alerts",
                                 state_path=tmp_path / "raw.sqlite", rule_paths=[RULE],
                                 initial_start="2026-01-01T00:00:00Z", allowed_lateness=timedelta(),
                                 lookback=timedelta(hours=1), clock=lambda: parse_timestamp(raw_now),
                                 evaluator=evaluator, initialize_alerts=True)
    raw.run_once()
    arguments = dict(source_state=raw.state_path, state_path=tmp_path / "episodes.sqlite",
                     sink_client=client, episodes_index="episodes", gap=timedelta(minutes=1),
                     initialize_index=True, clock=lambda: parse_timestamp("2026-01-01T00:20:00Z"))
    arguments.update(options)
    return EpisodeRunner(**arguments), raw, evaluator, client


def only_episode(client):
    documents = client.documents.get("episodes", {})
    assert len(documents) == 1
    return next(iter(documents.values()))


def raw_payload(raw, mutate):
    with sqlite3.connect(raw.state_path) as db:
        row = db.execute("SELECT alert_id,payload FROM alerts LIMIT 1").fetchone()
        value = json.loads(row[1])
        mutate(value)
        db.execute("UPDATE alerts SET payload=? WHERE alert_id=?", (canonical(value), row[0]))


def test_create_restart_and_unchanged_pass_keep_identity_and_revision(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    result = runner.run_once()
    assert result["episodes"] == {"created": 1, "updated": 0, "retracted": 0, "unchanged": 0}
    assert only_episode(client)["anchor_count"] == 1
    assert only_episode(client)["status"] == "open"
    assert only_episode(client)["peak_metrics"] == {"fails": 10}
    initial = deepcopy(only_episode(client))
    runner.clock = lambda: parse_timestamp("2026-01-01T00:21:00Z")
    assert runner.run_once()["episodes"]["unchanged"] == 1
    assert only_episode(client) == initial
    assert runner.status()["pending_outbox"] == 0
    assert raw.status()["logical_alerts"] == 1
    with sqlite3.connect(runner.state_path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_peak_metrics_do_not_sum_overlapping_windows_and_append_keeps_id(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    runner.run_once()
    first = deepcopy(only_episode(client))
    evaluator.events += events("2026-01-01T00:01:30Z", count=1, prefix="late")
    raw.run_once()
    assert runner.run_once()["episodes"]["updated"] == 1
    current = only_episode(client)
    assert current["episode_id"] == first["episode_id"]
    assert current["anchor_count"] == 2 and current["peak_metrics"] == {"fails": 11}
    assert current["revision"] == 2
    assert current["first_detected_at"] == first["first_detected_at"]


def test_checkpoint_equality_stays_open_then_one_microsecond_closes(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    runner.run_once()
    assert only_episode(client)["status"] == "open"
    raw.clock = lambda: parse_timestamp("2026-01-01T00:02:00.000001Z")
    raw.run_once()
    runner.run_once()
    assert only_episode(client)["status"] == "closed" and only_episode(client)["revision"] == 2
    raw.clock = lambda: parse_timestamp("2026-01-01T00:03:00Z")
    raw.run_once()
    assert runner.run_once()["episodes"]["unchanged"] == 1


def test_late_bridge_merges_then_retraction_splits_and_reactivates_id(tmp_path):
    source = events("2026-01-01T00:01:00Z") + events("2026-01-01T00:03:00Z")
    runner, raw, evaluator, client = setup(tmp_path, source=source, raw_now="2026-01-01T00:04:00Z")
    runner.run_once()
    original = deepcopy(client.documents["episodes"])
    assert len(original) == 2
    evaluator.events += events("2026-01-01T00:02:00Z", count=1, prefix="bridge")
    raw.run_once()
    result = runner.run_once()
    assert result["episodes"]["updated"] == 1 and result["episodes"]["retracted"] == 1
    active = [p for p in client.documents["episodes"].values() if p["status"] != "retracted"]
    retired = [p for p in client.documents["episodes"].values() if p["status"] == "retracted"]
    assert len(active) == len(retired) == 1
    assert active[0]["anchor_count"] == 3
    assert retired[0]["replacement_episode_ids"] == [active[0]["episode_id"]]
    evaluator.events = source
    raw.run_once()
    runner.run_once()
    assert set(client.documents["episodes"]) == set(original)
    assert all(p["status"] != "retracted" and p["replacement_episode_ids"] == []
               for p in client.documents["episodes"].values())


def test_earlier_anchor_rekeys_and_retains_explicit_replacement(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    runner.run_once()
    old_id = only_episode(client)["episode_id"]
    evaluator.events += events("2026-01-01T00:00:30Z", prefix="earlier")
    raw.run_once()
    runner.run_once()
    old = client.documents["episodes"][old_id]
    assert old["status"] == "retracted" and len(old["replacement_episode_ids"]) == 1
    successor = client.documents["episodes"][old["replacement_episode_ids"][0]]
    assert successor["first_anchor"] == "2026-01-01T00:00:30Z" and successor["anchor_count"] == 2


@pytest.mark.parametrize("stage,committed,remote", [("before_commit", False, 0), ("after_commit", True, 0), ("after_delivery", True, 1)])
def test_crash_boundary_recovers_same_revision(tmp_path, stage, committed, remote):
    runner, _, _, client = setup(tmp_path)
    def fault(at, _context):
        if at == stage:
            raise RuntimeError("simulated crash")
    runner.fault_hook = fault
    with pytest.raises(RuntimeError, match="simulated crash"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == int(committed)
    assert runner.status()["observed_source_alerts"] == int(committed)
    assert len(client.documents.get("episodes", {})) == remote
    runner.fault_hook = lambda *_: None
    runner.run_once()
    assert only_episode(client)["revision"] == 1
    assert runner.status()["pending_outbox"] == 0


def test_raw_pending_outbox_blocks_new_projection_until_delivery_recovers(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    runner.run_once()
    previous = runner.status()
    evaluator.events += events("2026-01-01T00:01:30Z", count=1, prefix="new")
    raw.fault_hook = lambda stage, _: (_ for _ in ()).throw(RuntimeError("crash")) if stage == "after_commit" else None
    with pytest.raises(RuntimeError):
        raw.run_once()
    result = runner.run_once()
    assert result["ok"] is False and result["status"] == "waiting_for_raw_delivery"
    assert runner.status() == previous and only_episode(client)["revision"] == 1
    raw.fault_hook = lambda *_: None
    raw.run_once()
    runner.run_once()
    assert only_episode(client)["anchor_count"] == 2


def test_sink_outage_keeps_committed_projection_and_retries(tmp_path):
    runner, _, _, client = setup(tmp_path)
    client.failure = True
    with pytest.raises(EpisodeError, match="outbox"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1 and runner.status()["observed_source_alerts"] == 1
    client.failure = False
    runner.run_once()
    assert only_episode(client)["revision"] == 1 and runner.status()["pending_outbox"] == 0


@pytest.mark.parametrize("bad_ack", [{"_version": True}, {"_version": 99}, {"_shards": {}}, {"_shards": {"failed": 1}}, {"_id": "wrong"}])
def test_incomplete_delivery_acknowledgements_remain_pending(tmp_path, bad_ack):
    runner, _, _, client = setup(tmp_path)
    client.bad_ack = bad_ack
    with pytest.raises(EpisodeError, match="outbox"):
        runner.run_once()
    assert runner.status()["pending_outbox"] == 1
    client.bad_ack = None
    runner.run_once()
    assert runner.status()["pending_outbox"] == 0


def test_timed_out_old_external_version_cannot_overwrite_new_episode(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    client.delay = True
    with pytest.raises(EpisodeError):
        runner.run_once()
    assert client.delayed
    runner.run_once()
    evaluator.events += events("2026-01-01T00:01:30Z", count=1, prefix="new")
    raw.run_once()
    runner.run_once()
    with pytest.raises(ElasticHTTPError) as error:
        client.request(*client.delayed)
    assert error.value.status == 409 and only_episode(client)["revision"] == 2


def test_all_episode_changes_and_source_manifest_rollback_at_change_cap(tmp_path):
    runner, raw, evaluator, client = setup(tmp_path)
    runner.run_once()
    previous = runner.status()
    original = deepcopy(client.documents["episodes"])
    evaluator.events += events("2026-01-01T00:00:30Z", prefix="earlier")
    raw.run_once()
    runner.max_changes = 1  # One new identity plus one old retraction require two changes.
    with pytest.raises(EpisodeError, match="max_changes"):
        runner.run_once()
    assert runner.status() == previous and client.documents["episodes"] == original
    runner.max_changes = 2
    runner.run_once()
    assert len(client.documents["episodes"]) == 2


@pytest.mark.parametrize("limit,value", [("max_source_alerts", 1), ("max_source_bytes", 1), ("max_episodes", 1), ("max_members", 1)])
def test_complete_pass_limits_do_not_commit_source_manifest(tmp_path, limit, value):
    source = events("2026-01-01T00:01:00Z") + events("2026-01-01T00:01:30Z") + events("2026-01-01T00:04:00Z")
    runner, _, _, client = setup(tmp_path, source=source, raw_now="2026-01-01T00:05:00Z")
    setattr(runner, limit, value)
    with pytest.raises(ValueError):
        runner.run_once()
    assert runner.status().get("observed_source_alerts", 0) == 0
    assert client.documents.get("episodes", {}) == {}


def test_missing_previously_observed_raw_row_is_not_a_retraction(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    runner.run_once()
    previous = runner.status()
    with sqlite3.connect(raw.state_path) as db:
        db.execute("DELETE FROM alerts")
    with pytest.raises(EpisodeError, match="lost a previously observed"):
        runner.run_once()
    assert runner.status() == previous and only_episode(client)["status"] == "open"


def test_raw_same_revision_payload_change_is_rejected(tmp_path):
    runner, raw, _, _ = setup(tmp_path)
    runner.run_once()
    raw_payload(raw, lambda value: value["metrics"].update(fails=11))
    with pytest.raises(EpisodeError, match="without a new revision"):
        runner.run_once()


def test_raw_revision_regression_is_rejected(tmp_path):
    runner, raw, evaluator, _ = setup(tmp_path)
    runner.run_once()
    evaluator.events += events(count=1, prefix="late")
    raw.run_once()
    runner.run_once()
    raw_payload(raw, lambda value: value.update(revision=1))
    with pytest.raises(EpisodeError, match="revision regressed"):
        runner.run_once()


def test_raw_checkpoint_regression_is_rejected(tmp_path):
    runner, raw, _, _ = setup(tmp_path, raw_now="2026-01-01T00:04:00Z")
    runner.run_once()
    with sqlite3.connect(raw.state_path) as db:
        db.execute("UPDATE checkpoints SET watermark=watermark-1000000")
    with pytest.raises(EpisodeError, match="checkpoint or clock regressed"):
        runner.run_once()


def replace_database(path):
    replacement = path.with_name("replacement.sqlite")
    with sqlite3.connect(path) as source, sqlite3.connect(replacement) as dest:
        source.backup(dest)
    os.replace(replacement, path)


def test_replaced_source_inode_fails_even_with_identical_content(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    runner.run_once()
    replace_database(raw.state_path)
    writes = len(client.calls)
    with pytest.raises(EpisodeError, match="scope changed"):
        runner.run_once()
    assert len(client.calls) == writes


def test_source_replaced_before_commit_rolls_back(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    runner.fault_hook = lambda stage, _: replace_database(raw.state_path) if stage == "before_commit" else None
    with pytest.raises(EpisodeError):
        runner.run_once()
    assert runner.status()["episodes"] == 0 and client.documents.get("episodes", {}) == {}


@pytest.mark.parametrize("stage,committed", [("before_commit", False), ("after_commit", True)])
def test_sink_replaced_during_pass_withholds_commit_or_delivery(tmp_path, stage, committed):
    runner, _, _, client = setup(tmp_path)
    runner.fault_hook = lambda at, _: client.uuids.update(episodes="replacement") if at == stage else None
    with pytest.raises(EpisodeError):
        runner.run_once()
    assert runner.status()["pending_outbox"] == int(committed)
    assert client.documents.get("episodes", {}) == {}


def test_missing_bound_sink_is_never_recreated(tmp_path):
    runner, _, _, client = setup(tmp_path)
    runner.run_once()
    del client.mappings["episodes"]
    del client.uuids["episodes"]
    with pytest.raises(ElasticHTTPError) as error:
        runner.run_once()
    assert error.value.status == 404 and "episodes" not in client.mappings


def test_fresh_state_cannot_adopt_populated_sink_or_overwrite_equal_revision(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    runner.run_once()
    original = deepcopy(only_episode(client))
    reset = EpisodeRunner(source_state=raw.state_path, state_path=tmp_path / "reset.sqlite",
                          sink_client=client, episodes_index="episodes", initialize_index=True,
                          gap=timedelta(minutes=1), clock=lambda: parse_timestamp("2026-01-01T00:30:00Z"))
    with pytest.raises(EpisodeError, match="empty dedicated sink"):
        reset.run_once()
    assert reset.status()["initialized"] is False and only_episode(client) == original
    assert runner.run_once()["ok"]


@pytest.mark.parametrize("response", [
    {"count": 0},
    {"count": False, "_shards": {"total": 1, "successful": 1, "failed": 0}},
    {"count": 0, "_shards": {"total": 1, "successful": 0, "failed": 1}},
    {"count": 0, "timed_out": True, "_shards": {"total": 1, "successful": 1, "failed": 0}},
])
def test_incomplete_first_sink_count_cannot_bind_state(tmp_path, response):
    runner, _, _, client = setup(tmp_path)
    client.count_response = response
    with pytest.raises(EpisodeError, match="count was incomplete"):
        runner.run_once()
    assert runner.status()["initialized"] is False and client.documents.get("episodes", {}) == {}


def test_gap_change_requires_new_state_but_limits_do_not(tmp_path):
    runner, _, _, _ = setup(tmp_path)
    runner.run_once()
    runner.max_changes = 1
    runner.run_once()
    runner.gap_us += 1
    with pytest.raises(EpisodeError, match="scope changed"):
        runner.run_once()


def test_episode_clock_backwards_blocks_pending_delivery(tmp_path):
    runner, _, _, client = setup(tmp_path)
    runner.fault_hook = lambda stage, _: (_ for _ in ()).throw(RuntimeError("crash")) if stage == "after_commit" else None
    with pytest.raises(RuntimeError):
        runner.run_once()
    runner.fault_hook = lambda *_: None
    runner.clock = lambda: parse_timestamp("2026-01-01T00:19:00Z")
    with pytest.raises(EpisodeError, match="clock moved backwards"):
        runner.run_once()
    assert client.documents.get("episodes", {}) == {}


def test_foreign_state_schema_is_preserved_without_network_mutation(tmp_path):
    runner, _, _, client = setup(tmp_path)
    with sqlite3.connect(runner.state_path) as db:
        db.execute("CREATE TABLE user_data (data TEXT)")
        db.execute("INSERT INTO user_data VALUES ('preserve')")
    before = runner.state_path.read_bytes()
    calls = len(client.calls)
    with pytest.raises(EpisodeError, match="Unknown episode state"):
        runner.run_once()
    assert runner.state_path.read_bytes() == before and len(client.calls) == calls


def test_state_exclusive_lock_released_after_failure(tmp_path):
    runner, _, _, _ = setup(tmp_path)
    with runner._state():
        with pytest.raises(EpisodeBusy):
            runner.run_once()
    assert runner.run_once()["ok"]


def test_source_state_cannot_be_same_file_or_hardlink(tmp_path):
    runner, raw, _, client = setup(tmp_path)
    with pytest.raises(EpisodeError, match="different files"):
        EpisodeRunner(source_state=raw.state_path, state_path=raw.state_path, sink_client=client, episodes_index="episodes")
    os.link(raw.state_path, runner.state_path)
    with pytest.raises(EpisodeError, match="same inode"):
        runner.run_once()


@pytest.mark.parametrize("key,value", [("max_changes", 0), ("max_members", True), ("max_episodes", -1),
                                       ("max_source_bytes", 0), ("gap", timedelta()), ("initialize_index", 1)])
def test_invalid_configuration_does_not_create_state(tmp_path, key, value):
    with pytest.raises(ValueError):
        EpisodeRunner(source_state=tmp_path/"raw", state_path=tmp_path/"state", sink_client=None,
                      episodes_index="episodes", **{key: value})
    assert not (tmp_path/"state").exists()
