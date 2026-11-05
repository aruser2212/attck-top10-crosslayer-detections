"""Differential incremental/full projection through real rolling SQLite state."""
from copy import deepcopy
from datetime import timedelta
import random
import sqlite3

import pytest
import yaml

from tests.test_episode_runner import Evaluator, MemoryElastic, RULE, events, setup
from tools import episode_runner as implementation
from tools.episode_runner import EpisodeError, EpisodeRunner
from tools.hunt_engine import parse_timestamp
from tools.rolling_runner import RollingDetectionRunner


def pair(tmp_path, *, source=None, raw_now="2026-01-01T00:03:00Z", gap=timedelta(minutes=2)):
    incremental, raw, evaluator, client = setup(tmp_path, source=source, raw_now=raw_now, gap=gap)
    incremental.clock = lambda: parse_timestamp("2026-01-01T02:00:00Z")
    reference = EpisodeRunner(source_state=raw.state_path, state_path=tmp_path / "reference.sqlite",
                              sink_client=client, episodes_index="episodes-reference", gap=gap,
                              initialize_index=True, clock=incremental.clock, projection_mode="full")
    return incremental, reference, raw, evaluator, client


def compare(incremental, reference, client):
    actual, expected = incremental.run_once(), reference.run_once()
    assert actual["episodes"] == expected["episodes"]
    assert actual["source_checkpoints"] == expected["source_checkpoints"]
    assert actual["source_alerts"] == expected["source_alerts"]
    assert client.documents.get("episodes", {}) == client.documents.get("episodes-reference", {})
    for runner in (incremental, reference):
        assert runner.status()["pending_outbox"] == 0
    return actual


def persisted(path):
    with sqlite3.connect(path) as db:
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("episode_source_alerts", "episodes", "episode_outbox")}


def test_late_merge_split_rekey_reactivation_matches_full_projection(tmp_path):
    alice = events("2026-01-01T00:01:00Z")
    bob = events("2026-01-01T00:02:00Z", user="bob")
    incremental, reference, raw, source, client = pair(tmp_path, source=alice + bob)
    result = compare(incremental, reference, client)
    assert result["recomputation"] == {"mode": "incremental", "groups_total": 2,
                                       "groups_recomputed": 2, "source_alerts_recomputed": 2}
    assert compare(incremental, reference, client)["recomputation"]["groups_recomputed"] == 0

    # At C=03:00.000001 only alice's 01:00 anchor crosses the strict 2m gap.
    raw.clock = lambda: parse_timestamp("2026-01-01T00:03:00.000001Z")
    raw.run_once()
    assert compare(incremental, reference, client)["recomputation"]["groups_recomputed"] == 1
    source.events += events("2026-01-01T00:02:00Z", prefix="append")
    raw.run_once()
    assert compare(incremental, reference, client)["recomputation"]["groups_recomputed"] == 1

    source.events += events("2026-01-01T00:06:00Z", prefix="separate")
    raw.clock = lambda: parse_timestamp("2026-01-01T00:07:00Z")
    raw.run_once()
    compare(incremental, reference, client)
    before_merge = deepcopy(client.documents["episodes"])
    source.events += events("2026-01-01T00:04:00Z", prefix="bridge")
    raw.run_once()
    merged = compare(incremental, reference, client)
    assert merged["recomputation"]["groups_recomputed"] == 1
    assert merged["episodes"]["retracted"] == 1

    source.events = [event for event in source.events if not event["event.id"].startswith("bridge-")]
    raw.run_once()
    split = compare(incremental, reference, client)
    assert split["episodes"]["updated"] >= 2
    assert set(before_merge) <= set(client.documents["episodes"])
    source.events += events("2026-01-01T00:00:30Z", prefix="earliest")
    raw.run_once()
    rekeyed = compare(incremental, reference, client)
    assert rekeyed["episodes"]["created"] == 1 and rekeyed["episodes"]["retracted"] == 1
    saved = deepcopy(source.events)
    source.events = [event for event in source.events if event["target.user"] != "alice"]
    raw.run_once()
    compare(incremental, reference, client)
    source.events = saved
    raw.run_once()
    compare(incremental, reference, client)
    assert compare(incremental, reference, client)["recomputation"]["groups_recomputed"] == 0


@pytest.mark.parametrize("seed", [7, 23, 81, 193])
def test_deterministic_mutation_sequences_equal_full_oracle(tmp_path, seed):
    rng = random.Random(seed)
    batches = {key: events(f"2026-01-01T00:{minute:02d}:00Z", user=f"user-{user}", prefix=f"batch-{key}")
               for key, (user, minute) in enumerate((user, minute) for user in range(4)
                                                    for minute in (1, 3, 5, 9, 12))}
    active = {0, 5, 10, 15}
    incremental, reference, raw, source, client = pair(
        tmp_path, source=[event for key in sorted(active) for event in batches[key]],
        raw_now="2026-01-01T00:15:00Z")
    compare(incremental, reference, client)
    for _ in range(16):
        key = rng.randrange(len(batches))
        active.symmetric_difference_update({key})
        source.events = [event for key in sorted(active) for event in batches[key]]
        rng.shuffle(source.events)
        raw.run_once()
        compare(incremental, reference, client)


def test_only_changed_or_newly_closing_groups_reach_grouping_engine(tmp_path, monkeypatch):
    runner, raw, source, _ = setup(tmp_path, source=events() + events("2026-01-01T00:02:00Z", user="bob"),
                                   raw_now="2026-01-01T00:03:00Z", gap=timedelta(minutes=2))
    seen = []
    engine = implementation.group_episodes

    def observed(alerts, **kwargs):
        seen.append({alert["group"]["target.user"] for alert in alerts})
        return engine(alerts, **kwargs)

    monkeypatch.setattr(implementation, "group_episodes", observed)
    runner.run_once()
    assert seen == [{"alice", "bob"}]
    runner.run_once()
    assert seen == [{"alice", "bob"}]
    raw.clock = lambda: parse_timestamp("2026-01-01T00:03:00.000001Z")
    raw.run_once()
    runner.run_once()
    assert seen[-1] == {"alice"} and len(seen) == 2
    source.events += events("2026-01-01T00:02:30Z", user="bob", prefix="late")
    raw.run_once()
    runner.run_once()
    assert seen[-1] == {"bob"} and len(seen) == 3
    raw.clock = lambda: parse_timestamp("2026-01-01T00:06:00Z")
    raw.run_once()
    runner.run_once()
    assert seen[-1] == {"bob"} and len(seen) == 4
    raw.clock = lambda: parse_timestamp("2026-01-01T00:07:00Z")
    raw.run_once()
    runner.run_once()
    assert len(seen) == 4  # Closed unchanged groups do not need rebuilding.


def test_rule_identity_separates_dirty_groups_with_identical_group_values(tmp_path):
    rule = yaml.safe_load(RULE.read_text())
    rule["aggregate"]["group_by"] = ["source.ip"]
    rule["project"].remove("target.user")
    paths = []
    for user in ("alice", "bob"):
        selected = deepcopy(rule)
        selected["where"]["all"].append({"field": "target.user", "op": "eq", "value": user})
        path = tmp_path / f"{user}.hunt.yaml"
        path.write_text(yaml.safe_dump(selected))
        paths.append(path)
    client = MemoryElastic()
    source = Evaluator(events() + events("2026-01-01T00:02:00Z", user="bob"))
    raw = RollingDetectionRunner(source_client=client, source_index="raw-source", alerts_index="raw-alerts",
                                 state_path=tmp_path / "raw.sqlite", rule_paths=paths,
                                 initial_start="2026-01-01T00:00:00Z", allowed_lateness=timedelta(),
                                 lookback=timedelta(hours=1), clock=lambda: parse_timestamp("2026-01-01T00:03:00Z"),
                                 evaluator=source, initialize_alerts=True)
    raw.run_once()
    common = dict(source_state=raw.state_path, sink_client=client, initialize_index=True,
                  gap=timedelta(minutes=2), clock=lambda: parse_timestamp("2026-01-01T02:00:00Z"))
    incremental = EpisodeRunner(**common, state_path=tmp_path / "episodes.sqlite", episodes_index="episodes")
    reference = EpisodeRunner(**common, state_path=tmp_path / "reference.sqlite",
                              episodes_index="episodes-reference", projection_mode="full")
    assert compare(incremental, reference, client)["recomputation"]["groups_total"] == 2
    raw.clock = lambda: parse_timestamp("2026-01-01T00:03:00.000001Z")
    raw.run_once()
    result = compare(incremental, reference, client)
    assert result["recomputation"]["groups_recomputed"] == 1
    assert {doc["status"] for doc in client.documents["episodes"].values()} == {"open", "closed"}


@pytest.mark.parametrize("limit", ["max_members", "max_episodes"])
def test_lowered_limits_cover_unchanged_cached_projection(tmp_path, limit):
    runner, _, _, client = setup(tmp_path, source=events() + events("2026-01-01T00:01:30Z")
                                 + events(user="bob"), gap=timedelta(minutes=2))
    runner.run_once()
    before = persisted(runner.state_path), runner.status(), deepcopy(client.documents["episodes"])
    setattr(runner, limit, 1)
    with pytest.raises(EpisodeError, match=limit):
        runner.run_once()
    assert before == (persisted(runner.state_path), runner.status(), client.documents["episodes"])


def test_episode_limit_is_global_across_cached_and_dirty_groups(tmp_path):
    runner, raw, source, client = setup(tmp_path, source=events() + events(user="bob"), max_episodes=2)
    runner.run_once()
    before = persisted(runner.state_path), runner.status(), deepcopy(client.documents["episodes"])
    source.events += events(user="carol")
    raw.run_once()
    with pytest.raises(EpisodeError, match="max_episodes"):
        runner.run_once()
    assert before == (persisted(runner.state_path), runner.status(), client.documents["episodes"])


def test_lowered_member_limit_accepts_dirty_group_that_really_shrank(tmp_path):
    runner, raw, source, client = setup(tmp_path, source=events() + events("2026-01-01T00:01:20Z")
                                 + events("2026-01-01T00:01:40Z"), max_members=3)
    runner.run_once()
    source.events = [event for event in source.events if event["@timestamp"] != "2026-01-01T00:01:40Z"]
    raw.run_once()
    runner.max_members = 2
    assert runner.run_once()["ok"]
    assert [value["anchor_count"] for value in client.documents["episodes"].values()
            if value["status"] != "retracted"] == [2]


def test_pending_raw_delivery_does_not_consume_dirty_revision(tmp_path):
    runner, raw, source, _ = setup(tmp_path)
    runner.run_once()
    before = persisted(runner.state_path), runner.status()
    source.events += events("2026-01-01T00:01:30Z")
    raw.fault_hook = lambda stage, _: (_ for _ in ()).throw(RuntimeError("crash")) if stage == "after_commit" else None
    with pytest.raises(RuntimeError):
        raw.run_once()
    assert runner.run_once()["status"] == "waiting_for_raw_delivery"
    assert before == (persisted(runner.state_path), runner.status())
    raw.fault_hook = lambda *_: None
    raw.run_once()
    assert runner.run_once()["recomputation"]["groups_recomputed"] == 1


def test_existing_full_state_can_restart_incrementally_without_migration(tmp_path):
    runner, raw, _, client = setup(tmp_path, projection_mode="full")
    runner.run_once()
    before = deepcopy(client.documents["episodes"])
    restarted = EpisodeRunner(source_state=raw.state_path, state_path=runner.state_path,
                              sink_client=client, episodes_index="episodes", gap=runner.gap,
                              clock=runner.clock)
    result = restarted.run_once()
    assert result["recomputation"]["groups_recomputed"] == 0
    assert client.documents["episodes"] == before
    with sqlite3.connect(runner.state_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    restarted.projection_mode = "full"
    result = restarted.run_once()
    assert result["recomputation"]["groups_recomputed"] == 1
    assert client.documents["episodes"] == before


@pytest.mark.parametrize("mode", ["unknown", None, True, []])
def test_unknown_projection_mode_rejected_before_state_creation(tmp_path, mode):
    with pytest.raises(EpisodeError, match="projection_mode"):
        EpisodeRunner(source_state=tmp_path / "raw.sqlite", state_path=tmp_path / "episodes.sqlite",
                      sink_client=None, episodes_index="episodes", projection_mode=mode)
    assert not (tmp_path / "episodes.sqlite").exists()
