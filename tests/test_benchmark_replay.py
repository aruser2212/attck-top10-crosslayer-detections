"""Benchmark evidence must represent a complete, checked and repeatable replay."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools import benchmark_replay as bench


@pytest.mark.parametrize("profile,size,expected", [
    ("rolling-v2", 9, 0), ("rolling-v2", 10, 1), ("rolling-v2", 23, 14),
    ("lsass", 1, 1), ("lsass", 10, 1), ("lsass", 11, 2), ("lsass", 23, 3),
])
def test_small_measured_workloads_match_independent_counts(profile, size, expected):
    result = bench.run_worker(profile, size, 42)
    assert result["events"] == size
    assert result["alerts"] == expected
    assert result["replay_seconds"] > 0
    assert result["peak_process_rss_kib"] > 0
    assert result["detector_limits"] == {"max_events": size, "max_alerts": size}


@pytest.mark.parametrize("profile", bench.PROFILES)
def test_seed_changes_order_without_changing_fixture_population(profile):
    first, expected = bench.build_events(profile, 23, 42)
    repeat, same_expected = bench.build_events(profile, 23, 42)
    shuffled, shuffled_expected = bench.build_events(profile, 23, 43)
    assert first == repeat and first != shuffled
    assert expected == same_expected == shuffled_expected
    assert sorted(first, key=lambda event: event["event.id"]) == sorted(shuffled, key=lambda event: event["event.id"])
    assert bench.records_digest(first) == bench.records_digest(repeat)
    assert bench.records_digest(first) != bench.records_digest(shuffled)


@pytest.mark.parametrize("changes", [
    {"profiles": []}, {"profiles": ["lsass", "lsass"]}, {"profiles": ["unknown"]},
    {"sizes": []}, {"sizes": [1, 1]}, {"sizes": [0]}, {"sizes": [100001]},
    {"sizes": [True]}, {"sizes": [1.5]}, {"sizes": list(range(1, 7))},
    {"repeats": 0}, {"repeats": 11}, {"repeats": True},
    {"seed": -1}, {"seed": 2**32}, {"seed": True},
    {"sizes": [100000, 99999], "repeats": 10},
])
def test_invalid_work_or_total_budget_rejected_before_any_child(monkeypatch, changes):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid configuration must not start work")
    monkeypatch.setattr(bench.subprocess, "run", forbidden)
    config = {"profiles": list(bench.PROFILES), "sizes": [10], "repeats": 1, "seed": 42}
    config.update(changes)
    with pytest.raises(ValueError):
        bench.benchmark(**config)


def test_wrong_detector_result_is_failure_not_a_fast_benchmark(monkeypatch):
    from tools import detect_lsass
    monkeypatch.setattr(detect_lsass, "evaluate_events", lambda events, **kwargs: {
        "alerts": [], "summary": {"input_events": len(events), "unique_events": len(events),
                                  "duplicate_events": 0, "alerts": 0}})
    with pytest.raises(ValueError, match="correctness check failed"):
        bench.run_worker("lsass", 10, 42)


def test_failed_worker_never_becomes_a_partial_success(monkeypatch):
    monkeypatch.setattr(bench, "source_metadata", lambda: {"source_sha256": {"core": "same"}})
    monkeypatch.setattr(bench.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 1, "", "max_alerts exceeded"))
    with pytest.raises(ValueError, match="worker failed.*max_alerts exceeded"):
        bench.benchmark(["lsass"], [10], 1, 42)


def test_changed_result_digest_prevents_aggregate_report():
    sample = bench.run_worker("lsass", 10, 42)
    other = deepcopy(sample)
    other["alerts_sha256"] = "unexpected"
    with pytest.raises(ValueError, match="results differ"):
        bench.summarize_samples([sample, other])


def test_empirical_p95_is_explicit_nearest_rank_not_an_slo():
    sample = bench.run_worker("lsass", 1, 42)
    samples = [{**sample, "replay_seconds": seconds, "events_per_second": 1 / seconds}
               for seconds in [0.3, 0.1, 0.2]]
    summary = bench.summarize_samples(samples)
    assert summary["median_replay_seconds"] == 0.2
    assert summary["empirical_p95_replay_seconds"] == 0.3
    assert summary["max_replay_seconds"] == 0.3


def test_existing_output_is_preserved_without_running_benchmark(monkeypatch, tmp_path):
    destination = tmp_path / "existing.json"
    destination.write_text("prior evidence")
    monkeypatch.setattr(bench, "benchmark", lambda *args: pytest.fail("must check destination before work"))
    assert bench.main(["--output", str(destination)]) == 1
    assert destination.read_text() == "prior evidence"


def test_cli_uses_fresh_workers_and_functions_outside_checkout(tmp_path):
    destination = tmp_path / "report.json"
    result = subprocess.run(
        [sys.executable, str(Path(bench.__file__).resolve()), "--profiles", "rolling-v2", "lsass",
         "--sizes", "23", "--repeats", "2", "--output", str(destination)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(destination.read_text())
    assert len(report["results"]) == 2
    assert [item["alerts"] for item in report["results"]] == [14, 3]
    assert all(item["sample_count"] == 2 for item in report["results"])
    samples = [sample for item in report["results"] for sample in item["samples"]]
    assert all(sample["worker_pid"] != __import__("os").getpid() for sample in samples)
    assert all(sample["child_process_seconds"] >= sample["replay_seconds"] for sample in samples)
    assert len({sample["worker_pid"] for sample in samples}) == 4
    assert report["source"]["source_sha256"]
