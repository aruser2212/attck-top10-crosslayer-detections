#!/usr/bin/env python3
"""Bounded, deterministic offline replay benchmark; no production EPS claim.

Each sample runs in a new Python process. replay_seconds measures the detector
call, including its validation, sorting and alert construction. Child-process
wall time also includes interpreter startup, imports, fixture generation and
verification. Linux peak RSS covers the entire worker, not detector allocations
alone. Every sample must satisfy independent fixture expectations before a
report is returned; repeated samples must have identical input/output digests.

The two workloads intentionally have different alert densities. These are
controlled finite inputs, not a representative attack or benign population.
There is no collection, network, Elasticsearch, SQLite or history-retention load.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("rolling-v2", "lsass")
MAX_EVENTS = 100_000
MAX_REPEATS = 10
MAX_TOTAL_EVENTS = 2_000_000
DEFAULT_SEED = 424242
HUNT_PATH = ROOT / "techniques/T1110_Brute_Force/hunts/win_4625_brute_agg_rolling.hunt.yaml"


def _integer(value, name: str, lower: int, upper: int) -> None:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")


def validate_config(profiles, sizes, repeats: int, seed: int) -> None:
    if (not isinstance(profiles, (list, tuple)) or not profiles
            or any(profile not in PROFILES for profile in profiles)
            or len(set(profiles)) != len(profiles)):
        raise ValueError("profiles must be a nonempty unique selection of rolling-v2 and lsass")
    if not isinstance(sizes, (list, tuple)) or not 1 <= len(sizes) <= 5:
        raise ValueError("supply one to five event sizes")
    for size in sizes:
        _integer(size, "event size", 1, MAX_EVENTS)
    if len(set(sizes)) != len(sizes):
        raise ValueError("event sizes must be unique")
    _integer(repeats, "repeats", 1, MAX_REPEATS)
    _integer(seed, "seed", 0, 2**32 - 1)
    if sum(sizes) * len(profiles) * repeats > MAX_TOTAL_EVENTS:
        raise ValueError(f"total requested work exceeds {MAX_TOTAL_EVENTS} input events")


def build_events(profile: str, size: int, seed: int) -> tuple[list[dict], int]:
    """Return inert data and a count specified independently of detector output.

    Rolling: one group, distinct 1ms anchors, all records within the 5m window;
    count >=10 qualifies anchors 10..N. LSASS: every tenth record has VM_READ,
    including some AV-named source images; all others have query-only access.
    """
    validate_config([profile], [size], 1, seed)
    origin = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    for i in range(size):
        timestamp = (origin + timedelta(milliseconds=i)).isoformat(timespec="microseconds").replace("+00:00", "Z")
        event = {"@timestamp": timestamp, "event.id": f"bench-{profile}-{i:06d}"}
        if profile == "rolling-v2":
            event.update({"event.dataset": "windows.security.logons", "event.code": "4625",
                          "target.user": "benchmark-account", "source.ip": "192.0.2.10"})
        else:
            event.update({
                "event.dataset": "windows.sysmon.process_access", "event.code": "10",
                "host.name": f"host-{i % 32:02d}.lab",
                "source.process.guid": f"{i + 1:08x}-0000-0000-0000-000000000001",
                "target.process.guid": "00000000-0000-0000-0000-000000000002",
                "source.image": (r"C:\Program Files\Defender\MsMpEng.exe" if i % 20 == 0
                                 else r"C:\Lab\diagnostic.exe"),
                "target.image": r"C:\Windows\System32\lsass.exe",
                "process.access_mask": 0x1410 if i % 10 == 0 else 0x1000,
            })
        events.append(event)
    random.Random(seed).shuffle(events)
    expected = max(0, size - 9) if profile == "rolling-v2" else (size + 9) // 10
    return events, expected


def records_digest(records) -> str:
    """Hash ordered canonical JSON lines without a second full-size JSON buffer."""
    digest = hashlib.sha256()
    for record in records:
        digest.update(json.dumps(record, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def run_worker(profile: str, size: int, seed: int) -> dict:
    validate_config([profile], [size], 1, seed)
    if sys.platform != "linux":
        raise ValueError("this benchmark reports Linux ru_maxrss in KiB; other platforms are unsupported")
    import resource

    # Absolute project imports work both through -m and direct invocation from
    # another working directory. No optional benchmark dependency is required.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    if profile == "rolling-v2":
        from tools.rolling_hunt import evaluate_hunt, load_hunt
        rule = load_hunt(HUNT_PATH)
        if (rule["aggregate"] != {
                "group_by": ["target.user", "source.ip"], "window": "5m", "window_type": "rolling",
                "metrics": [{"name": "fails", "fn": "count", "field": "*"}],
            } or rule["having"] != [{"field": "fails", "op": "gte", "value": 10}]):
            raise ValueError("the rolling rule changed; review this benchmark's independent expectations")

        def evaluate(events):
            return evaluate_hunt(rule, events, max_events=size, max_alerts=size)
    else:
        from tools.detect_lsass import evaluate_events

        def evaluate(events):
            return evaluate_events(events, max_events=size, max_alerts=size)

    events, expected = build_events(profile, size, seed)
    input_digest = records_digest(events)
    begin = time.perf_counter()
    result = evaluate(events)
    elapsed = time.perf_counter() - begin
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError("invalid replay timer result")
    summary, alerts = result["summary"], result["alerts"]
    if (summary["input_events"] != size or summary["unique_events"] != size
            or summary["duplicate_events"] != 0 or len(alerts) != expected
            or summary["alerts"] != expected):
        raise ValueError("benchmark correctness check failed; no timing report is valid")
    # Verify identities/window counts as well as count, so an arbitrary result
    # with the expected cardinality cannot become a passing benchmark.
    if profile == "lsass":
        expected_ids = [f"bench-lsass-{i:06d}" for i in range(0, size, 10)]
        if [alert["event.id"] for alert in alerts] != expected_ids:
            raise ValueError("benchmark candidate identities differ from the declared fixture")
    else:
        if ([alert["fails"] for alert in alerts] != list(range(10, size + 1))
                or any(alert["target.user"] != "benchmark-account"
                       or alert["source.ip"] != "192.0.2.10" for alert in alerts)):
            raise ValueError("benchmark rolling counts/groups differ from the declared fixture")
    output_digest = records_digest(alerts)
    return {
        "profile": profile, "events": size, "seed": seed, "alerts": expected,
        "detector_limits": {"max_events": size, "max_alerts": size},
        "input_sha256": input_digest, "alerts_sha256": output_digest,
        "replay_seconds": elapsed, "events_per_second": size / elapsed,
        "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "worker_pid": os.getpid(),
    }


def summarize_samples(samples: list[dict]) -> dict:
    if not samples:
        raise ValueError("no successful benchmark samples")
    invariant = ("profile", "events", "seed", "alerts", "input_sha256", "alerts_sha256")
    if any(any(sample[key] != samples[0][key] for key in invariant) for sample in samples):
        raise ValueError("repeated benchmark inputs or results differ; no aggregate report is valid")
    times = sorted(sample["replay_seconds"] for sample in samples)
    if any(not math.isfinite(value) or value <= 0 for value in times):
        raise ValueError("sample replay times must be positive finite values")
    return {
        **{key: samples[0][key] for key in invariant}, "sample_count": len(samples),
        "median_replay_seconds": statistics.median(times),
        "empirical_p95_replay_seconds": times[math.ceil(0.95 * len(times)) - 1],
        "max_replay_seconds": times[-1],
        "median_events_per_second": statistics.median(sample["events_per_second"] for sample in samples),
        "max_process_rss_kib": max(sample["peak_process_rss_kib"] for sample in samples),
        "samples": samples,
    }


def source_metadata() -> dict:
    paths = [Path(__file__), HUNT_PATH, ROOT / "schema/rolling-hunt.schema.yaml",
             ROOT / "requirements-dev.lock"]
    paths += [ROOT / "tools" / name for name in (
        "rolling_hunt.py", "hunt_engine.py", "detect_lsass.py", "lsass_profile.py")]
    sources = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in paths}
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    state = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
    return {"git_commit": commit.stdout.strip() if commit.returncode == 0 else None,
            "working_tree_dirty": bool(state.stdout) if state.returncode == 0 else None,
            "source_sha256": sources}


def benchmark(profiles, sizes, repeats: int, seed: int) -> dict:
    validate_config(profiles, sizes, repeats, seed)
    before = source_metadata()
    results = []
    for profile in profiles:
        for size in sizes:
            samples = []
            for _ in range(repeats):
                begin = time.perf_counter()
                child = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), "--worker", profile,
                     "--size", str(size), "--seed", str(seed)],
                    capture_output=True, text=True, timeout=120, cwd=ROOT,
                )
                child_elapsed = time.perf_counter() - begin
                if child.returncode:
                    raise ValueError(f"benchmark worker failed for {profile}/{size}: {child.stderr.strip()}")
                sample = json.loads(child.stdout)
                if (sample.get("profile"), sample.get("events"), sample.get("seed")) != (profile, size, seed):
                    raise ValueError("benchmark worker returned a different workload")
                sample["child_process_seconds"] = child_elapsed
                samples.append(sample)
            results.append(summarize_samples(samples))
    after = source_metadata()
    if before["source_sha256"] != after["source_sha256"]:
        raise ValueError("benchmark sources changed during the run; discard mixed-version measurements")
    return {
        "format_version": 1,
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "deterministic finite offline replay; not operational throughput, accuracy or a service SLO",
        "timing_scope": "replay_seconds includes the detector call; imports/generation/checks are excluded",
        "memory_scope": "Linux whole-worker ru_maxrss in KiB, including imports, generated input, results and checks",
        "percentile_scope": "nearest-rank empirical p95 of these samples; with <=10 repeats this is their maximum",
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "machine": platform.machine(), "logical_cpu_count": os.cpu_count(),
                        "cpu_affinity_count": len(os.sched_getaffinity(0))},
        "source": before,
        "config": {"profiles": list(profiles), "sizes": list(sizes), "repeats": repeats, "seed": seed,
                   "worker_timeout_seconds": 120},
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 10000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", type=Path, help="Write a new JSON report; never overwrite an existing path")
    parser.add_argument("--worker", choices=PROFILES, help=argparse.SUPPRESS)
    parser.add_argument("--size", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.worker is not None:
            if args.output is not None:
                raise ValueError("internal workers may not write output files")
            result = run_worker(args.worker, args.size, args.seed)
        else:
            if args.size is not None:
                raise ValueError("use --sizes for the public benchmark command")
            if args.output is not None and (args.output.exists() or args.output.is_symlink()):
                raise ValueError("benchmark output already exists; choose a new report path")
            if args.output is not None and not args.output.parent.is_dir():
                raise ValueError("benchmark output parent directory does not exist")
            result = benchmark(args.profiles, args.sizes, args.repeats, args.seed)
        encoded = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output is None:
            print(encoded, end="")
        else:
            # The exclusive open also protects a path created after preflight.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"Replay benchmark failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
