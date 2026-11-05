#!/usr/bin/env python3
"""Keep checked-in Elastic aggregation templates aligned with the actual hunts.

These templates need elastic_adapter.py for PIT, complete pagination and having
thresholds. They are not standalone scheduled alert definitions.
"""
import argparse
import json
from pathlib import Path

try:
    from tools.elastic_adapter import compile_hunt
    from tools.hunt_engine import load_hunt
except ModuleNotFoundError:
    from elastic_adapter import compile_hunt
    from hunt_engine import load_hunt

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = ROOT / "techniques/T1110_Brute_Force"
    for name in ("brute", "spray"):
        body, _ = compile_hunt(load_hunt(directory / f"hunts/win_4625_{name}_agg.hunt.yaml"))
        text = json.dumps(body, ensure_ascii=False, indent=2) + "\n"
        path = directory / f"queries/elastic/win_4625_{name}.json"
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                raise SystemExit(f"Stale Elastic template: {path.name}; run python tools/generate_elastic_queries.py")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    print("OK: both Elastic aggregation templates match their Hunt v1 rules.")


if __name__ == "__main__":
    main()
