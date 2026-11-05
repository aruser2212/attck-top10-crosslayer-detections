#!/usr/bin/env python3
"""Compile every YARA rule and match inert source fixtures with libyara.

Fixtures are text passed to the scanner, never executed. These checks establish
fixture behavior only; they do not measure operational detection accuracy.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parents[1]


def check_yara(root: Path = ROOT) -> dict:
    paths = sorted(root.glob("techniques/*/yara/*.yara"))
    if not paths:
        raise ValueError("No YARA rules found")
    rules = yara.compile(filepaths={f"rule_{i}": str(path) for i, path in enumerate(paths)},
                         error_on_warning=True)
    manifest = json.loads((root / "tests/fixtures/yara/cases.json").read_text())
    names = {rule.identifier for rule in rules}
    if names != set(manifest["rules"]):
        raise ValueError(f"YARA inventory differs from fixtures: {names!r}")
    if not manifest["cases"]:
        raise ValueError("No YARA fixtures found")
    covered = set()
    cases = []
    for case in manifest["cases"]:
        matches = sorted(match.rule for match in rules.match(data=case["text"].encode("utf-8"), timeout=5))
        expected = sorted(case["expected"])
        if matches != expected:
            raise AssertionError(f"{case['id']}: expected {expected}, got {matches}")
        covered.update(matches)
        cases.append({"id": case["id"], "matches": matches})
    if covered != names:
        raise ValueError(f"Rules without positive fixtures: {names - covered}")
    return {"engine": f"libyara {yara.__version__}", "rules": len(names), "cases": cases,
            "scope": "inert source fixture matching; operational accuracy unmeasured"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(check_yara(args.root), indent=2))


if __name__ == "__main__":
    main()
