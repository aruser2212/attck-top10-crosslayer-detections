#!/usr/bin/env python3
"""Evaluate matched observation IDs against an explicitly labeled universe.

Input is one JSON object with schema_version=1, dataset provenance, observations
({id, label: positive|negative}), and detected_ids. The observation unit must be
declared as event, window_group, or incident. For aggregations/correlations,
define and label the complete window/group or incident population upstream;
raw event counts are not interchangeable with alert counts.

This tool computes arithmetic for the supplied labels and matched IDs. It does
not execute a detector, verify label quality/population completeness, or establish
that a synthetic dataset represents operational traffic. It never updates rule
metadata or promotes a detection's maturity status.

Run: python tools/evaluate_detection.py INPUT.json [--output NEW_REPORT.json]
Without --output, the JSON report is written to stdout. Existing output files
are never overwritten. Undefined rates are JSON null, not invented zeros.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


class EvaluationError(ValueError):
    """The input does not define a valid labeled observation universe."""


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvaluationError(f"non-JSON numeric constant: {value}")


def load_json(path: Path | str) -> Any:
    """Read strict JSON, rejecting duplicate keys and NaN/Infinity anywhere."""
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_unique_keys,
                             parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise EvaluationError(f"invalid JSON input: {exc}") from exc


def _object(value: Any, *, field: str, required: set[str],
            optional: frozenset[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationError(f"{field} must be an object")
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise EvaluationError(f"{field} missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        raise EvaluationError(f"{field} has unknown fields: {', '.join(sorted(map(str, unknown)))}")
    return value


def _text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvaluationError(f"{field} must be a nonempty string")
    return value


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate(payload: Any) -> dict[str, Any]:
    """Compute observation-level metrics; duplicate detections count only once."""
    data = _object(payload, field="input", required={
        "schema_version", "dataset", "observations", "detected_ids",
    })
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise EvaluationError("schema_version must be the integer 1")

    source = _object(data["dataset"], field="dataset", required={
        "name", "kind", "unit", "source_description",
    }, optional=frozenset({"period"}))
    dataset = {key: _text(value, field=f"dataset.{key}") for key, value in source.items()}
    if dataset["kind"] not in {"synthetic", "operational"}:
        raise EvaluationError("dataset.kind must be synthetic or operational")
    if dataset["unit"] not in {"event", "window_group", "incident"}:
        raise EvaluationError("dataset.unit must be event, window_group, or incident")

    if not isinstance(data["observations"], list) or not data["observations"]:
        raise EvaluationError("observations must be a nonempty array")
    labels = {}
    for index, observation in enumerate(data["observations"]):
        field = f"observations[{index}]"
        observation = _object(observation, field=field, required={"id", "label"})
        observation_id = _text(observation["id"], field=f"{field}.id")
        label = _text(observation["label"], field=f"{field}.label")
        if label not in {"positive", "negative"}:
            raise EvaluationError(f"{field}.label must be positive or negative")
        if observation_id in labels:
            raise EvaluationError(f"duplicate observation ID: {observation_id!r}")
        labels[observation_id] = label

    if not isinstance(data["detected_ids"], list):
        raise EvaluationError("detected_ids must be an array")
    detected = {_text(value, field=f"detected_ids[{index}]")
                for index, value in enumerate(data["detected_ids"])}
    unknown_ids = detected - labels.keys()
    if unknown_ids:
        raise EvaluationError(f"unknown detected observation IDs: {', '.join(sorted(unknown_ids))}")

    positives = {key for key, label in labels.items() if label == "positive"}
    negatives = labels.keys() - positives
    tp = len(detected & positives)
    fp = len(detected & negatives)
    fn = len(positives - detected)
    tn = len(negatives - detected)
    denominators = {"precision": tp + fp, "recall_tpr": tp + fn, "fpr": fp + tn}
    metrics = {"precision": _ratio(tp, denominators["precision"]),
               "recall_tpr": _ratio(tp, denominators["recall_tpr"]),
               "fpr": _ratio(fp, denominators["fpr"])}
    undefined = []
    if not denominators["precision"]:
        undefined.append("precision: no detected observations")
    if not denominators["recall_tpr"]:
        undefined.append("recall_tpr: no labeled positive observations")
    if not denominators["fpr"]:
        undefined.append("fpr: no labeled negative observations")

    limitations = [
        "Metrics describe only the supplied labeled observation universe and matched IDs.",
        "Label quality, population completeness, and detector execution are not independently verified.",
    ]
    if dataset["kind"] == "synthetic":
        limitations.append("Synthetic results are not an operational quality measurement.")
    return {
        "schema_version": 1,
        "dataset": dataset,
        "scope": "supplied_labeled_observations",
        "totals": {
            "observations": len(labels),
            "positives": len(positives),
            "negatives": len(negatives),
            "detected_observations": len(detected),
            "submitted_detected_ids": len(data["detected_ids"]),
            "duplicate_detected_ids": len(data["detected_ids"]) - len(detected),
        },
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": metrics,
        "metric_denominators": denominators,
        "metric_definitions": {
            "precision": "TP / (TP + FP)",
            "recall_tpr": "TP / (TP + FN)",
            "fpr": "FP / (FP + TN)",
        },
        "undefined_metrics": undefined,
        "limitations": limitations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("input", type=Path, help="JSON dataset, labels, and matched observation IDs")
    parser.add_argument("--output", type=Path, help="new .json report file; existing files are not overwritten")
    args = parser.parse_args(argv)
    try:
        report = evaluate(load_json(args.input))
        encoded = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        if args.output is not None:
            if args.output.suffix.lower() != ".json":
                raise EvaluationError("output must have a .json extension")
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        else:
            sys.stdout.write(encoded)
    except (EvaluationError, OSError) as exc:
        print(f"Evaluation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
