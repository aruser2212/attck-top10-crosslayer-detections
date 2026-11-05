"""Arithmetic and input-contract tests; fixtures are not measured rule quality."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from tools.evaluate_detection import EvaluationError, evaluate, load_json, main


FIXTURE = Path(__file__).parent / "fixtures" / "evaluation" / "synthetic_observations.json"


def sample():
    return load_json(FIXTURE)


def test_nontrivial_confusion_matrix_and_duplicate_detection_accounting():
    payload = sample()
    original = deepcopy(payload)
    report = evaluate(payload)
    assert report["confusion_matrix"] == {"tp": 2, "fp": 1, "tn": 3, "fn": 1}
    assert report["metrics"] == pytest.approx({"precision": 2 / 3, "recall_tpr": 2 / 3, "fpr": 1 / 4})
    assert report["metric_denominators"] == {"precision": 3, "recall_tpr": 3, "fpr": 4}
    assert report["totals"] == {
        "observations": 7, "positives": 3, "negatives": 4,
        "detected_observations": 3, "submitted_detected_ids": 4, "duplicate_detected_ids": 1,
    }
    assert report["undefined_metrics"] == []
    assert payload == original


def test_no_detections_has_undefined_precision_but_zero_recall_and_fpr():
    payload = sample()
    payload["detected_ids"] = []
    report = evaluate(payload)
    assert report["confusion_matrix"] == {"tp": 0, "fp": 0, "tn": 4, "fn": 3}
    assert report["metrics"] == {"precision": None, "recall_tpr": 0, "fpr": 0}
    assert report["undefined_metrics"] == ["precision: no detected observations"]


def test_detecting_every_observation_has_unit_recall_and_fpr():
    payload = sample()
    payload["detected_ids"] = [observation["id"] for observation in payload["observations"]]
    report = evaluate(payload)
    assert report["confusion_matrix"] == {"tp": 3, "fp": 4, "tn": 0, "fn": 0}
    assert report["metrics"] == pytest.approx({"precision": 3 / 7, "recall_tpr": 1, "fpr": 1})


@pytest.mark.parametrize("detect", [False, True])
def test_positive_only_population_cannot_estimate_fpr(detect):
    payload = sample()
    payload["observations"] = [{"id": "p", "label": "positive"}]
    payload["detected_ids"] = ["p"] if detect else []
    report = evaluate(payload)
    assert report["metrics"]["fpr"] is None
    assert report["metric_denominators"]["fpr"] == 0
    assert "fpr: no labeled negative observations" in report["undefined_metrics"]
    assert report["metrics"]["recall_tpr"] == int(detect)


@pytest.mark.parametrize("detect", [False, True])
def test_negative_only_population_cannot_estimate_recall(detect):
    payload = sample()
    payload["observations"] = [{"id": "n", "label": "negative"}]
    payload["detected_ids"] = ["n"] if detect else []
    report = evaluate(payload)
    assert report["metrics"]["recall_tpr"] is None
    assert report["metrics"]["fpr"] == int(detect)
    assert report["metrics"]["precision"] == (0 if detect else None)


def test_order_and_repeated_detections_do_not_change_metrics():
    payload = sample()
    expected = evaluate(payload)
    payload["observations"].reverse()
    payload["detected_ids"] = list(reversed(payload["detected_ids"])) * 3
    actual = evaluate(payload)
    assert actual["metrics"] == expected["metrics"]
    assert actual["confusion_matrix"] == expected["confusion_matrix"]
    assert actual["totals"]["duplicate_detected_ids"] == 9


@pytest.mark.parametrize("unit", ["event", "window_group", "incident"])
@pytest.mark.parametrize("kind", ["synthetic", "operational"])
def test_provenance_and_declared_unit_survive_report(unit, kind):
    payload = sample()
    payload["dataset"].update(unit=unit, kind=kind, period="2026-01-01/2026-01-02")
    report = evaluate(payload)
    assert report["dataset"] == payload["dataset"]
    assert report["scope"] == "supplied_labeled_observations"
    assert any("not independently verified" in text for text in report["limitations"])
    assert any("not an operational quality measurement" in text for text in report["limitations"]) == (kind == "synthetic")
    report["dataset"]["name"] = "changed report"
    assert payload["dataset"]["name"] == "Inert arithmetic example"


def test_unknown_detected_ids_are_errors_not_false_positives():
    payload = sample()
    payload["detected_ids"].append("not-in-labeled-universe")
    with pytest.raises(EvaluationError, match="unknown detected observation IDs"):
        evaluate(payload)


@pytest.mark.parametrize("label", ["positive", "negative"])
def test_duplicate_observation_ids_fail_even_with_agreeing_labels(label):
    payload = sample()
    payload["observations"].append({"id": "positive-1", "label": label})
    with pytest.raises(EvaluationError, match="duplicate observation ID"):
        evaluate(payload)


@pytest.mark.parametrize("value", [[], None, {}, "observations", True])
def test_missing_observation_population_fails(value):
    payload = sample()
    payload["observations"] = value
    with pytest.raises(EvaluationError, match="observations must be a nonempty array"):
        evaluate(payload)


@pytest.mark.parametrize("label", [True, False, 1, 0, None, "POSITIVE", "", [], {}])
def test_labels_require_explicit_strings(label):
    payload = sample()
    payload["observations"][0]["label"] = label
    with pytest.raises(EvaluationError, match="label"):
        evaluate(payload)


@pytest.mark.parametrize("value", [True, False, 1.0, "1", 2, None])
def test_schema_version_requires_integer_one(value):
    payload = sample()
    payload["schema_version"] = value
    with pytest.raises(EvaluationError, match="schema_version"):
        evaluate(payload)


@pytest.mark.parametrize(("field", "value"), [
    ("name", ""), ("name", True), ("source_description", " "),
    ("kind", "mixed"), ("unit", "alert_count"), ("period", None),
])
def test_provenance_requires_explicit_valid_values(field, value):
    payload = sample()
    payload["dataset"][field] = value
    with pytest.raises(EvaluationError, match=f"dataset.{field}"):
        evaluate(payload)


@pytest.mark.parametrize("value", [True, 1, None, "", " ", {}, []])
def test_observation_ids_are_nonempty_strings(value):
    payload = sample()
    payload["observations"][0]["id"] = value
    with pytest.raises(EvaluationError, match="observations\\[0\\].id"):
        evaluate(payload)


@pytest.mark.parametrize("value", [True, 1, None, "", {}, []])
def test_detected_ids_are_nonempty_strings(value):
    payload = sample()
    payload["detected_ids"] = [value]
    with pytest.raises(EvaluationError, match="detected_ids\\[0\\]"):
        evaluate(payload)


@pytest.mark.parametrize("field", ["schema_version", "dataset", "observations", "detected_ids"])
def test_required_top_level_fields(field):
    payload = sample()
    del payload[field]
    with pytest.raises(EvaluationError, match="missing required fields"):
        evaluate(payload)


def test_unknown_fields_are_not_silently_ignored():
    payload = sample()
    payload["detected_event_count"] = 100
    with pytest.raises(EvaluationError, match="unknown fields"):
        evaluate(payload)


@pytest.mark.parametrize("text", [
    '{"schema_version": 1, "schema_version": 1}',
    '{"dataset": {"kind": "synthetic", "kind": "operational"}}',
])
def test_duplicate_json_properties_fail_at_any_level(tmp_path, text):
    path = tmp_path / "duplicate.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(EvaluationError, match="duplicate JSON key"):
        load_json(path)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_json_numbers_fail(tmp_path, constant):
    path = tmp_path / "non-json.json"
    path.write_text('{"value": ' + constant + '}', encoding="utf-8")
    with pytest.raises(EvaluationError, match="non-JSON numeric constant"):
        load_json(path)


def test_cli_stdout_is_json_and_has_no_file_side_effects(capsys):
    assert main([str(FIXTURE)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == evaluate(sample())


def test_cli_creates_new_report_and_refuses_to_overwrite(tmp_path, capsys):
    output = tmp_path / "report.json"
    assert main([str(FIXTURE), "--output", str(output)]) == 0
    contents = output.read_bytes()
    assert json.loads(contents) == evaluate(sample())
    assert main([str(FIXTURE), "--output", str(output)]) == 2
    assert output.read_bytes() == contents
    assert "Evaluation failed" in capsys.readouterr().err


def test_cli_rejects_non_json_output(tmp_path, capsys):
    output = tmp_path / "DET-EXAMPLE.yaml"
    assert main([str(FIXTURE), "--output", str(output)]) == 2
    assert not output.exists()
    assert ".json extension" in capsys.readouterr().err


def test_invalid_input_does_not_create_report(tmp_path, capsys):
    source = tmp_path / "invalid.json"
    source.write_text("{}", encoding="utf-8")
    output = tmp_path / "report.json"
    assert main([str(source), "--output", str(output)]) == 2
    assert not output.exists()
    assert capsys.readouterr().out == ""


def test_process_exit_status_propagates_invalid_json(tmp_path):
    source = tmp_path / "invalid.json"
    source.write_text("{", encoding="utf-8")
    process = subprocess.run(
        [sys.executable, "tools/evaluate_detection.py", str(source)],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
    )
    assert process.returncode == 2
    assert process.stdout == ""
    assert "invalid JSON input" in process.stderr
