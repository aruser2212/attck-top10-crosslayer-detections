# Evaluating labeled detection outcomes

[`tools/evaluate_detection.py`](../tools/evaluate_detection.py) computes a confusion
matrix and rates for an explicit set of labeled observations and matching
observation IDs. It uses the Python standard library and does not execute a rule.
Preparing the labels, running the detector, and matching its output to the same
observation units happen before this command.

## Start with the synthetic arithmetic example

From the repository root:

```bash
python tools/evaluate_detection.py tests/fixtures/evaluation/synthetic_observations.json
```

The included example contains inert placeholder IDs and hand-written outcomes.
It exercises the evaluator's arithmetic and duplicate handling. Its results are
not measurements of any repository detection's operational quality.

To save a report, create its parent directory and choose a new filename:

```bash
mkdir -p artifacts
python tools/evaluate_detection.py tests/fixtures/evaluation/synthetic_observations.json \
  --output artifacts/evaluation-synthetic-example.json
```

Without `--output`, the report is JSON on stdout. With `--output`, the destination
must have a `.json` extension and must not already exist. The command does not
overwrite an earlier report or create missing parent directories. Success exits
with code `0`; invalid input or an output/storage error exits with code `2` and
an explanation on stderr.

## Input contract: schema version 1

Input is one UTF-8 JSON object, not JSONL. The exact shape is:

```json
{
  "schema_version": 1,
  "dataset": {
    "name": "Inert format example",
    "kind": "synthetic",
    "unit": "event",
    "source_description": "Hand-labeled placeholder observations; no detector run or real telemetry."
  },
  "observations": [
    {"id": "example-positive", "label": "positive"},
    {"id": "example-negative", "label": "negative"}
  ],
  "detected_ids": ["example-positive"]
}
```

| Field | Requirement |
|---|---|
| `schema_version` | Integer `1`; strings, floats and booleans are rejected. |
| `dataset.name` | Nonempty string identifying the dataset. |
| `dataset.kind` | Exactly `synthetic` or `operational`. |
| `dataset.unit` | Exactly `event`, `window_group` or `incident`. |
| `dataset.source_description` | Nonempty string describing provenance and how labels and matches were obtained. |
| `dataset.period` | Optional nonempty string describing the observation period. The evaluator preserves it without validating date syntax. |
| `observations` | Nonempty array of objects containing exactly `id` and `label`. |
| `observations[].id` | Unique nonempty string. IDs are compared exactly, including case. |
| `observations[].label` | Exactly `positive` or `negative`; boolean/numeric labels are rejected. |
| `detected_ids` | Array of nonempty strings referring to IDs in `observations`; an empty array is allowed. |

Unknown fields, duplicate JSON object keys, and NaN/Infinity constants are
rejected. Repeated observation IDs are errors even when their labels agree.
Repeated IDs in `detected_ids` are counted once as detections; the number removed
is reported in `totals.duplicate_detected_ids`. A detected ID absent from the
labeled universe is an error, not an automatically inferred false positive.

## Define the observation universe first

The universe is the full set of observations selected for this evaluation,
including observations for which the detector emitted nothing. A label states
whether the observation should be detected according to the independently
established ground truth. A match states whether the evaluated detector actually
detected that same observation.

Use one unit consistently throughout a run:

- **`event`**: each observation is one event, suitable for an event predicate.
- **`window_group`**: each observation is a defined time window and grouping key,
  suitable for an aggregation such as failed logons per user and source IP.
- **`incident`**: each observation is a defined incident, with a documented rule
  for matching one or more alerts to that incident.

For the T1110 aggregation, label the chosen window/group population and map its
alerts to those window/group IDs. Counting each failed-logon event as an
independent positive while counting one aggregate alert as one detection mixes
units and produces misleading rates. Define window boundaries, grouping keys,
eligible groups, and the evaluation period upstream; the evaluator does not
infer them from raw logs or create unobserved negative windows.

A file containing only emitted alerts cannot establish missed positives or the
complete negative population. Include independently labeled non-alerted
observations to measure those outcomes. Unlabeled observations cannot be treated
as negative by default. If sampling or exclusions were used, record them and
interpret the report only for that selected population.

## Report and metric definitions

| Outcome | Meaning |
|---|---|
| `tp` | Labeled positive and detected. |
| `fp` | Labeled negative and detected. |
| `tn` | Labeled negative and not detected. |
| `fn` | Labeled positive and not detected. |

| Metric key | Formula | Undefined when |
|---|---|---|
| `precision` | TP / (TP + FP) | No observations were detected. |
| `recall_tpr` | TP / (TP + FN) | No observations are labeled positive. |
| `fpr` | FP / (FP + TN) | No observations are labeled negative. |

Undefined rates are JSON `null`, with their reasons in `undefined_metrics`.
In particular, a positive-only test cannot establish FPR; the absence of a
negative population does not mean zero false positives. FPR is the fraction of
negative observations detected, not the fraction of alerts that are incorrect.

The report includes the confusion matrix, formulas, metric denominators,
observation and duplicate counts, and the supplied dataset metadata. The scope
is explicitly `supplied_labeled_observations`; no confidence interval or claim
about an unseen population is inferred.

## Evaluating operational observations

1. Select and document an observation unit, period, population and labeling
   procedure. Include relevant benign activity and positive cases; avoid
   deriving labels from the detector being evaluated.
2. Run the chosen detector/version against the selected data and match its
   output to observation IDs at that unit. Record the detector version,
   configuration, dataset version, label provenance and any sampling in
   `dataset.source_description` or an accompanying study record.
3. Supply the labels and matched IDs in the same input format, using
   `dataset.kind: operational` only when describing operational observations.
   Evaluate that file and retain a new JSON report with its source evidence.

The `operational` designation and other provenance fields are caller-supplied
metadata. They do not prove that labels are correct, that the population is
representative, or that a detector was executed. The tool validates the input
contract and computes rates; those substantive claims require supporting data
and review. Synthetic examples remain synthetic regardless of their scores.

Evaluation does not write metrics into DetCards or promote rules to `stable`.
Any later maturity decision must follow the project's evidence and review
requirements.
