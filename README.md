# ATT&CK Top-10 Cross-Layer Detections

[![Validate repository](https://github.com/aruser2212/attck-top10-crosslayer-detections/actions/workflows/validate.yml/badge.svg)](https://github.com/aruser2212/attck-top10-crosslayer-detections/actions/workflows/validate.yml)

SIEM-agnostic portfolio project for analyzing **Top-10 MITRE ATT&CK TTPs** and building detection artifacts across multiple layers: **Sigma**, **Suricata/Snort**, **YARA**, neutral **Hunt DSL**, and future SIEM-specific queries.

The core idea is simple: keep detection logic portable first, then add adapters for concrete platforms in `queries/<platform>/` and `profiles/`.

## Current coverage

| Metric | Count |
|---|---:|
| Techniques | 10 |
| DetCards | 19 |
| Sigma rules | 19 |
| Hunt DSL files | 22 |
| Network / IDPS rules | 6 |
| YARA rules | 2 |
| Test plans | 10 |

## Repository layout

```text
schema/       DetCard schema
profiles/     field mappings and future platform profiles
packs/        thematic detection packs
techniques/   ATT&CK technique dossiers and artifacts
docs/         methodology, coverage and validation notes
tools/        repository validation utilities
```

## Artifact model

Each detection is described by a **DetCard** (`DET-*.yaml`) with links to supporting artifacts:

- `sigma/` — host detection logic
- `network/` — Suricata/Snort rules where relevant
- `yara/` — AV/EDR/static detection where relevant
- `hunts/` — vendor-neutral hunting logic
- `queries/` — optional adapters for concrete platforms
- `tests/` — validation plan and future datasets

## Start here

1. Read [`docs/methodology.md`](docs/methodology.md).
2. Open [`docs/coverage.md`](docs/coverage.md) for the current ATT&CK coverage table.
3. Pick a technique under `techniques/` and review its DetCards, Sigma rules, hunts and test plan.

## Notes

This repository intentionally avoids binding core detection logic to a single SIEM. Platform-specific versions can be added later without rewriting the core artifacts.

Core artifacts are kept vendor-neutral so platform-specific adapters remain optional.

## Attribution

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

Technique descriptions in this repository are original summaries written for detection engineering practice. Official technique definitions are referenced in each technique dossier.

## Quality checks

The repository includes a lightweight validator for DetCards, artifact links and YAML structure:

```bash
python tools/validate_repo.py
```

The same check runs in GitHub Actions on push and pull request events.

## Project status

This repository is published as a **v0.2 portfolio baseline**. It includes compact dossiers for all Top-10 techniques, cross-layer detection artifacts, DetCards and repository validation.

Future updates will focus on selected platform mappings for Elastic, Splunk and MaxPatrol, followed by safe synthetic datasets for lab-style validation. See [`docs/roadmap.md`](docs/roadmap.md).

