# Roadmap

## v0.1 — Portfolio baseline

Status: ready for initial GitHub publication.

- Top-10 ATT&CK TTP folders are present.
- DetCards, Sigma, Hunt DSL, IDPS rules, YARA rules and test plans are linked.
- Repository validator is available in `tools/validate_repo.py`.
- GitHub Actions validation workflow is available in `.github/workflows/validate.yml`.

## v0.2 — Deeper dossiers

Status: complete for portfolio baseline.

Each technique README contains compact analysis:

- confirmed facts from MITRE ATT&CK and vendor documentation;
- attacker workflow;
- telemetry map;
- false positive sources;
- response checklist;
- references.

## v0.3 — Platform adapters

Add optional adapters without changing the SIEM-agnostic core:

- `queries/elastic/`
- `queries/splunk/`
- `queries/maxpatrol/`

## v0.4 — Lab and synthetic data

Add safe lab notes and sanitized/synthetic event examples:

- EVTX snippets;
- JSON logs;
- PCAP samples;
- validation screenshots or reports.
