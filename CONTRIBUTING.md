# Contributing

Use Python 3.12 and the hashed development lock. Run `make setup` then `make check` from the repository root. Network or Elastic changes also require `make check-network` or `make lab-up && make check-elastic`. See docs/elastic.md for the synthetic lab.

`make demo` checks the seven documented offline paths without executing fixture
commands. The ten process-v1 rules are explicitly listed in
`profiles/elastic/process-rules.json`; changes must preserve their manual
expectations and native query parity. Sigma identifiers must be UUIDv4.
GitHub Actions use full commit pins with version comments; update the pin only
after checking the official action's runtime and inputs.

Every detection change should include:

1. An explicit observation and ATT&CK mapping, distinguishing observed behavior from attack-chain context.
2. Source prerequisites and field normalization. Absent fields and ambiguous aliases are not benign evidence.
3. A positive fixture and meaningful benign/boundary negatives. Use inert synthetic content or sanitized data with provenance and expected alerts.
4. Updated DetCard references, lifecycle, validation scope and changelog. Add a dedicated card for new platform behavior.
5. A native format/engine check where applicable. Compiled rules are not replay evidence; predicate fixtures are not SIEM parity.
6. `make coverage` and review of generated differences. Commit docs/coverage.md, not artifacts/ outputs.

See docs/methodology.md for lifecycle gates and metric definitions. Do not promote stable or fill TPR/FPR from handpicked passing examples. Do not weaken assertions or silently skip unsupported rules to make CI green.

Update requirements-dev.in, run `uv pip compile requirements-dev.in --generate-hashes -o requirements-dev.lock`, install with hash verification and repeat affected checks. Container updates include a verified immutable digest and native replay results.

PR descriptions state changed behavior, assumptions, executed checks and limitations. Attribution must reflect actual contributors and licenses; inherited placeholder author metadata must be resolved by the repository owner rather than guessed.
