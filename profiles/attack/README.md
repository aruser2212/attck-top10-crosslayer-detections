# Pinned Enterprise ATT&CK identities

The offline catalog is derived from official MITRE Enterprise ATT&CK **v20.0**, STIX **2.1**. Catalog schema 2 retains all 867 technique/subtechnique identities, names, lifecycle flags, tactic phases, parent relations and declared replacement relations, plus the 15 canonical tactic identities/shortnames. Descriptions and procedure examples are not copied.

Source repository: [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data). The tag was discovered through read-only `git ls-remote --tags`; its peeled commit is `20664a889568dce884a1dac0ec7b12ae3a199f51`. The annotated tag object, immutable download URL, source byte count/SHA256 and derived catalog SHA256 are recorded in [metadata.json](metadata.json).

The original STIX copyright/trademark statement is preserved verbatim in [NOTICE.txt](NOTICE.txt), together with the source and terms of use. See the [mapping review](../../docs/attack-mapping.md) for the checked T1070.002 → T1685.006 migration and the reason historical folder/DetCard identifiers remain stable.

`python tools/check_attack.py check` validates the catalog checksum and lints all DetCard technique IDs/tactics and Sigma technique/tactic tags **without network access**. Unknown, revoked and deprecated active references fail. Historical references in deprecated artifacts warn. Contextual differences between linked cards and Sigma rules, or valid tactics not assigned to their selected techniques, warn for human review; source files are never rewritten. Parent/subtechnique relationships are recognized, but distinct subtechniques are not treated as interchangeable.

Sigma tactic shortnames may use hyphens or underscores; canonical TA IDs are also recognized. Numeric group/software/campaign/mitigation/data-source/data-component tags remain outside this check's scope. In v20.0, `defense-evasion` is no longer a canonical tactic: for example, T1070 uses `stealth`, whereas T1685.006 uses `defense-impairment`. There is no safe blanket string replacement; use the selected technique's official phases and review contextual tactics explicitly.

The checksum detects changes to the pinned catalog relative to its stored metadata. It is not a signature or evidence that an upstream tag can never move. Source identity is pinned to the full commit, not a branch or a tag URL. Runtime checks do not download updates or monitor new ATT&CK releases; refreshing the source is an explicit reviewed change.

## Rebuild or update

Download the official bundle outside the checkout over verified HTTPS. Review the selected release and peeled commit before updating the metadata. The builder performs no download and verifies the expected source SHA256 before processing:

```bash
python tools/check_attack.py build /path/to/enterprise-attack-v20.0.json \
  --attack-tag v20.0 \
  --commit 20664a889568dce884a1dac0ec7b12ae3a199f51 \
  --tag-object 3a9dc7798bf78b53b77fc2f821002f7167c00be3 \
  --source-sha256 81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352
```

The generated catalog and metadata are deterministic for the same source bytes and arguments. Review new revoked/deprecated identities and declared successors; do not automatically replace technique mappings just to make lint pass. Source bundle descriptions may be needed to determine whether a replacement preserves the detector's observed behavior.

This project is not affiliated with or endorsed by MITRE. ATT&CK source material is subject to MITRE's [terms of use](https://attack.mitre.org/resources/terms-of-use/); see [NOTICE.txt](NOTICE.txt) for the exact source attribution.
