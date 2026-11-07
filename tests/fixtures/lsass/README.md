# LSASS ProcessAccess fixture contract

`cases.json` contains **40 manually specified scenarios / 50 synthetic records**.
The records are invented, inert normalized events. They are not captures from a
real customer, an attack execution dataset or a representative benign baseline.
Their expected event IDs were written from the declared observation contract,
without using the detector to generate expected answers.

The dedicated candidate observes a supported Sysmon ProcessAccess event whose
target filename is `lsass.exe` and whose granted mask contains `PROCESS_VM_READ`
(`0x10`). Extra granted rights do not suppress a candidate. Generic-right and
`MAXIMUM_ALLOWED` flags are not expanded into guessed process-specific rights.
An event grants an access right; it does not prove that memory was read or dumped.
Matching the filename also does not establish that the target is the genuine
Windows LSASS process: the same name under a user directory remains a candidate.

Each case declares:

- `events`: complete flat normalized inputs to the finite replay.
- `expected_event_ids`: manually declared matching source event IDs in timestamp,
  then event-ID order.
- `profile_valid`: whether the whole batch satisfies the strict source contract.
  A rejected batch must fail before producing alerts or ingesting documents.
- `outcome`: `candidate`, `benign_candidate`, `nonmatch` or `invalid`.
- `reason`: the expected observation and its interpretation.
- Optional `bounds`: a half-open `[start,end)` interval at microsecond precision.

**28 cases** satisfy the profile; **12** must be rejected. The expected benign
candidates model authorized AV/EDR reads. They deliberately remain matches and
must not be relabeled as negative cases or silently excluded by executable name.
Their synthetic benign labels describe the authored scenario, not independently
measured real-world ground truth. No production precision, TPR or FPR is derived
from this fixture collection.

The cases cover exact and additional-bit masks, query/write-only lookalikes,
Windows filename case, spoofed security basenames, a same-named non-system target,
PID reuse, host-scoped process GUIDs, repeated events, immutable duplicate retry,
conflicting IDs, deterministic ties and exact time bounds. Missing identities or
rights, malformed uint32 values, relative paths and nested field aliases are
errors rather than benign evidence.

`tests/test_lsass_fixtures.py` checks manual expectations and linked evidence.
The Elasticsearch Basic suite reuses these scenarios to check finite replay on
the actual engine. Fixtures do not establish collection completeness, validate a
live Sysmon deployment, authenticate image signatures or implement generic Hunt
DSL/Sigma equivalence.

Files under `native/` are separate synthetic XML exports used to test the Sysmon
normalizer. Their normalization timestamps use the declared `System/TimeCreated`
record time; no equivalence with operation-time `EventData/UtcTime` is assumed.
