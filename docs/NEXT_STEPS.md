# Next Implementation Steps

**Product:** GyLiber Security Intruder  
**Planning baseline:** after the 2026-10-03 end-to-end CLI milestone  
**Immediate objective:** complete the v0.1.0 closed-loop safety foundation

## 1. Next work session — primary implementation unit

The next substantive unit should be the **deterministic adversarial fixture laboratory**.

Required project fixtures:

```text
secure fixture      -> expected PASS
vulnerable fixture  -> expected FAIL
fixed fixture       -> expected PASS
```

The fixture laboratory must be synthetic, deterministic, locally runnable in CI, and incapable of depending on production GyLiber data.

### Acceptance criteria

The next unit is complete only when:

- secure, vulnerable, and fixed fixture states are represented in repository-controlled test infrastructure;
- the same baseline security contract is evaluated against all three;
- the vulnerable state generates the expected FAIL result;
- the corrected state returns to PASS;
- fixture execution remains within the existing Target Gate and budget controls;
- the behavior is reproducible in GitHub Actions;
- no external account or production target is required.

This is the highest-value next step because it proves that the Intruder detects a deliberately introduced control failure rather than merely producing reports.

## 2. Following unit — formal target and campaign contracts

Promote the current internal execution-spec concept into stable v0.1.0 configuration contracts.

Planned work:

- versioned target schema;
- versioned campaign schema;
- canonical campaign/test identifiers;
- strict unknown-field rejection;
- validation of target/campaign relationship;
- validation of approved probe types and budgets;
- machine-readable schema files under repository control;
- operator commands aligned with the intended interface:

```text
intruder target validate <target-file>
intruder campaign validate <campaign-file>
intruder campaign plan <campaign-file>
intruder run <campaign-file-or-id>
```

The current `baseline-run` command is an intentionally narrow bridge to this stable campaign interface, not the final CLI contract.

## 3. Evidence bundle and report operations

After campaign contracts are stable:

- define a run-directory/bundle layout;
- include run ID, target ID, campaign ID/version, tool version, and source commit;
- emit sealed JSON evidence and human report together;
- refuse silent overwrite of prior evidence;
- add deterministic manifest/checksum generation;
- document retention and redaction behavior;
- keep all v0.1.0 fixtures synthetic.

Durable external evidence storage is not required for the first fixture release, but its future trust boundary must be documented before real GyLiber evidence is admitted.

## 4. v0.1.0 release engineering

Before tagging v0.1.0:

- add a release workflow using immutable action revisions;
- build release binaries from the pinned Rust toolchain;
- produce checksums;
- produce an SBOM where supported by the adopted tooling;
- generate build provenance/attestation where supported;
- document known limitations;
- document authorized-use boundaries;
- create a v0.1.0 release evidence dossier;
- validate that source and release artifacts are recoverable independently of a developer laptop.

## 5. v0.1.0 exit criteria

v0.1.0 should not be tagged until all of these are true:

- secure fixture → PASS;
- vulnerable fixture → FAIL;
- fixed fixture → PASS;
- arbitrary-target execution remains unavailable through the normal CLI;
- tested target-boundary escape attempts are denied;
- request/concurrency/rate/time budgets are enforced;
- kill-switch behavior is fail-closed;
- evidence contains no prohibited response bodies/header values;
- evidence integrity verification detects tampering;
- JSON and human reports are produced deterministically enough for the defined contract;
- CI passes formatting, compile, Clippy, and all tests;
- Security passes dependency audit and CodeQL;
- release artifacts/checksums are generated through CI;
- documentation states what was and was not tested;
- no production GyLiber secret or real client data is required.

## 6. Deferred work after v0.1.0

The current roadmap remains capability-gated.

### v0.2.0 — integrity/authenticity

Primary themes:

- signed target and campaign records;
- signer trust model and key rotation;
- canonical serialization;
- anti-replay/rollback controls;
- signed evidence/report manifests.

### v0.3.0 — authentication/session assurance

Primary themes:

- synthetic identities;
- bounded authentication flows;
- session expiry/revocation checks;
- throttling/lockout verification.

### v0.4.0 and later

Subsequent versions expand authorization/API assurance, detection correlation, containment/recovery, safe adversarial coverage, durability/continuous assurance, and final v1.0.0 hardening.

## 7. External dependencies / client actions

No new external service account is required for the immediate fixture-laboratory work.

Before durable real-world evidence, persistent deployment, or production-target execution is introduced, GyLiber will need explicit decisions on:

- private durable evidence/object storage;
- independent backup provider;
- production authorization and environment ownership;
- signing-key custody;
- access-control/identity provider;
- alert/detection integration.

Those decisions are intentionally deferred so that v0.1.0 can prove the safety model without introducing unnecessary credentials or infrastructure.

## 8. Recommended next commit sequence

The next implementation work should remain incremental. A likely sequence is:

```text
test(fixtures): add deterministic baseline fixture service
test(fixtures): prove vulnerable and fixed control states
feat(campaign): define versioned target and campaign contracts
feat(cli): validate and plan baseline campaigns
feat(cli): execute campaign contract end to end
docs: document v0.1.0 operations and fixture evidence
ci(release): add v0.1.0 release evidence pipeline
chore(release): prepare v0.1.0
```

Commit boundaries may change when implementation evidence requires it; correctness of each unit remains more important than preserving a prewritten sequence.
