# Next Implementation Steps

**Product:** GyLiber Security Intruder  
**Planning baseline:** after v0.1.0 closed-loop safety foundation  
**Immediate objective:** v0.2.0 — integrity and authenticity

## 0. Post-v0.1.0 governance closure before broader attack capability

Before materially expanding the Intruder's adversarial surface, close or explicitly accept these carry-forward controls:

1. add a dependency license/source allow/deny policy (for example `cargo-deny`) and run it in CI;
2. verify/enable GitHub secret scanning and push protection for the public repository, and record the setting as governance evidence;
3. verify GitHub branch/ruleset protection and required CI/Security checks from repository administration; document any plan limitations;
4. create an encrypted independent source/release backup outside the primary GitHub account/provider and perform a restore drill;
5. record the accepted RPO/RTO for source/release recovery;
6. define signing-key custody, rotation and revocation ownership before v0.2.0 signed authorization is allowed to become operational.

These are not reasons to reopen v0.1.0; they are explicit prerequisites for increasing trust and operational consequence.

## 1. v0.2.0 primary implementation unit

The next release should add a cryptographic trust layer around the configuration and evidence contracts already proven in v0.1.0.

The primary implementation sequence is:

1. define canonical serialization for signed target and campaign documents;
2. add signer/key identifiers and explicit signature envelopes;
3. verify Ed25519 signatures before target/campaign authorization;
4. define key-rotation and revocation semantics;
5. add expiry/not-before and anti-replay/rollback controls;
6. sign run-bundle manifests so integrity can be tied to an authenticated signer, not only a SHA-256 digest;
7. add negative fixtures for invalid signatures, stale signatures, wrong signer, rollback, and tampered manifests;
8. publish v0.2.0 only after the same CI/Security/release evidence gates used by v0.1.0 remain green.

v0.1.0 deliberately stops short of this trust layer: its evidence hashes provide integrity detection but not signer identity.

## 2. Trust model decisions required before production authorization

Before v0.2.0 is allowed to authorize non-fixture targets, GyLiber must document:

- who may sign target enrollments;
- who may sign campaigns;
- whether the same key class may sign both;
- key custody and backup;
- rotation frequency and emergency revocation;
- acceptable signature age and execution window;
- behavior when revocation/authorization state cannot be verified.

The implementation must fail closed when those answers are unavailable or ambiguous.

## 3. v0.3.0 — authentication and session assurance

After v0.2.0 establishes signed authorization, the next capability gate is synthetic authentication/session testing:

- synthetic identities only;
- bounded login attempts;
- throttling/lockout verification;
- session expiry;
- session revocation;
- logout invalidation;
- replay resistance where applicable;
- no real employee/client credentials.

## 4. Later release gates

Subsequent minor releases should continue the existing capability-gated roadmap:

- authorization/API boundary assurance;
- detection correlation;
- containment and recovery verification;
- safe adversarial fixture expansion;
- scheduled continuous assurance;
- durable confidential evidence storage and restore testing;
- production Command Center profiles only after explicit authorization and environment ownership are established;
- final v1.0.0 hardening and acceptance evidence.

## 5. Infrastructure and account decisions

No new external account is required to begin v0.2.0 fixture-based signing work.

Before real-world durable evidence or production-target authorization, GyLiber will need explicit decisions for:

- private durable evidence/object storage;
- independent backup provider;
- signing-key custody;
- workload identity/access control;
- production authorization ownership;
- alert/detection integration.

These are intentionally not smuggled into v0.1.0 as hidden infrastructure dependencies.

## 6. Recommended next commit sequence

A likely next sequence is:

```text
feat(signing): define canonical signed document envelope
feat(signing): verify target and campaign signatures
test(signing): reject stale wrong-signer and tampered documents
feat(evidence): sign run bundle manifest
test(evidence): prove signed manifest tamper detection
docs: document key custody rotation and revocation
ci(release): extend release evidence for signed artifacts
chore(release): prepare v0.2.0
```

Commit boundaries may change when implementation evidence requires it; the fail-closed trust model remains authoritative.
