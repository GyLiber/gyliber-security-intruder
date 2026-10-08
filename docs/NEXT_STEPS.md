# Next Implementation Steps

**Product:** GyLiber Security Intruder  
**Planning baseline:** after v0.2.0 integrity/authenticity release  
**Immediate product objective:** v0.3.0 — synthetic authentication and session assurance

## 0. Manual/governance controls that remain outside automated repository access

These do not block the synthetic/LAB v0.2.0 release, but must remain explicit:

1. verify or enable GitHub secret scanning and push protection for the public repository;
2. configure and verify branch/ruleset protection with required CI/Security checks;
3. create an encrypted independent source/release backup outside the primary GitHub account/provider;
4. perform and record a restore drill;
5. accept explicit source/release RPO and RTO values;
6. select production signing-key custody technology and ownership before any non-fixture target authorization.

No production target or confidential evidence should be admitted merely because v0.2.0 exists.

## 1. v0.3.0 primary implementation unit

The next minor release should add **synthetic authentication/session assurance** while preserving all v0.2 trust and safety gates.

The initial capability target is:

- synthetic identities only;
- bounded login attempts;
- explicit authentication-attempt budget consumption;
- expected success/failure oracle;
- throttling/lockout verification where the target profile declares it;
- session creation and expiry checks;
- logout/session invalidation checks;
- no credential stuffing, password cracking, or real employee/client credentials.

Every authentication campaign remains target-enrolled, signed, budgeted, kill-switch controlled, and evidence-authenticated.

## 2. Before production Command Center testing

GyLiber must still define:

- production/staging ownership and authorization;
- workload identity between the Intruder and Command Center;
- synthetic test-account lifecycle;
- detection/alert correlation;
- evidence retention and confidential storage;
- production kill/containment authority;
- key custody, rotation, backup, and emergency revocation;
- independent backup and restore evidence.

## 3. Later release gates

After v0.3.0, continue capability-gated development:

- v0.4.x: authorization/API boundary assurance;
- later minors: detection correlation and containment/recovery verification;
- safe adversarial fixture expansion;
- scheduled continuous assurance;
- confidential durable evidence storage with restore tests;
- production Command Center profiles only after explicit authorization;
- final v1.0.0 hardening and acceptance evidence.

## 4. Recommended next commit sequence

```text
feat(auth): define synthetic authentication campaign contract
feat(auth): enforce authentication attempt budgets
feat(auth): add session lifecycle oracle
test(auth): prove success failure lockout and expiry cases
feat(evidence): record redacted authentication/session metadata
docs(auth): document synthetic identity and session boundaries
ci(release): extend release evidence for authentication assurance
chore(release): prepare v0.3.0
```

Commit boundaries may change when implementation evidence requires it. The fail-closed target/signature/budget model remains authoritative.
