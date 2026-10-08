# GyLiber Security Intruder
## Engineering Gap Register — Experienced-Practice Additions — v1.0.0

**Purpose:** Record engineering, security, operations, legal/IP and organizational considerations that are easy for a first-time product owner to miss, so they remain visible throughout GyLiber's growth.  
**Status:** Living document  
**Baseline date:** 2026-10-03  
**Last reviewed:** 2026-10-08 for v0.2.0 release candidate  

---

## 1. Why this document exists

A novice founder can specify the visible product correctly while still missing invisible operating requirements: key rotation, restore testing, dependency compromise, staff offboarding, security ownership, incident response, legal provenance, reproducible releases, cost limits, and similar controls.

Those omissions are normal unknown-unknowns, but a professional engineering process must externalize them before they become incidents.

**Release checkpoint:** v0.1.0 shipped on 2026-10-04. This register now distinguishes shipped controls from carry-forward governance and production-readiness gaps; release does not silently close an unevidenced control.

This register is therefore not a criticism of the product brief. It is the place where experienced-practice obligations are made explicit and later converted into requirements, ADRs, runbooks or company policy.

---

## 2. Security has no final “guaranteed secure” state

**Gap:** treating security as a one-time finish line.

**Professional control:** security claims are scoped to tested properties, versions, environments and dates. New code, dependencies, staff, infrastructure and attackers change the threat model.

**GyLiber rule:** never admit irreplaceable or high-consequence data solely because a version number has reached `3.0.0` (or any other number). Admission is based on explicit security/data gates: architecture review, backup/restore proof, access controls, vulnerability testing, logging, incident response and accepted residual risk.

---

## 3. The Intruder and Command Center need separate trust domains

**Gap:** thinking the security verifier should also hold the data it protects.

**Risk:** one compromise gains both the crown jewels and the tool/credentials used to test defenses.

**Control:** the Command Center owns business data and enforcement; the Intruder gets narrowly scoped, short-lived synthetic test capability and observes the result.

---

## 4. Public source code changes the threat model

**Gap:** public repository can be treated like private development with only secrets omitted.

**Additional risk:** architecture, routes, test cases and control assumptions may reveal how the product is defended.

**Controls:**

- keep environment-specific production detail out of public Git;
- store confidential findings/evidence outside the repository;
- examples use synthetic/reserved identifiers;
- assume Git history is permanent disclosure;
- explicitly decide what remains public after v1.0.0;
- do not rely on obscurity for security, but also do not publish unnecessary exploit-enabling operational detail.

---

## 5. Repository ownership is a security boundary

**Gap:** focusing on application security while leaving source-control administration weak.

**Controls:**

- passkey/hardware-backed MFA for owner accounts;
- recovery codes stored separately;
- protected `main`;
- no force-push;
- required CI;
- signed commits/tags where enforceable;
- CODEOWNERS;
- minimal GitHub App/OAuth permissions;
- regular review of installed GitHub Apps;
- no long-lived personal access token when a GitHub App/OIDC workflow can do the job.

Future staff should not all be organization owners.

---

## 6. CI is part of the production attack surface

**Gap:** treating GitHub Actions as “just automation.”

**Risk:** a compromised Action or malicious PR can steal secrets, alter artifacts or deploy backdoored code.

**Controls:**

- pin third-party Actions to full commit SHAs;
- minimal `GITHUB_TOKEN` permissions;
- separate build and deployment permissions;
- OIDC instead of static cloud keys;
- no deployment secret to untrusted PR runs;
- production environment approvals;
- artifact hashes and provenance;
- review workflow changes as security-sensitive code.

---

## 7. Dependency risk requires more than vulnerability scanning

**Gap:** assuming “no known CVE” means a dependency is safe.

**Controls:**

- lockfile;
- vulnerability audit;
- license/source allow/deny policy;
- minimize dependency count;
- review new maintainers/ownership for critical dependencies where practical;
- inspect network/crypto/parser dependencies more closely;
- consider dependency vetting for the highest-trust crates;
- generate an SBOM for releases;
- keep an emergency dependency-upgrade path.

---

## 8. Backup is not the same as provider durability

**Gap:** “the cloud provider stores multiple copies, therefore we have backups.”

**Risk:** account compromise, operator deletion, ransomware, provider control-plane error or bad application writes can affect all provider-managed copies.

**Controls:**

- separate independent provider/account copy;
- encryption before cross-provider archive when data is confidential;
- versioning/immutability where appropriate;
- backup credentials separated from normal application credentials;
- scheduled restore test;
- documented RPO/RTO.

The restore test is the proof.

---

## 9. Free infrastructure is a prototype constraint, not a production architecture

**Gap:** treating free tiers as equivalent to paid durability/availability.

**Controls:**

- use free compute only for low-risk bootstrap/staging where its limitations are acceptable;
- never make expiring/no-backup free databases authoritative for irreplaceable data;
- document provider limits;
- define the revenue/risk threshold that triggers paid migration;
- design export/migration paths before data becomes large.

---

## 10. Data must be classified before it is stored

**Gap:** storing information first and deciding its sensitivity later.

**Recommended GyLiber classes:** `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.

Examples of **RESTRICTED** future data:

- bank credentials or signing secrets;
- private keys;
- real production session tokens;
- staff identity/payroll records;
- sensitive client personal information;
- credentials to revenue systems.

The Intruder should generally never store raw RESTRICTED values.

---

## 11. Financial dashboards should not imply custody of bank credentials

**Gap:** a future real-time asset view can be misunderstood as requiring storage of bank usernames/passwords.

**Control direction for the Command Center:** use provider/bank APIs or financial-data integrations with narrowly scoped tokens; prefer read-only scopes; tokenize references; isolate payment/signing capabilities from read-only financial observation.

The Intruder should test those boundaries using synthetic accounts, not real money movement.

---

## 12. Secret management requires lifecycle, not an `.env` file policy

**Gap:** “do not commit `.env`” is necessary but insufficient.

A secret lifecycle includes:

1. generation;
2. storage;
3. distribution;
4. runtime access;
5. rotation;
6. revocation;
7. compromise response;
8. audit;
9. deletion.

Prefer no secret → short-lived credential → workload identity before permanent tokens.

---

## 13. Cryptographic keys need recovery and rotation design

**Gap:** choosing Ed25519 or TLS without deciding who holds keys and what happens if they are lost/compromised.

**Controls:**

- key purpose separation;
- key IDs;
- rotation windows;
- revocation list/state;
- offline/independent recovery for critical signing authority;
- no private key in Git, logs, issue trackers or AI prompts;
- documented transition from old to new signing key.

---

## 14. Audit logs must be designed against tampering and over-collection

**Gap:** logs can be both evidence and a secret-leak channel.

**Controls:**

- stable event IDs/codes;
- correlation IDs;
- append-oriented storage;
- hashes/immutability for high-value evidence;
- strict redaction;
- bounded body capture;
- retention periods;
- access audit;
- no raw Authorization/Cookie headers.

---

## 15. Incident response must exist before the first serious incident

**Gap:** writing an incident process during an attack.

Before production high-consequence data, define:

- who can declare an incident;
- kill/isolation actions;
- credential rotation order;
- forensic evidence preservation;
- communication path;
- recovery path;
- legal/customer notification decision ownership;
- post-incident review and regression test requirement.

The Intruder itself should have a compromise playbook.

---

## 16. A kill switch can itself be dangerous

**Gap:** assuming “more kill switches” is automatically safer.

**Risk:** a stolen kill credential becomes a denial-of-service control.

**Controls:**

- scope local/campaign/target/global separately;
- no permanent universal kill credential;
- require authorization appropriate to impact;
- log state transitions;
- auto-expire high-impact test containment;
- provide independent recovery path;
- test false-positive behavior.

---

## 17. Environment separation matters

**Gap:** one cloud project/account for development, staging and production.

**Future direction:** separate credentials and preferably separate projects/accounts for production boundaries. A staging compromise should not automatically grant production access.

At minimum:

- separate secrets;
- separate databases/buckets;
- separate target authorizations;
- explicit environment marker in every campaign/evidence item.

---

## 18. Migrations need rollback and compatibility policy

**Gap:** schema/config changes are easy while one developer controls everything, then become dangerous at scale.

**Controls:**

- version schemas;
- forward/backward compatibility rules;
- migration tests;
- backups before destructive migrations;
- downgrade/rollback plan where feasible;
- never silently reinterpret signed campaign/evidence data under a new schema.

---

## 19. Semantic versioning is not enough by itself

**Gap:** version numbers do not explain security compatibility.

Also track:

- campaign schema version;
- target-policy schema version;
- evidence schema version;
- defense adapter protocol version;
- minimum supported Command Center version;
- breaking security-policy changes.

---

## 20. SLO, RPO and RTO must eventually become numbers

**Gap:** “always available” and “never lose data” cannot be engineered literally.

Professional practice requires measurable targets, for example:

- SLO: service availability target;
- RPO: maximum tolerable data loss interval;
- RTO: maximum tolerable recovery time.

GyLiber should not choose expensive targets before its business need justifies them, but it must choose explicit targets before the system becomes livelihood-critical.

---

## 21. Cost is a security concern

**Gap:** cost control is treated only as finance.

**Security effect:** unexpected bills can cause suspended services, rushed migrations or disabled backups.

Controls:

- provider budgets/alerts;
- bounded security-test traffic;
- storage retention policy;
- no unbounded logs;
- no unbounded fuzzing against paid APIs;
- documented paid-upgrade trigger.

---

## 22. Copyright/IP requires provenance

**Gap:** writing original code is not the only IP issue.

Track:

- dependency licenses;
- copied snippets/templates and their licenses;
- generated assets;
- AI assistance statement;
- ownership of future employee/contractor work;
- trademarks/brand assets;
- third-party API terms.

`cargo-deny` or an equivalent license policy should block disallowed dependency licenses.

---

## 23. Trade secrets conflict with a public repository

**Gap:** a product may be public while the company wants methods to remain trade secrets.

**Control:** decide which knowledge is intentionally published and which stays in private operational documents/services. A trade secret that is voluntarily published cannot be protected by secrecy alone.

Security does not require source secrecy, but company IP strategy may.

---

## 24. Staff security becomes a system feature

Before adding staff:

- named individual accounts only;
- least privilege;
- MFA/passkeys;
- no shared passwords;
- role matrix;
- onboarding checklist;
- offboarding immediate revocation;
- device expectations;
- production access logging;
- confidential-data handling expectations;
- code-review separation for highest-risk changes.

A 6–10 developer team also needs CODEOWNERS and subsystem ownership to prevent “everyone owns everything.”

---

## 25. Security review needs independence

**Gap:** the same developer/system that built a control also declares it sufficient.

The Intruder improves independence, but it is still developed by GyLiber. Once finances and consequence justify it, commission an independent human security review/penetration test. Findings should become regression campaigns where safe.

---

## 26. Fuzzing must target parsers and boundaries, not production availability

**Gap:** “fuzzing” can be misapplied as uncontrolled live traffic.

**Control:** fuzz URL/campaign/policy/evidence parsers locally and in CI; production uses bounded, policy-approved mutation sets and health circuit breakers.

---

## 27. AI must never become a trust authority

**Gap:** because AI writes much of the code, it may implicitly be treated as a security reviewer/signatory.

**Control:** AI can propose and review; deterministic tests, cryptographic verification, CI, operator authorization and eventually independent human review establish evidence.

Do not provide AI systems standing production credentials or hidden administrative access.

---

## 28. “No Python” requires a tooling audit, not just source-code discipline

**Gap:** a Rust application can still depend operationally on Python-based helper scripts.

**GyLiber rule:** no Python in first-party build, runtime, deployment or test orchestration for this project unless a future explicit client-approved ADR reverses the rule.

Third-party hosted services may internally use any language; that is not part of the GyLiber stack, but their security posture remains a vendor-risk concern.

---

## 29. Release evidence should outlive the CI run

**Gap:** workflow logs/artifacts may expire.

For meaningful releases preserve:

- source commit/tag;
- checksums;
- SBOM;
- build provenance;
- test summaries;
- known limitations;
- sanitized security-assurance evidence;
- deployment target/revision;
- operator approval.

Copy high-value release dossiers to durable second-provider storage.

---

## 30. GitHub backup needs more than `git clone`

**Gap:** a clone may omit issues, releases, settings, Actions configuration state or other metadata.

Source recovery should at least preserve the full Git object graph (`git bundle`/mirror). Business-critical non-Git metadata should be exported/documented separately where needed. Disaster recovery must state what is and is not reconstructed.

---

## 31. Security findings require disclosure discipline

**Gap:** a public issue for a live vulnerability can create avoidable risk.

Controls:

- `SECURITY.md` private reporting route;
- confidential finding storage;
- remediation owner/deadline;
- regression test after fix;
- coordinated disclosure only when appropriate.

---

## 32. The Command Center needs a future data-retention policy

**Gap:** keeping all business data forever “just in case.”

Retention increases breach impact and backup cost. Future GyLiber policy should define retention/deletion rules for staff, client, financial, audit and security records, subject to legal obligations.

The Intruder's evidence retention should be separate and purpose-specific.

---

## 33. Provider concentration is a business-continuity risk

**Gap:** code, database, backups, identity and DNS all controlled by one provider/account.

Direction:

- source on GitHub;
- second-provider encrypted source/release archives;
- database backups copied outside the primary database provider;
- DNS/domain recovery documented;
- account recovery factors stored independently.

This is more important than deploying many databases or microservices.

---

## 34. Future compliance should follow actual business need

**Gap:** adding “bank-grade/compliance” labels before there is a legal/customer requirement.

Use standards as engineering guidance now (OWASP, NIST, CVSS, ATT&CK where appropriate). Adopt formal compliance programs only when the business/data/jurisdiction/customer contract requires them. Compliance and security overlap but are not the same thing.

---

## 35. Recommended living company-security documents

As GyLiber matures, maintain:

1. security policy;
2. data-classification standard;
3. access-control standard;
4. secret/key-management standard;
5. secure SDLC standard;
6. incident-response plan;
7. backup/disaster-recovery plan;
8. vulnerability-management policy;
9. vendor-risk register;
10. software/component inventory and SBOM archive;
11. staff onboarding/offboarding checklist;
12. risk-acceptance register;
13. IP/copyright/third-party license register;
14. AI-assisted engineering policy.

Do not create bureaucracy before it has an operational purpose, but do not leave high-consequence practices implicit.

---

## 36. v0.1.0 closure status and carry-forward controls

- [x] Threat model document — `docs/THREAT_MODEL.md`.
- [x] `SECURITY.md`.
- [x] `CONTRIBUTING.md` with conventional commits and security-sensitive change rules.
- [x] AI-assisted engineering disclosure/policy in README and requirements.
- [x] `CODEOWNERS` with initial repository ownership.
- [x] Dependency/license/source policy enforced through pinned `cargo-deny` in the Security workflow.
- [x] SHA-pinned Actions.
- [ ] Repository-level secret-scanning/push-protection configuration verified and evidenced — code alone cannot prove the GitHub setting.
- [x] SBOM, checksums, build-provenance attestation and binary-SBOM attestation for v0.1.0.
- [x] Safe fixture lab proving PASS/FAIL/PASS.
- [x] Disaster-recovery document — `docs/DISASTER_RECOVERY.md`; independent backup automation/restore proof remains open.
- [x] Explicit statement that real business/banking/staff data does not belong in the Intruder v0.1.0/v1.0 test-data posture.

**v0.2.0 update:** the dependency license/source policy gap is closed. Repository-level secret-scanning/push-protection verification and independent backup/restore evidence remain open; branch/ruleset protection also requires repository-administration action.

---

## 37. Deferred but mandatory before livelihood-critical production use

- [ ] Paid durable database with PITR for authoritative business data.
- [ ] Cross-provider encrypted backups.
- [ ] Restore-drill evidence.
- [ ] Quantified RPO/RTO and availability SLO.
- [ ] Managed secret/KMS strategy.
- [ ] Independent security review.
- [ ] Incident-response drill.
- [ ] Staff access/offboarding controls.
- [ ] Legal/privacy/retention review appropriate to actual jurisdictions/data.
- [ ] Account-recovery plan for domain, GitHub and cloud providers.
- [ ] Security monitoring/alert delivery with tested failure paths.

---

## 38. Governing principle

GyLiber should not imitate complexity associated with large banks merely because the data may one day be valuable. It should adopt the **control objectives** used by serious organizations—least privilege, isolation, reproducibility, defense in depth, secure supply chain, auditable change, tested recovery—and implement the simplest architecture that demonstrably satisfies those objectives at the current scale.

That produces a system that can grow without either amateur shortcuts or performative enterprise complexity.