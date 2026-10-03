# GyLiber Security Intruder
## Requirements Register, Delivery Checklist & Contract Controls — v1.0.0

**Document status:** Implementation control document  
**Document version:** 1.0.0  
**Baseline date:** 2026-10-03  
**Owner/client:** Gyile / GyLiber  
**Engineering executor:** GyLiber Engineering with AI-assisted implementation  
**Source design:** `GyLiber-Security-Intruder-Design-v1.0.0.md` (approved baseline dated 2026-10-01)  
**Companion product:** `GyLiber/gyliber-command-center`  

---

## 1. Purpose

This register captures every explicit requirement in the 2026-10-03 client brief, the obligations implied by those requirements, and the implementation gates that must be satisfied before the project may be described as professionally delivered.

This is a living contract-control document. Requirements may be refined as implementation reveals new facts, but they must not silently disappear. A requirement that changes must be marked **superseded**, with the reason and replacement recorded in an ADR or change record.

---

## 2. Non-negotiable scope distinction

The approved design defines **GyLiber Security Intruder** as an authorized adversarial security-assurance system for GyLiber-owned systems. It is **not** the Command Center itself, a banking datastore, a staff-record system, or a vault for production business data.

Accordingly:

- v1.0.0 of the Intruder uses **synthetic/security-test data only**;
- the Intruder must not hold real client passwords, copied browser cookies, production session tokens, database master credentials, or a permanent “security master key”;
- the Command Center remains authoritative for business data, authentication, authorization, containment, and recovery;
- the Intruder verifies those controls and records sanitized evidence;
- future Command Center versions may hold highly sensitive GyLiber information, but that does not make the Intruder the owner of that information.

This separation is itself a security control and must not be weakened for convenience.

---

## 3. Security claim policy

### R-SEC-000 — No absolute-security claim

No programming language, framework, hosting provider, AI system, test suite, or security architecture can guarantee that a system is impossible to breach.

The engineering objective is instead to:

1. minimize classes of preventable vulnerability;
2. make trust boundaries explicit;
3. fail closed;
4. continuously test defined security properties;
5. detect and contain failures;
6. preserve reproducible evidence;
7. recover safely;
8. maintain independent backups and restore capability.

**Decision:** Rust is the primary implementation language because it materially reduces memory-safety risk and supports explicit, strongly typed security boundaries. Rust does not replace threat modeling, access control, secret management, secure deployment, code review, or independent testing.

---

## 4. Explicit client requirements traceability

| ID | Requirement | v0.1.0 treatment | v1.0.0 obligation | Status |
|---|---|---|---|---|
| R-001 | Design for indefinite extension beyond v1.0.0 | Stable domain types, modular boundaries, versioned schemas, ADRs | Backward-compatible extension policy and semver | OPEN |
| R-002 | Use the most security-capable suitable language; no Python | Rust only for first-party executable product code | Rust remains primary unless an ADR proves a safer need | DECIDED |
| R-003 | Treat work as professional client delivery | Requirements register, ADRs, runbooks, acceptance gates | Full delivery evidence and release dossier | IN PROGRESS |
| R-004 | Security from project inception | Target Gate, fail-closed policies, secret hygiene, CI scanning | Complete self-security acceptance matrix | IN PROGRESS |
| R-005 | Automated testing from inception | Unit + integration + safety fixture tests | Unit, property, integration, fixture, fuzz, live-assurance layers | IN PROGRESS |
| R-006 | CI/CD from inception | GitHub Actions CI and security workflows | Release, provenance, deployment and scheduled assurance workflows | IN PROGRESS |
| R-007 | Free hosting initially; paid upgrade later | Prefer ephemeral GitHub-hosted execution; no unnecessary public service | Supported paid runner/storage migration plan | DECIDED |
| R-008 | All important project resources survive laptop loss | GitHub is canonical source; CI and release artifacts online | Cross-provider encrypted backups and restore drills | OPEN |
| R-009 | Account for provider/server loss | Backup architecture specified from start | Tested recovery from independent provider copies | OPEN |
| R-010 | Conventional Commits | Enforced by contributor process/CI where practical | Required release history discipline | DECIDED |
| R-011 | Professional rich README and docs | README is part of initial repository tranche | README, security model, operations, contribution and AI statement complete | OPEN |
| R-012 | Public repository until v1.0.0 | No secrets, internal credentials, sensitive target configuration, or confidential evidence in Git | Safe private-repo transition plan at/around v1.0.0 | OPEN |
| R-013 | v0.1.0 must be working end-to-end | Authorized target → safe probe → assertion → evidence → report; secure and vulnerable fixture tests | Later versions extend this closed loop | OPEN |
| R-014 | Scale to ~6–10 professional developers later | Clear crate/module ownership and CODEOWNERS-ready structure | Team ownership, review and release governance | OPEN |
| R-015 | Unique to GyLiber without abandoning industry practice | GyLiber-specific assurance vocabulary, Command Center adapter, evidence model | Brand-specific product experience, standards-mapped internals | OPEN |
| R-016 | Incremental correct commits | Small verified units, no “mega commit” | Release history remains auditable | OPEN |
| R-017 | Correct earlier work when new facts invalidate it | Fix/refactor/revert accepted and documented | ADR supersession process | DECIDED |
| R-018 | Design document may change during implementation | Baseline + ADRs + change log; no silent divergence | Current design generated from implementation truth | DECIDED |
| R-019 | Use current, non-deprecated 2026 components | Version checks at implementation time; lockfile committed | Automated dependency/update policy | IN PROGRESS |
| R-020 | Calm dark/silver/dark-blue visual direction | No public web UI required for v0.1; static reports may adopt this direction | Any future operator console follows the GyLiber visual direction | DEFERRED |
| R-021 | Use as many databases as necessary | Do not add a DB without a durable-data requirement | Multiple stores allowed only where threat/consistency model justifies them | DECIDED |
| R-022 | Notify client when external accounts become required | Account dependency register below | No hidden vendor dependency | OPEN |
| R-023 | Protect financial, trade-secret, copyright, staff and future sensitive information | Intruder never ingests raw forms of these classes in v1.0 | Command Center data architecture handles them; Intruder uses synthetic references | DECIDED |
| R-024 | AI-developed code must not create hidden access for the AI provider | No AI credentials/runtime backdoor; all auth material externally managed | Reproducible builds and operator-controlled secrets | OPEN |

---

## 5. Implicit requirements created by the client brief

### 5.1 Identity and access governance

- [ ] MFA/passkeys enabled on GitHub and every infrastructure account.
- [ ] No shared staff accounts when GyLiber grows.
- [ ] Least-privilege roles documented for owner, maintainer, security reviewer, deployment bot and read-only auditor.
- [ ] Break-glass access is separately controlled, logged and rotated.
- [ ] Service credentials are short-lived where provider support exists.
- [ ] Production deployments use workload identity/OIDC instead of static cloud keys where possible.
- [ ] Joiner/mover/leaver process exists before staff access is granted.

### 5.2 Repository governance

- [ ] `main` is protected by ruleset/branch protection.
- [ ] Force pushes and branch deletion are blocked for protected branches.
- [ ] Required CI checks are configured.
- [ ] Signed commits/tags are required when the account plan supports enforcement.
- [ ] `CODEOWNERS` protects security-sensitive paths and protects itself.
- [ ] Pull-request review becomes mandatory once a second trusted maintainer exists.
- [ ] GitHub Actions are pinned to immutable full-length commit SHAs.
- [ ] Workflow `GITHUB_TOKEN` permissions default to read-only and are elevated per job only.
- [ ] `pull_request_target` with untrusted checkout is prohibited.
- [ ] Repository secrets are never exposed to forked/untrusted PR code.

### 5.3 Software supply-chain security

- [ ] `Cargo.lock` committed.
- [ ] Dependency vulnerability audit runs in CI.
- [ ] Dependency allow/deny and license policy runs in CI.
- [ ] Dependency changes are reviewable and automated updates are rate-limited.
- [ ] SBOM generated for releases.
- [ ] Release artifacts have hashes.
- [ ] Build provenance/artifact attestations are generated where available.
- [ ] Third-party GitHub Actions are SHA-pinned.
- [ ] Unsafe Rust is denied by default; exceptions require an ADR/security review.
- [ ] New network-capable dependencies receive explicit security review.

### 5.4 Data classification

The following classes exist even if the Intruder must not store their raw values:

| Class | Examples | Intruder v1.0 treatment |
|---|---|---|
| PUBLIC | Published docs, public release metadata | May store |
| INTERNAL | Non-sensitive test plans, synthetic campaign metadata | May store with access control |
| CONFIDENTIAL | Security weaknesses, internal architecture, trade secrets | Redacted/minimized; encrypted durable evidence |
| RESTRICTED | Banking credentials, secrets, real session tokens, personal/staff data, private keys | Must not be ingested/stored by Intruder; record only sanitized indicator/reference |

### 5.5 Cryptography and key management

- [ ] No custom cryptographic algorithms.
- [ ] TLS via `rustls`-based stack where applicable.
- [ ] Campaign/authorization signing uses a reviewed Ed25519 implementation or equivalent approved mechanism.
- [ ] Private signing keys never enter the repository.
- [ ] Key identifiers and rotation policy are versioned.
- [ ] Confidential evidence supports client-side encryption before cross-provider backup.
- [ ] Key-loss and key-compromise recovery are documented separately.

### 5.6 Backup and disaster recovery

For **source and release materials** from the first milestone:

- [ ] Canonical Git repository on GitHub.
- [ ] Immutable release archive + checksums on GitHub Releases.
- [ ] Periodic encrypted `git bundle`/release backup to a second provider.
- [ ] Restore procedure tested, not merely documented.

Before **irreplaceable real GyLiber data** is ever admitted to the Command Center:

- [ ] Primary database has automated backups and point-in-time recovery.
- [ ] Encrypted logical backups are copied to an independent provider/account.
- [ ] Object evidence/storage has versioning or immutable retention where supported.
- [ ] RPO and RTO are explicitly accepted by Gyile/GyLiber.
- [ ] Restore tests are scheduled and evidenced.
- [ ] A single cloud account compromise cannot delete every copy without a separately protected recovery path.

### 5.7 Observability and audit

- [ ] Structured logs have stable event codes.
- [ ] Secrets and sensitive headers are redacted before logging.
- [ ] Audit events are append-oriented and integrity checked.
- [ ] Correlation IDs link campaign, run, target, request and security event.
- [ ] Security telemetry is not used as a hidden authorization source.
- [ ] Alerting failures are distinguishable from prevention failures.

### 5.8 Operational security

- [ ] Kill switches are implemented and tested before aggressive probes.
- [ ] Safety budgets are centrally enforced.
- [ ] Target authorization expires and fails closed.
- [ ] Redirect/DNS rebinding/private-network protections are tested.
- [ ] Production campaigns cannot be silently escalated from low-impact to high-impact behavior.
- [ ] System-wide containment exercise requires explicit arming and auto-expiry.

### 5.9 Legal/IP/copyright controls

- [ ] Repository license is deliberately selected; do not default casually for a proprietary security product.
- [ ] Third-party dependency licenses are inventoried and policy checked.
- [ ] AI-assisted contributions are acknowledged transparently without assigning security responsibility to AI.
- [ ] Copyright headers/NOTICE policy is selected before external contributors exist.
- [ ] Future staff/contractor IP-assignment and confidentiality terms are handled outside Git.
- [ ] Vulnerability disclosure process and `SECURITY.md` are present before public release.

### 5.10 AI-assisted engineering controls

- [ ] No production secret, private key, bank credential or real session token is pasted into AI prompts.
- [ ] AI output is treated as untrusted code requiring tests/review.
- [ ] AI does not receive standing production credentials.
- [ ] No product authentication path trusts an AI identity.
- [ ] README records meaningful AI assistance accurately.
- [ ] Release evidence is generated by deterministic tooling, not by an AI assertion.

---

## 6. Account and vendor dependency register

| Service/account | Needed | Blocking point | Security posture | Current decision |
|---|---|---|---|---|
| GitHub | Yes | Repository initialization | MFA/passkey, protected `main`, minimal Actions permissions | Required now |
| Existing GyLiber deployment provider (currently used by Command Center) | Later | Only if a persistent hosted Intruder control service becomes justified | Separate service identity; no master credentials | Not required for initial CLI/CI v0.1 |
| Cloudflare account / R2 private bucket | Recommended | Durable cross-provider evidence/source backup | Private bucket, scoped token, client-side encryption for confidential archives | Required before treating online evidence as durable |
| Paid durable PostgreSQL provider | Not yet | When durable campaign/trend metadata becomes a product requirement | PITR, backups, TLS, least privilege, separate roles | Defer; do not add DB for appearance |
| Domain/DNS provider | Later | If an operator console/API gets a public hostname | MFA, DNSSEC where supported, restricted API tokens | No new account needed if GyLiber domain already exists |
| Error-monitoring SaaS | No | N/A | Avoid unnecessary third-party data flow initially | Do not add in v0.1 |

**Important:** a free Render PostgreSQL database is not acceptable as the sole store for irreplaceable data because the current free service expires and lacks backups. Prototype compute may be free; authoritative data requires a different durability posture.

---

## 7. Public-repository controls through v1.0.0

Because the client requires the repository to remain public until v1.0.0:

- [ ] Assume every committed byte is permanently public even after deletion.
- [ ] Never commit real target credentials, internal-only URLs that reveal sensitive topology, tokens, signing keys, private evidence, staff information, bank information or trade-secret payloads.
- [ ] `.env` and local secret files are ignored.
- [ ] Example configs contain only reserved/example domains and synthetic identifiers.
- [ ] Secret scanning runs before merge.
- [ ] Commit history is not used as a secret store.
- [ ] Security findings from live GyLiber targets are stored outside the public repository.
- [ ] Public documentation describes controls without publishing exploitable production secrets.

---

## 8. v0.1.0 minimum end-to-end contract

v0.1.0 is accepted only when a real executable can perform this closed loop:

```text
signed/approved local test target definition
        ↓
Target Gate validates destination + safety budget
        ↓
safe baseline request through the only network boundary
        ↓
assertion/oracle evaluates result
        ↓
redacted evidence record produced
        ↓
evidence hash calculated
        ↓
machine-readable report + human report produced
        ↓
secure fixture passes
vulnerable fixture fails with the expected finding
        ↓
CI reproduces both outcomes deterministically
```

### v0.1.0 acceptance checklist

- [ ] Rust workspace builds on stable pinned toolchain policy.
- [ ] CLI has no arbitrary `scan <url>` execution path.
- [ ] Target registry format exists and rejects unknown targets.
- [ ] Target Gate blocks off-policy redirects and disallowed network classes in internet mode.
- [ ] Request/time/concurrency budget primitive exists.
- [ ] Kill-switch primitive exists and is tested.
- [ ] At least one baseline HTTP/security-header probe exists.
- [ ] Evidence redaction + SHA-256 hashing exists.
- [ ] JSON report exists.
- [ ] Human-readable report exists.
- [ ] Secure fixture expected PASS.
- [ ] Deliberately vulnerable fixture expected FAIL.
- [ ] CI runs format, build, lint and tests.
- [ ] Security workflow runs dependency/license/secret/code analysis appropriate to a public Rust repository.
- [ ] README explains scope, safety model, AI use, non-goals and authorized-use restriction.
- [ ] Changelog begins at `0.1.0`.
- [ ] No secret is required to run fixture tests.

---

## 9. Planned version gates to v1.0.0

| Version | Primary delivery gate |
|---|---|
| 0.1.0 | Trust/safety foundation + first complete fixture/evidence/report loop |
| 0.2.0 | Signed target/campaign integrity + stronger policy engine |
| 0.3.0 | Authentication/session assurance profile |
| 0.4.0 | Authorization/API assurance profile |
| 0.5.0 | Detection-event correlation and audit verification |
| 0.6.0 | Synthetic containment + recovery verification |
| 0.7.0 | Safe SSRF canaries, business-logic scenarios, bounded fuzz/input suite |
| 0.8.0 | Scheduling, trend metadata, durable evidence replication and restore drill |
| 0.9.0 | Self-security hardening, fuzzing, network-escape tests, release-candidate operations |
| 1.0.0 | Full approved acceptance matrix, Command Center staging exercise, bounded authorized production exercise, complete docs/operations dossier |

Version numbers may change if implementation evidence warrants it. The security gates, not the numbering itself, are authoritative.

---

## 10. Definition of professional completion

A feature is not “done” merely because it compiles or works once. A completed security-sensitive change must normally include:

- [ ] implementation;
- [ ] negative-path behavior;
- [ ] automated tests;
- [ ] logging/evidence behavior;
- [ ] secret/redaction review;
- [ ] documentation update;
- [ ] changelog/release impact decision;
- [ ] threat-model or ADR update if a trust boundary changed;
- [ ] CI green;
- [ ] conventional commit representing one coherent unit of work.

---

## 11. Change-control rule

When new implementation facts make an earlier decision wrong, the correct action is to change it. The project will use:

- ADR status: `proposed → accepted → superseded/deprecated`;
- conventional commits (`fix:`, `refactor:`, `revert:`, `docs:`, `security:` only if configured as an allowed type, etc.);
- changelog entries for externally material behavior;
- migration notes for schema/config changes;
- no preservation of a bad decision merely to keep history aesthetically clean.

---

## 12. Client-held decisions still required later

These are intentionally **not blockers for repository initialization**, but must be resolved before the corresponding security boundary becomes real:

- [ ] exact repository name (three candidates supplied with the implementation handoff);
- [ ] proprietary/open-source licensing posture;
- [ ] date/criteria for changing repository visibility from public to private;
- [ ] Cloudflare account/R2 bucket creation for second-provider durable archives;
- [ ] accepted RPO/RTO before production business data is stored in Command Center;
- [ ] budget threshold that triggers paid durable database and paid runner infrastructure;
- [ ] future staff access roles and review requirements;
- [ ] independent human penetration-test/review cadence after the project begins handling high-consequence real data.

---

## 13. Sign-off model

For each tagged release, retain:

```text
release version
source commit SHA
CI run IDs
security scan results
SBOM hash
binary/container digest (if any)
evidence/report schema version
known limitations
accepted residual risks
operator approval
```

This creates a defensible chain from requirement → code → test → artifact → deployment → evidence.