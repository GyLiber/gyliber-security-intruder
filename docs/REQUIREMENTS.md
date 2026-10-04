# GyLiber Security Intruder
## Requirements Register, Delivery Checklist & Contract Controls — v1.0.0

**Document status:** Implementation control document  
**Document version:** 1.0.0  
**Baseline date:** 2026-10-03  
**Last reviewed:** 2026-10-04 after successful v0.1.0 release  
**Owner/client:** Gyile / GyLiber  
**Engineering executor:** GyLiber Engineering with AI-assisted implementation  
**Source design:** [`docs/DESIGN.md`](DESIGN.md) — approved v1.0.0 baseline dated 2026-10-01  
**Companion product:** `GyLiber/gyliber-command-center`  

---

## 1. Purpose

This register captures every explicit requirement in the 2026-10-03 client brief, the obligations implied by those requirements, and the implementation gates that must be satisfied before the project may be described as professionally delivered.

This is a living contract-control document. Requirements may be refined as implementation reveals new facts, but they must not silently disappear. A requirement that changes must be marked **superseded**, with the reason and replacement recorded in an ADR or change record.

**v0.1.0 closure:** released 2026-10-04 as tag `v0.1.0` at commit `b98e0a29864c70db3abc9ed023d33446d426fb89`. Status values such as **SATISFIED FOR v0.1**, **PARTIAL**, and **IN PROGRESS** distinguish shipped evidence from obligations that remain on the path to v1.0.0.

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
| R-001 | Design for indefinite extension beyond v1.0.0 | Stable domain types, modular boundaries, versioned schemas, ADRs | Backward-compatible extension policy and semver | IN PROGRESS |
| R-002 | Use the most security-capable suitable language; no Python | Rust only for first-party executable product code | Rust remains primary unless an ADR proves a safer need | DECIDED |
| R-003 | Treat work as professional client delivery | Requirements register, ADRs, runbooks, acceptance gates | Full delivery evidence and release dossier | IN PROGRESS |
| R-004 | Security from project inception | Target Gate, fail-closed policies, secret hygiene, CI scanning | Complete self-security acceptance matrix | IN PROGRESS |
| R-005 | Automated testing from inception | Unit + integration + safety fixture tests | Unit, property, integration, fixture, fuzz, live-assurance layers | IN PROGRESS |
| R-006 | CI/CD from inception | GitHub Actions CI and security workflows | Release, provenance, deployment and scheduled assurance workflows | IN PROGRESS |
| R-007 | Free hosting initially; paid upgrade later | Prefer ephemeral GitHub-hosted execution; no unnecessary public service | Supported paid runner/storage migration plan | DECIDED |
| R-008 | All important project resources survive laptop loss | GitHub is canonical source; CI and release artifacts online | Cross-provider encrypted backups and restore drills | PARTIAL |
| R-009 | Account for provider/server loss | Backup architecture specified from start | Tested recovery from independent provider copies | OPEN |
| R-010 | Conventional Commits | Enforced by contributor process/CI where practical | Required release history discipline | DECIDED |
| R-011 | Professional rich README and docs | README, operations, security, release dossier, threat model and AI disclosure exist | Keep docs synchronized through v1.0.0 | SATISFIED FOR v0.1 |
| R-012 | Public repository until v1.0.0 | Public-safe synthetic fixtures/configuration only | Safe private-repo transition plan at/around v1.0.0 | IN PROGRESS |
| R-013 | v0.1.0 must be working end-to-end | Versioned target/campaign → gated probe → PASS/FAIL → sealed evidence → checksummed run bundle; PASS/FAIL/PASS fixtures | Later versions extend this closed loop | SATISFIED FOR v0.1 |
| R-014 | Scale to ~6–10 professional developers later | Clear crate/module ownership plus CODEOWNERS | Team ownership, review and release governance | IN PROGRESS |
| R-015 | Unique to GyLiber without abandoning industry practice | GyLiber-specific assurance vocabulary and evidence/release model | Command Center adapters and standards-mapped profiles | IN PROGRESS |
| R-016 | Incremental correct commits | Small verified conventional commits with CI-gated corrections | Maintain this discipline through v1.0.0 | SATISFIED FOR v0.1 |
| R-017 | Correct earlier work when new facts invalidate it | Fix/refactor/revert accepted and documented | ADR supersession process | DECIDED |
| R-018 | Design document may change during implementation | Baseline + ADRs + change log; no silent divergence | Current design generated from implementation truth | DECIDED |
| R-019 | Use current, non-deprecated 2026 components | Version checks at implementation time; lockfile committed | Automated dependency/update policy | IN PROGRESS |
| R-020 | Calm dark/silver/dark-blue visual direction | No public web UI required for v0.1; static reports may adopt this direction | Any future operator console follows the GyLiber visual direction | DEFERRED |
| R-021 | Use as many databases as necessary | Do not add a DB without a durable-data requirement | Multiple stores allowed only where threat/consistency model justifies them | DECIDED |
| R-022 | Notify client when external accounts become required | v0.1.0 required no new external account beyond GitHub; future dependencies are registered | No hidden vendor dependency | SATISFIED TO DATE |
| R-023 | Protect financial, trade-secret, copyright, staff and future sensitive information | Intruder never ingests raw forms of these classes in v1.0 | Command Center data architecture handles them; Intruder uses synthetic references | DECIDED |
| R-024 | AI-developed code must not create hidden access for the AI provider | No AI runtime identity/standing production credential; deterministic release evidence | Preserve operator-controlled credentials and reproducible gates | SATISFIED FOR v0.1 |

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
- [x] `CODEOWNERS` exists and assigns initial ownership; team-specific ownership must expand when additional maintainers join.
- [ ] Pull-request review becomes mandatory once a second trusted maintainer exists.
- [x] GitHub Actions are pinned to immutable full-length commit SHAs.
- [x] Workflow `GITHUB_TOKEN` permissions default to read-only and are elevated per job only.
- [x] Repository workflows do not use `pull_request_target`.
- [ ] Repository secrets are never exposed to forked/untrusted PR code.

### 5.3 Software supply-chain security

- [x] `Cargo.lock` committed.
- [x] RustSec dependency vulnerability audit runs in CI/Security.
- [ ] Dependency allow/deny and license policy runs in CI.
- [x] Dependabot opens bounded weekly Cargo and GitHub Actions update pull requests.
- [x] CycloneDX SBOM generated for v0.1.0 release.
- [x] v0.1.0 release artifacts have SHA-256 checksums.
- [x] v0.1.0 release has GitHub build-provenance and binary-SBOM attestations.
- [x] Third-party GitHub Actions are SHA-pinned.
- [x] Unsafe Rust is denied by default; any future exception still requires ADR/security review.
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

- [x] Canonical Git repository on GitHub.
- [x] v0.1.0 release archive + checksums published on GitHub Releases.
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

- [x] Kill switches are implemented and tested before aggressive probes.
- [x] Safety budgets are centrally enforced.
- [ ] Target authorization expires and fails closed.
- [x] v0.1.0 disables redirects and hostname execution and tests literal/resolved private-network restrictions; full hostname/DNS-rebinding-safe execution remains a later capability.
- [ ] Production campaigns cannot be silently escalated from low-impact to high-impact behavior.
- [ ] System-wide containment exercise requires explicit arming and auto-expiry.

### 5.9 Legal/IP/copyright controls

- [x] Repository license posture is deliberately proprietary/all-rights-reserved for v0.1.0.
- [ ] Third-party dependency licenses are inventoried and policy checked.
- [x] AI-assisted contributions are acknowledged transparently without assigning security responsibility to AI.
- [ ] Copyright headers/NOTICE policy is selected before external contributors exist.
- [ ] Future staff/contractor IP-assignment and confidentiality terms are handled outside Git.
- [x] `SECURITY.md` and private-disclosure guidance were present before public release.

### 5.10 AI-assisted engineering controls

- [ ] No production secret, private key, bank credential or real session token is pasted into AI prompts.
- [x] AI-assisted code is subjected to the same deterministic CI/Security/release gates.
- [x] The product/release design gives AI no standing production credential or runtime identity.
- [x] No product authentication path trusts an AI identity.
- [x] README records meaningful AI assistance accurately.
- [x] v0.1.0 release evidence is generated by deterministic CI/Security/release tooling, not by an AI assertion.

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

## 8. v0.1.0 minimum end-to-end contract — **SATISFIED**

v0.1.0 was released on 2026-10-04 only after the executable reproduced this closed loop:

```text
versioned/approved local test target + campaign
        ↓
Target Gate validates destination + safety budget
        ↓
safe IP-literal HTTP HEAD request through the network boundary
        ↓
status oracle evaluates PASS / FAIL
        ↓
metadata-only evidence record produced
        ↓
evidence SHA-256 integrity seal calculated and verified
        ↓
machine-readable + human report + run metadata + SHA256SUMS
        ↓
secure fixture PASS
vulnerable fixture FAIL
fixed fixture PASS
        ↓
CI/Security/release pipeline reproduces the acceptance evidence
```

### v0.1.0 acceptance checklist

- [x] Rust workspace builds on the pinned Rust 1.99.0 toolchain policy.
- [x] CLI has no arbitrary `scan <url>` execution path.
- [x] Versioned target/campaign formats exist and reject unknown fields/mismatched targets.
- [x] Redirects are disabled in v0.1.0 and disallowed network classes/cloud metadata endpoints are rejected.
- [x] Request-rate/total/time/concurrency budget primitives exist and are tested.
- [x] Kill-switch primitives exist and are tested.
- [x] One bounded `HTTP_HEAD_STATUS` probe exists.
- [x] Metadata-only evidence + SHA-256 integrity sealing exists.
- [x] JSON report exists.
- [x] Human-readable text report exists.
- [x] Secure fixture expected PASS.
- [x] Deliberately vulnerable fixture expected FAIL.
- [x] Fixed fixture returns to PASS.
- [x] CI runs format, compile, strict Clippy and tests.
- [x] Security runs RustSec and CodeQL on the release commit.
- [x] Release pipeline generates binary/archive, CycloneDX SBOM, SHA-256 checksums, provenance attestation and SBOM attestation.
- [x] README explains scope, safety model, AI use, non-goals and authorized-use restriction.
- [x] Changelog begins at `0.1.0`.
- [x] No secret is required to run fixture tests.

### Carry-forward governance controls

These are **not** retroactively marked complete by the v0.1.0 release:

- [ ] dedicated dependency-license/source allow/deny policy;
- [ ] repository-level secret-scanning/push-protection configuration verified and evidenced;
- [ ] branch/ruleset enforcement and required-check settings verified from repository administration;
- [ ] independent encrypted source/release backup plus a tested restore drill.

They are recorded in the gap register and next-actions document.

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