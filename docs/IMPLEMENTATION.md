# GyLiber Security Intruder
## Implementation Design & Architecture Baseline — v1.0.0

**Document status:** Implementation baseline derived from approved product design  
**Document version:** 1.0.0  
**Baseline date:** 2026-10-03  
**Owner:** GyLiber / GyLiber Engineering  
**Companion application:** `GyLiber/gyliber-command-center`  
**Source baseline:** [`docs/DESIGN.md`](DESIGN.md) — approved v1.0.0 baseline dated 2026-10-01  
**Implementation checkpoint:** v0.1.0 released 2026-10-04 at commit `b98e0a29864c70db3abc9ed023d33446d426fb89`; this document continues to describe the architecture path to v1.0.0.  

---

## 1. Executive decision

GyLiber Security Intruder will be implemented as a **Rust modular monolith with an ephemeral execution model and hard internal trust boundaries**.

The implementation optimizes for:

1. safety before attack capability;
2. reproducible evidence rather than “green scanner” claims;
3. a small trusted computing base;
4. no standing production super-credential;
5. fail-closed authorization;
6. future growth to a 6–10 person engineering/security team without requiring a premature microservice rewrite;
7. no dependency on a developer laptop for source, CI or release continuity.

The approved product design remains authoritative where this implementation document is silent. Where implementation discovers a conflict, an ADR records the decision and whether the design baseline must be amended.

---

## 2. Relationship to the existing GyLiber Command Center

Known current companion-system state from prior GyLiber work:

- Command Center is implemented in Rust/Axum;
- authentication uses GitHub OAuth with PKCE and an explicit allowlist;
- durable sessions use PostgreSQL;
- protected member APIs and live/module monitoring exist;
- containerized deployment and CI/security checks already exist;
- the deployed Command Center has reached the v0.3.0 line and has passed its current live health/playground verification.

The Intruder is not merged into that repository. It remains an independently deployable verifier so that compromise or failure of one system does not automatically collapse both sides of the security relationship.

---

## 3. Product boundary

### The Intruder SHALL

- enroll only authorized GyLiber targets;
- validate signed/approved campaigns;
- enforce target/network/safety policy before every outbound request;
- use synthetic identities and data;
- test prevention, detection, containment, recovery and evidence properties;
- create redacted, hash-linked evidence;
- integrate with CI/release gates;
- fail closed when authorization or safety state is uncertain.

### The Intruder SHALL NOT

- accept arbitrary internet targets for normal execution;
- function as a general-purpose exploitation framework;
- store raw banking credentials, real client secrets, real user passwords or master database credentials;
- become the Command Center's hidden super-admin;
- silently execute system-wide containment;
- claim that a passing run proves absolute security.

---

## 4. Technology baseline (2026-10-03)

### 4.1 Language

**Rust stable 1.99.0** is the initial toolchain baseline. The repository uses Rust edition 2024 unless a dependency/tooling incompatibility forces an ADR-backed exception.

Policy:

- first-party executable product code: Rust;
- no Python in the product stack;
- YAML/TOML/JSON/Markdown for configuration, schemas and automation;
- shell commands in CI kept minimal and non-authoritative;
- unsafe Rust forbidden by default (`#![forbid(unsafe_code)]` where compatible).

### 4.2 Core dependency families

Exact versions are selected and locked during implementation.

- async/runtime: Tokio;
- HTTP: Reqwest configured for rustls;
- TLS: rustls ecosystem;
- serialization: Serde;
- CLI: Clap;
- structured telemetry: Tracing;
- URL/IP parsing: standards-compliant Rust crates with explicit normalization tests;
- signatures: reviewed Ed25519 implementation;
- hashes: SHA-256 via a well-maintained Rust crypto implementation;
- secret wrappers/zeroization where meaningful;
- schema validation: JSON Schema-compatible validation for external files;
- property testing: `proptest` or equivalent;
- fuzzing: `cargo-fuzz`/libFuzzer in dedicated jobs;
- dependency audit/policy: `cargo-audit`, `cargo-deny`; additional vetting may be added after bootstrap.

No dependency is added merely because it is fashionable. Every network, crypto, parser, templating or serialization dependency expands the trusted computing base and receives deliberate review.

---

## 5. Repository architecture

The repository starts as a Cargo workspace while remaining a single product/deployable. Workspace crates create enforceable ownership and dependency boundaries without introducing distributed runtime services.

```text
gyliber-security-intruder/
├── .cargo/
│   └── config.toml
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   ├── ISSUE_TEMPLATE/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       ├── codeql.yml
│       ├── release.yml
│       ├── scheduled-assurance.yml
│       └── backup-source.yml
├── crates/
│   ├── intruder-cli/
│   ├── intruder-core/
│   ├── intruder-policy/
│   ├── intruder-net/
│   ├── intruder-evidence/
│   └── intruder-report/
├── fixtures/
│   ├── secure-target/
│   └── vulnerable-target/
├── campaigns/
│   ├── baseline/
│   ├── command-center/
│   ├── detection/
│   └── containment/
├── policies/
│   ├── production/
│   ├── staging/
│   └── lab/
├── schemas/
│   ├── target.schema.json
│   ├── campaign.schema.json
│   └── evidence.schema.json
├── docs/
│   ├── DESIGN.md
│   ├── SECURITY_MODEL.md
│   ├── THREAT_MODEL.md
│   ├── OPERATIONS.md
│   ├── TARGET_ENROLLMENT.md
│   ├── CAMPAIGN_AUTHORING.md
│   ├── DEFENSE_INTEGRATION.md
│   ├── DISASTER_RECOVERY.md
│   ├── AI_ASSISTED_ENGINEERING.md
│   └── adr/
├── tests/
│   ├── safety/
│   ├── integration/
│   └── fixtures/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── LICENSE-or-PROPRIETARY-NOTICE
```

### 5.1 Crate responsibilities

**`intruder-core`**  
Domain IDs, run state machine, verdict taxonomy, budgets, target/campaign abstractions. No direct external network client.

**`intruder-policy`**  
Target enrollment, authorization validity, execution windows, permitted probe families, environment tiers, policy evaluation. Pure/mostly-pure logic so it is easy to unit/property test.

**`intruder-net`**  
The only production crate allowed to own the outbound HTTP client. Implements the Target Gate, DNS/IP/redirect checks, request budgets and response-size limits. Probe code receives a constrained executor interface, not a raw Reqwest client.

**`intruder-evidence`**  
Redaction, canonical serialization, evidence IDs, hashing, integrity manifests and storage adapter interface.

**`intruder-report`**  
Machine JSON plus a human report. A future static HTML report may use the GyLiber dark/silver/dark-blue direction without creating a public operator service.

**`intruder-cli`**  
Safe operator interface. Wires policy, campaign execution, evidence and reports. It contains no bypass command for arbitrary raw targets.

---

## 6. Security architecture

### 6.1 Primary invariant: no network bypass

A probe cannot obtain a raw unrestricted HTTP client through the public API of the product.

```text
probe intent
   ↓
policy evaluation
   ↓
Target Gate
   ├─ target enrollment
   ├─ authorization expiry/window
   ├─ scheme/host/path
   ├─ DNS resolution
   ├─ IP class policy
   ├─ redirect re-validation
   ├─ request/response limits
   ├─ concurrency/rate budget
   ├─ circuit breaker
   └─ kill switch
   ↓
restricted outbound transport
```

### 6.2 Fail-closed behavior

Execution is denied when:

- policy is missing or unparsable;
- target authorization is absent/expired;
- signature validation fails;
- kill-switch state required by policy cannot be verified;
- host/IP/redirect normalization is ambiguous;
- budget arithmetic overflows or produces an invalid state;
- environment classification is unknown;
- a requested capability exceeds the campaign's approved containment/probe level.

### 6.3 DNS/redirect defense

The network boundary re-validates each destination after resolution and each redirect hop. Tests cover:

- IPv4 and IPv6 loopback;
- private/link-local ranges;
- unspecified/multicast/documentation ranges where relevant;
- numeric IP hosts;
- hostname normalization and trailing-dot behavior;
- alternate IP representations accepted by URL parsers;
- redirect escape;
- DNS answer changes/rebinding simulation;
- cloud metadata address blocks;
- userinfo/authority parsing ambiguity.

No single string-level hostname check is considered sufficient.

---

## 7. Campaign and target integrity

### Target records

Use immutable logical `target_id` values. Raw URLs are data inside a signed/approved target registry, not operator CLI parameters.

### Campaign records

Campaigns are declarative, schema-validated and eventually signature-validated. They contain:

- campaign ID/version;
- target ID;
- environment;
- preconditions;
- synthetic actors;
- ordered phases;
- per-phase safety budget;
- expected events/containment/recovery;
- cleanup;
- evidence policy;
- stop conditions.

The parser treats campaign input as untrusted even when the repository is controlled.

---

## 8. Evidence model

Evidence is a security product, not debug exhaust.

### 8.1 Evidence requirements

Each material result includes:

- run/campaign/target identifiers;
- source commit and tool version;
- UTC timestamps;
- target revision when available;
- expected vs observed behavior;
- sanitized request/response metadata;
- oracle result;
- security-event/containment/recovery references where applicable;
- evidence schema version;
- SHA-256 content hashes;
- limitation notes.

### 8.2 Redaction

Default-deny evidence capture:

- authorization/cookie headers are never emitted raw;
- secret-like values are replaced with typed redaction markers;
- response bodies are not stored wholesale by default;
- evidence extract sizes are bounded;
- a `RESTRICTED_VALUE_DETECTED_REDACTED` marker is recorded when forbidden data appears unexpectedly.

### 8.3 Storage

v0.1.0 may produce CI artifacts and local files because all fixtures are synthetic. Before evidence from real GyLiber production testing becomes important:

1. private cross-provider object storage is configured;
2. confidential bundles are encrypted before upload;
3. retention/immutability policy is defined;
4. restore is tested;
5. the public source repository stores only hashes/metadata that are safe to disclose.

---

## 9. Database policy

Databases are introduced only for state that actually requires transactional/durable query semantics.

### v0.1.0

No production database is required. Runs are ephemeral and fixture evidence is file/object oriented. This reduces attack surface and operational failure modes.

### Later

PostgreSQL becomes appropriate for:

- durable campaign/run metadata;
- trend queries;
- finding lifecycle;
- scheduler coordination if the execution model needs it;
- audit references that are not themselves secrets.

Large evidence payloads remain object storage, not relational rows.

A second database technology will not be added unless a concrete consistency, isolation, performance or security property justifies it.

---

## 10. CI/CD and software-supply-chain design

### 10.1 `ci.yml`

Runs on pull requests and pushes:

1. formatting check;
2. `cargo check`/build;
3. Clippy with warnings denied;
4. unit tests;
5. integration/fixture tests;
6. documentation tests;
7. architecture/safety invariant tests.

### 10.2 `security.yml` — implemented v0.1.0 controls

Runs on pushes, pull requests, schedule and manual dispatch:

- RustSec dependency vulnerability audit with warnings denied;
- CodeQL Rust analysis using the `security-extended` query suite.

The following remain explicit carry-forward governance/security work rather than being described as already implemented:

- dependency license/source allow/deny policy (for example `cargo-deny`);
- repository-level secret-scanning/push-protection verification;
- sanitizer/property/fuzz expansion;
- OpenSSF Scorecard if it adds useful signal at the project's scale.

### 10.3 CodeQL placement

CodeQL is implemented inside `security.yml`, not in a separate `codeql.yml`. If repository visibility or GitHub plan changes later make CodeQL unavailable, an equivalent open CI analysis path must replace it rather than silently dropping static security analysis.

### 10.4 Workflow hardening

- every third-party Action pinned to a full commit SHA;
- explicit minimal `permissions:` block;
- OIDC for cloud authentication when available;
- no long-lived cloud deployment token if OIDC can replace it;
- deployment environment approval for production;
- untrusted PRs receive no deployment/evidence secrets;
- build outputs are hashed;
- release artifacts receive provenance/attestation where supported.

### 10.5 Release pipeline — v0.1.0 implementation

```text
push to main
 ↓
normal CI + Security workflows
 ↓
release-request marker (.release/vX.Y.Z.json)
 ↓
independent release rebuild + tests
 ↓
CycloneDX SBOM + SHA-256 checksums
 ↓
wait for exact-commit CI + RustSec + CodeQL success
 ↓
build-provenance attestation + binary-SBOM attestation
 ↓
GitHub Release + version tag
```

The v0.1.0 release workflow uses least-privilege job permissions and refuses to overwrite an existing release tag.

## 11. Testing strategy

### Level 1 — Unit and property tests

Target:

- policy evaluation;
- URL/IP parsing;
- signature validation;
- budget math;
- state transitions;
- redaction;
- deterministic evidence serialization.

### Level 2 — Adversarial fixtures

Required from v0.1.0:

```text
secure fixture     → expected PASS
vulnerable fixture → expected FAIL
fixed fixture      → expected PASS
```

The fixture laboratory proves the Intruder can actually identify a controlled failure.

### Level 3 — Integration target

Command Center staging, with synthetic identities and test-only endpoints/adapters.

### Level 4 — Live bounded assurance

Production-safe profile only after explicit authorization, health circuit breaker and recovery path are verified.

### Fuzzing

Fuzz parsers and the Target Gate before v1.0.0, prioritizing:

- URL normalization;
- target/campaign deserialization;
- redirect policy;
- evidence redaction;
- signature/canonicalization inputs.

---

## 12. v0.1.0 functional slice — released

The shipped v0.1.0 operator surface is intentionally narrow and complete.

### Commands

```text
intruder target validate <target-file>
intruder campaign validate --target <target-file> <campaign-file>
intruder campaign plan --target <target-file> <campaign-file>
intruder run --target <target-file> --campaign <campaign-file> --kill-switch <kill-switch-file> --run-id <id> --out-dir <new-directory>
intruder kill-switch-status
```

No `intruder scan https://arbitrary-host` command exists.

### Armed probe family

v0.1.0 arms only `HTTP_HEAD_STATUS` against an approved IP-literal target. Redirects, automatic retries, ambient proxy inheritance and hostname execution are disabled. Response bodies and HTTP header values are not persisted.

### Oracle and run bundle

The oracle compares observed status with the typed expected status and records PASS or FAIL. A successful run writes a new directory containing `report.json`, `report.txt`, `run.json`, and `SHA256SUMS`. Evidence is metadata-only and SHA-256 sealed; the hash provides integrity detection, not signer identity.

## 13. Hosting and online execution

### Initial choice: GitHub-hosted ephemeral execution

A permanently exposed web service is **not required** for v0.1.0 and would add an unnecessary attack surface.

The safe free starting point is:

- GitHub repository: canonical source;
- GitHub Actions: CI, scheduled/manual authorized fixture runs and builds;
- GitHub Releases: tagged release artifacts/checksums;
- private second-provider object storage before durable evidence matters.

A persistent hosted control plane is added only when scheduling, inbound events, dedicated egress identity or multi-user operations justify it.

### Free Render use

Render free compute may be used for non-authoritative staging fixtures or a future prototype service, but free Render PostgreSQL is unsuitable for irreplaceable data because its current free database expires after 30 days and provides no backups.

### Future paid infrastructure

When GyLiber has revenue, migrate security-sensitive production operation to infrastructure that supports:

- stable/dedicated runtime identity and egress where needed;
- private networking;
- managed secrets/KMS;
- paid PostgreSQL with PITR/backups;
- high availability where the accepted SLO requires it;
- log/evidence retention;
- explicit regional/data-residency choice;
- supportable disaster recovery.

---

## 14. Disaster recovery and “server burns down” design

Provider durability is not treated as backup.

### Source

- primary: GitHub Git repository;
- secondary: encrypted `git bundle` snapshots to a different provider;
- release: GitHub Release plus second-provider archive;
- integrity: signed/hash manifest.

### Evidence

- primary durable private object store;
- cross-account/provider replication or scheduled encrypted export for high-value evidence;
- version/retention policy;
- restore drill with recorded result.

### Future Command Center business data

The Intruder does not store this data. The Command Center must eventually use:

- managed primary database;
- automated PITR;
- independent encrypted backup copy;
- tested restore;
- documented RPO/RTO;
- access-separated backup credentials.

A backup that has never been restored is not accepted as a proven recovery mechanism.

---

## 15. Repository/security settings baseline

Once the repository exists:

- default branch: `main`;
- require status checks;
- block force push and deletion;
- require signed commits where enforceable;
- require linear history unless merge policy requires otherwise;
- require conversation resolution;
- CODEOWNERS for `.github/`, `crates/intruder-net/`, policy/signature/evidence code;
- allow only approved GitHub Actions and require full-SHA pinning where repository settings support it;
- Dependabot/security alerts enabled;
- secret scanning/push protection enabled where available;
- private vulnerability reporting enabled for public repository if available;
- releases created only from protected commits.

With one human maintainer, a “required one other reviewer” rule can deadlock development. Until GyLiber has a second trusted human reviewer, mandatory review is replaced by required CI/security gates and explicit owner sign-off; the rule is tightened as staff grows.

---

## 16. Conventional commit contract

Examples of acceptable early commits:

```text
chore: initialize Rust workspace and repository policy
ci: add formatting lint and test workflow
ci: add security scanning workflow
feat(policy): define target authorization model
feat(net): enforce target gate host and IP policy
feat(evidence): add redacted hashed evidence envelope
test(fixtures): add secure and vulnerable baseline targets
feat(cli): execute baseline campaign end to end
docs: document security model and authorized use
chore(release): prepare v0.1.0
```

Commits are units of verified work, not diary entries. A later `fix:`, `refactor:` or `revert:` is expected when new evidence invalidates an earlier choice.

---

## 17. AI-assisted engineering policy

The README will acknowledge that OpenAI models materially assist design, implementation, review and documentation.

The project does **not** claim that AI assistance provides a security guarantee.

Controls:

- AI receives no standing production credential;
- secrets are never intentionally placed in prompts;
- generated code must pass the same tests and review gates as human-authored code;
- deterministic CI, static analysis, fuzzing and fixture tests are the evidence;
- GyLiber owns release decisions and risk acceptance;
- future human maintainers can replace the AI workflow without changing product trust assumptions.

---

## 18. Security information classes relevant to GyLiber

The Command Center may eventually handle:

- financial/asset state;
- contracts and copyright records;
- proprietary development methods and trade secrets;
- source/release plans for commercial tools;
- staff identity/employment information;
- client/customer records;
- API/service credentials;
- legal/tax/company records;
- incident and vulnerability information;
- strategic plans and pricing/revenue data.

The Intruder may test whether boundaries protecting these classes work, but v1.0.0 uses synthetic substitutes and sanitized references rather than the real data.

---

## 19. Version roadmap

### v0.1.0 — Closed-loop safety foundation — **RELEASED 2026-10-04**

Authoritative tag: `v0.1.0` → `b98e0a29864c70db3abc9ed023d33446d426fb89`.

- repository/workspace;
- CI + security workflow;
- target registry/policy types;
- Target Gate minimum implementation;
- budgets + kill switch;
- baseline probe;
- secure/vulnerable fixture laboratory;
- evidence hash/redaction;
- JSON + human report;
- rich README/security docs.

### v0.2.0 — Integrity

- signed campaigns/registries;
- canonical serialization;
- authorization expiry;
- stronger redirect/DNS safety tests.

### v0.3.0 — Authentication/session

- synthetic authentication adapter;
- GitHub OAuth/PKCE/allowlist assurance profile;
- cookie/session lifecycle checks.

### v0.4.0 — Authorization/API

- object/function/property authorization campaigns;
- API schema/inventory checks;
- Command Center protected API profile.

### v0.5.0 — Detection

- security-event adapter;
- run/event correlation;
- detection assertions.

### v0.6.0 — Containment/recovery

- L1 synthetic actor/session containment;
- recovery assertions;
- control-account safety check;
- explicitly armed higher containment drill framework.

### v0.7.0 — Extended safe adversarial coverage

- safe SSRF canary;
- bounded input/fuzz cases;
- business-logic scenarios;
- resource-control tests.

### v0.8.0 — Continuous assurance and durability

- schedules;
- trend metadata;
- durable evidence object storage;
- backup automation;
- restore drill.

### v0.9.0 — Hardening

- parser and Target Gate fuzzing campaign;
- dependency review;
- network-policy escape tests;
- kill-switch/recovery drills;
- staging release candidate.

### v1.0.0 — Contract release

- complete acceptance matrix;
- vulnerable/secure/fixed fixture proof;
- Command Center staging exercise;
- authorized bounded production exercise where safe;
- operational runbook;
- disaster-recovery evidence;
- known limitations/residual-risk register;
- release dossier.

---

## 20. Architectural evolution beyond v1.0.0

The initial modular monolith may evolve into multiple services only when measurable requirements justify the added security/operational cost, for example:

- dedicated geographically controlled runners;
- tenant/target isolation;
- high-volume scheduled assurance;
- dedicated egress IP pools;
- separate evidence service;
- independent signing/control plane;
- enterprise staff/RBAC needs.

The stable contracts to preserve are target authorization, campaign schema, evidence schema, result taxonomy and security-event semantics—not any particular runtime topology.

---

## 21. Historical v0.1.0 implementation order

The following list was the initial commit-sized plan for v0.1.0. The release is now complete; actual commit names diverged where implementation evidence required fixes/refactors. This list is retained only as planning history, not as current next actions:

1. `chore: initialize Rust workspace and repository policy`
2. `ci: add formatting lint and test workflow`
3. `ci: add dependency secret and code security checks`
4. `feat(core): define target campaign budget and verdict types`
5. `feat(policy): validate authorized target policy`
6. `feat(net): implement fail-closed target gate`
7. `feat(core): add kill switch and budget enforcement`
8. `feat(evidence): add redaction and content hashing`
9. `test(fixtures): add secure and vulnerable baseline targets`
10. `feat(probes): add baseline HTTP boundary probe`
11. `feat(report): add JSON and Markdown run reports`
12. `feat(cli): execute baseline campaign end to end`
13. `docs: complete v0.1 security and operations guidance`
14. `chore(release): prepare v0.1.0`

Each step must leave the repository coherent and CI-green before the next unit is merged/committed.

---

## 22. Architecture acceptance statement

This implementation baseline intentionally favors a small, strongly constrained system over a feature-rich scanner. The first success criterion remains:

> a deliberately vulnerable authorized fixture produces the expected finding; the corrected/secure fixture passes; both outcomes are reproducible in CI; the runner cannot escape its target authorization boundary through the tested paths.

That is the minimum credible foundation on which GyLiber can safely add richer adversarial behavior.