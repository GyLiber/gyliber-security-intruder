# GyLiber Security Intruder
## Complete Product Design Document — v1.0.0

**Repository:** `GyLiber/gyliber-security-intruder`  
**Document version:** 1.0.0  
**Design status:** Approved design baseline for implementation  
**Design date:** 2026-10-01  
**Owner:** GyLiber / GyLiber Engineering  
**Companion system:** `GyLiber/gyliber-command-center`  
**Security principle:** *Trust is demonstrated by controlled attempts to break the trust boundary, not by assuming the boundary works.*

**Implementation checkpoint (2026-10-04):** v0.1.0 has been released. This document remains the approved **v1.0.0 product target**, not a claim that every capability described below is present in v0.1.0. The shipped v0.1.0 subset uses versioned but unsigned target/campaign documents, an IP-literal HTTP HEAD status probe, metadata-only evidence, and a constrained CLI. Signed authorization, authentication/session assurance, defense correlation, containment/recovery verification, and continuous scheduling remain later capability gates.

---

## Document control

| Item | Value |
|---|---|
| Product | GyLiber Security Intruder |
| Repository | `GyLiber/gyliber-security-intruder` |
| Version covered | v1.0.0 |
| Primary role | Continuous adversarial security assurance for GyLiber-owned applications |
| First protected product | GyLiber Command Center |
| Primary target | Authorized GyLiber environments only |
| Deployment posture | Controlled, allowlisted, policy-gated |
| Data posture | Synthetic/security-test data only in v1.0.0 |
| Production claim | The product does **not** prove that a system is absolutely secure |
| Security objective | Detect, validate, contain, evidence and improve security controls continuously |

---

# 1. Executive summary

GyLiber Security Intruder is a continuously maintained adversarial security-assurance product intended to test whether the GyLiber Command Center and later GyLiber-owned systems actually enforce the security properties claimed by their design.

It is deliberately more than a conventional vulnerability scanner.

A conventional scan can demonstrate that a request reached an endpoint, that a response had a particular status, or that a known weakness may exist. That is useful, but it is insufficient for the Command Center's security objective. GyLiber needs evidence that:

1. a protected boundary rejects unauthorized behavior;
2. an authentication or authorization control resists the expected abuse;
3. suspicious behavior is detected and produces the expected security event;
4. the correct account/session/resource is contained when containment is required;
5. unrelated legitimate access is not accidentally locked;
6. the incident state is auditable;
7. recovery returns the system to a known-safe state;
8. the same security contract remains true after later software changes.

The Intruder therefore treats the target as a defensive system under adversarial test and runs controlled attack simulations against it. Every campaign is bounded by a target-authorization policy, a safety budget, a test-data policy, a maximum execution window, a network allowlist, a circuit breaker, and a kill switch.

The complete v1.0.0 product target is designed as a **modular Rust application** rather than an unnecessarily distributed system. At that target it provides:

- signed and allowlisted target enrollment;
- declarative adversarial campaigns;
- deterministic and state-aware web/API probes;
- safe synthetic identities and test data;
- bounded discovery and fuzzing;
- authentication and authorization abuse simulation;
- session, cookie and OAuth control verification;
- API security tests;
- business-logic abuse tests;
- limited resource-consumption tests;
- observability/detection assertions;
- containment/lock assertions;
- evidence capture and redaction;
- reproducible reports;
- CI release-gate integration;
- scheduled continuous assurance.

The product must never become a general-purpose internet attack framework. Its central security property is that **the Intruder itself is difficult to repurpose**.

---

# 2. Design thesis

## 2.1 Security is an empirical property

The Command Center's security architecture contains claims such as:

- protected resources are deny-by-default;
- browser state is not an authorization source;
- GitHub identity is constrained by an explicit allowlist;
- sessions are protected and eventually durable;
- security-sensitive actions are audited;
- suspicious behavior should be detectable;
- containment should be possible;
- sensitive data should remain outside public and unauthenticated paths.

The Intruder exists to test those claims.

A design document, source-code review or successful CI run is evidence of construction quality. It is not evidence that every runtime control behaves correctly under adversarial pressure.

Therefore:

> **The Intruder is the runtime adversarial-verification counterpart to the Command Center's security architecture.**

## 2.2 The Intruder does not declare the system "secure"

No finite test suite can prove that a real internet-facing application has no vulnerabilities.

The product instead produces evidence about specific security properties at a specific revision, environment and test date.

The correct statement after a successful release is therefore:

> The tested security controls covered by the v1.0.0 assurance profile passed the defined adversarial verification suite for the tested target revision and environment, with recorded limitations and residual risk.

It must never automatically report:

> "The site is secure."

---

# 3. Objectives

## 3.1 Primary objectives

The v1.0.0 product shall:

- continuously verify high-value web and API security boundaries;
- exercise authentication and authorization controls using synthetic identities;
- test detection and alerting paths as deliberately as the vulnerability paths;
- verify containment behavior without causing uncontrolled lockout;
- test recovery from security containment;
- produce immutable, reproducible evidence;
- stop safely when the target behaves unexpectedly;
- prevent execution against unauthorized targets;
- integrate with the Command Center without making the Intruder a trust authority for the Command Center;
- support future target applications through adapters rather than target-specific forks.

## 3.2 Secondary objectives

The product should:

- map tests to OWASP ASVS, OWASP WSTG, OWASP API Security Top 10, OWASP Automated Threats terminology, and MITRE ATT&CK where meaningful;
- use CVSS v4.0 for vulnerability severity metadata when a genuine vulnerability is identified;
- distinguish vulnerability findings from detection/response findings;
- track regressions over time;
- make security failures easy to reproduce locally;
- provide concise client-facing evidence and detailed engineering evidence separately.

---

# 4. Non-goals and prohibited behavior

v1.0.0 is **not**:

- an unrestricted penetration-testing platform;
- a botnet;
- a DDoS tool;
- a credential-stuffing service;
- a password-cracking engine;
- a malware delivery system;
- a persistence framework;
- a lateral-movement framework;
- a general internet vulnerability scanner;
- a covert exfiltration platform;
- a system for testing third-party websites without explicit authorization;
- a replacement for independent security review or penetration testing;
- a tool that stores real client credentials for attack purposes.

### Prohibited by design

The Intruder shall reject or lack the capability to:

- accept an arbitrary target URL in an unapproved execution mode;
- follow redirects to a non-allowlisted host;
- access cloud instance metadata or private-network destinations from internet-target mode;
- use real user passwords or stolen credentials;
- enumerate or attack real third-party accounts;
- intentionally cause sustained denial of service;
- delete or corrupt production data;
- install persistent code on the target;
- exfiltrate arbitrary real target data;
- automatically invoke system-wide production lockout without the target's own containment policy and explicit campaign authorization;
- execute unsigned third-party attack scripts in v1.0.0.

---

# 5. Security assurance model

Every campaign evaluates five distinct layers.

| Layer | Question |
|---|---|
| Prevention | Was the adversarial action blocked? |
| Detection | Did the security system recognize the suspicious behavior? |
| Containment | Was the correct actor/session/resource contained? |
| Recovery | Did the system return to the intended operating state? |
| Evidence | Can the result be independently reconstructed? |

A campaign is not considered fully successful merely because an HTTP request received `403`.

For example, a test of a protected administrative action may require:

1. the unauthorized synthetic actor attempts the action;
2. the action is denied;
3. a security event is generated;
4. the event is correlated with the Intruder test run;
5. the synthetic actor is contained when the scenario requires it;
6. the authorized control account remains functional;
7. the event and containment action are recorded;
8. the test cleanup succeeds.

---

# 6. Target model

## 6.1 Target enrollment

Targets are identified by immutable logical IDs rather than raw URLs.

Example:

```text
target_id: command-center-production
environment: production
application: gyliber-command-center
```

The target registry supplies:

- allowed hostnames;
- allowed schemes;
- permitted paths;
- environment classification;
- expected authentication adapter;
- expected defense adapter;
- traffic budget;
- execution windows;
- test-account policy;
- allowed containment levels;
- permitted probe families;
- response/body size limits;
- redirect policy;
- network restrictions;
- kill-switch configuration.

The CLI does not provide a bypass such as `--url https://somewhere.example` for normal execution.

## 6.2 Ownership and authorization

A target may enter the registry only after an explicit GyLiber authorization record establishes:

- target ownership or written authorization;
- target environment;
- permitted testing scope;
- authorized test windows;
- approved source/runner;
- contact/stop authority.

No target enrollment means no run.

## 6.3 Environment tiers

| Tier | Intended use | Permitted testing |
|---|---|---|
| LAB | Isolated developer/security lab | Broadest safe testing |
| STAGING | Production-like pre-release environment | Broad active testing |
| CANARY | Production deployment with synthetic test boundary | Controlled adversarial tests |
| PRODUCTION | Real public deployment | Bounded, non-destructive tests; stronger containment rules |

The first v1.0 Command Center deployment should support STAGING and PRODUCTION profiles with different safety budgets.

---

# 7. Target Gate — the primary safety boundary

Every outbound request passes through a mandatory Target Gate.

The Target Gate validates:

1. target is registered;
2. target authorization has not expired;
3. current time is inside the execution window;
4. requested scheme is approved;
5. hostname exactly matches an enrolled host or permitted subdomain rule;
6. redirect destination remains allowlisted;
7. resolved address is permitted by network policy;
8. request method is permitted for the selected probe;
9. path is permitted;
10. request budget has not been exhausted;
11. body size is within bounds;
12. concurrency limit is not exceeded;
13. circuit breaker is closed;
14. global kill switch is not active.

The Target Gate is a **non-bypassable library boundary**. Probe implementations do not get direct access to the HTTP client.

### DNS and redirect protections

The Gate must defend against target-policy bypass through:

- DNS changes;
- redirect chains;
- alternate hostnames;
- numeric IP destinations;
- IPv4/IPv6 ambiguity;
- localhost/private/link-local destinations;
- cloud metadata endpoints;
- DNS rebinding;
- URL parsing ambiguities.

Internet-target profiles shall reject private, loopback, link-local and metadata destinations unless the target is explicitly enrolled as a LAB/STAGING target that permits them.

---

# 8. Campaign model

A campaign is a signed declarative description of an adversarial scenario.

A campaign contains:

- campaign ID;
- version;
- target ID;
- attack profile;
- expected preconditions;
- synthetic actor identities;
- ordered test phases;
- per-phase budget;
- expected security events;
- expected containment level;
- cleanup actions;
- stop conditions;
- evidence policy.

Campaigns are reviewed as code.

## 8.1 Campaign lifecycle

```text
DRAFT
  ↓
REVIEWED
  ↓
SIGNED
  ↓
SCHEDULED
  ↓
ARMED
  ↓
RUNNING
  ↓
OBSERVING
  ↓
CLEANUP
  ↓
VERIFIED
  ↓
REPORT
```

A campaign may also transition to:

```text
ABORTED
FAILED-SAFETY
FAILED-TARGET
FAILED-CONTROL
```

These states must be distinguished. A safety abort is not equivalent to a security-control failure.

---

# 9. Execution modes

## 9.1 Safe baseline

Low-volume verification of:

- TLS/HTTPS expectations;
- security headers;
- cookie flags;
- public/unauthenticated route boundaries;
- known public API surface;
- health endpoint behavior.

Recommended recurring mode.

## 9.2 Authenticated adversarial

Uses synthetic accounts and sessions to verify:

- authentication;
- session management;
- authorization;
- protected API behavior;
- logout/revocation;
- role or actor boundaries.

## 9.3 Detection exercise

Generates a pre-defined suspicious sequence and asserts:

- detection;
- event creation;
- correlation;
- alert delivery;
- containment.

## 9.4 Containment exercise

Executes a scenario designed to cross a pre-approved detection threshold and verifies the target's containment behavior.

Containment may be:

- actor-level;
- session-level;
- token-level;
- resource/action-level;
- system-wide.

System-wide containment is never silently armed.

## 9.5 Release gate

Runs a concise high-signal test set against a newly deployed revision.

A release can be marked security-gate-failed even when the application remains technically reachable.

## 9.6 Deep assessment

Broad active testing intended for STAGING or LAB, including bounded fuzzing and more extensive API/business-logic testing.

This mode is not the default production schedule.

---

# 10. Attack and verification catalog

## 10.1 Surface and configuration verification

Test:

- unexpected exposed routes;
- administrative/debug routes;
- unsafe HTTP methods;
- security headers;
- TLS expectations;
- caching of protected content;
- error disclosure;
- framework/version disclosure where controllable;
- CORS policy;
- content-type handling.

## 10.2 Authentication

Test:

- protected route access without authentication;
- session establishment;
- session fixation resistance;
- session renewal on authentication;
- logout invalidation;
- expired-session behavior;
- invalid-session behavior;
- authentication rate limiting;
- OAuth state handling;
- OAuth PKCE expectations;
- callback validation;
- allowlist enforcement;
- authentication failure semantics.

Tests use synthetic identities and bounded attempts.

No real user's password is used.

## 10.3 Authorization

Test:

- unauthenticated → protected;
- authenticated actor → unauthorized resource;
- actor A → actor B synthetic resource;
- role/function separation;
- HTTP method authorization;
- property/field-level authorization;
- resource identifier substitution;
- protected UI vs protected API consistency.

This includes coverage aligned with OWASP API Security Top 10 categories such as broken object-level authorization, broken authentication, broken function-level authorization and security misconfiguration.

## 10.4 Session security

Test:

- cookie `Secure`;
- `HttpOnly`;
- `SameSite`;
- session renewal;
- server-side session state;
- revocation;
- expiration;
- logout;
- persistence across service restarts where durability is promised;
- behavior after backend session-store failure.

## 10.5 Injection and input handling

Test safe canary cases for:

- SQL injection indicators;
- command-injection defenses;
- path traversal;
- template injection indicators;
- unsafe deserialization boundaries;
- header manipulation;
- malformed JSON/XML/YAML where accepted;
- encoding/canonicalization errors.

The Intruder shall prefer **oracle-based detection of unsafe behavior** over destructive proof.

## 10.6 API security

Test:

- undocumented endpoints;
- HTTP method confusion;
- object authorization;
- property authorization;
- function authorization;
- excessive resource consumption;
- API version drift;
- deprecated endpoints;
- unsafe third-party API consumption boundaries;
- schema validation.

## 10.7 SSRF and outbound-request controls

Test only through controlled canaries.

The objective is to determine whether user-controlled server-side fetch functionality can reach a declared safe canary.

The test does not attempt to retrieve:

- real cloud metadata;
- real internal credentials;
- arbitrary internal services.

A synthetic canary service provides the authoritative success/failure oracle.

## 10.8 Business-logic abuse

Test bounded misuse of legitimate functions, including where applicable:

- repeated sensitive action;
- action ordering violations;
- replay;
- bypassing intended state transitions;
- excessive retries;
- unauthorized workflow acceleration;
- resource ownership confusion.

OWASP Automated Threats terminology is useful here because many real threats abuse valid application functionality rather than exploiting implementation bugs.

## 10.9 Browser security

Test:

- CSRF protections where relevant;
- origin handling;
- clickjacking protections;
- unsafe cross-origin behavior;
- XSS-safe output handling through canary markers;
- DOM-based security invariants.

## 10.10 Resource-consumption controls

The production profile may test:

- rate limits;
- per-account quotas;
- expensive-request protection;
- bounded payloads;
- repeated invalid authentication attempts.

It shall **not** perform sustained denial-of-service.

Production tests operate inside a strict request/time budget and stop immediately on degraded-health thresholds.

## 10.11 Security boundary abuse sequences

These tests intentionally combine multiple benign actions to mimic a realistic intrusion sequence:

```text
reconnaissance
    ↓
authentication boundary probe
    ↓
authorization probe
    ↓
suspicious repeated action
    ↓
detection assertion
    ↓
containment assertion
    ↓
recovery assertion
```

The sequence is designed to exercise the entire defensive chain.

---

# 11. Synthetic identity and data system

The Intruder must never need real client data to prove that a boundary works.

## 11.1 Synthetic actors

The target adapter creates or provisions dedicated test principals:

- `intruder-unauthenticated`;
- `intruder-user-a`;
- `intruder-user-b`;
- `intruder-admin` only where explicitly permitted;
- `intruder-expired-session`.

Each actor has an immutable test identity.

## 11.2 Synthetic records

Where object authorization must be tested, the target exposes synthetic records owned by known synthetic actors.

Example:

```text
record-A → intruder-user-a
record-B → intruder-user-b
```

The test verifies that A cannot access B.

## 11.3 Canaries

Canaries are unique markers that allow the Intruder to prove that a protected synthetic value was or was not reached.

Canaries must:

- contain no real credential;
- contain no real personal information;
- be unique per campaign;
- be harmless if exposed;
- be automatically invalidated after testing.

---

# 12. Detection and alert contract

The Intruder must be able to verify the defense system's **security telemetry**, not merely the HTTP response.

## 12.1 Required event envelope

A test-related security event should include, directly or by correlation:

- event ID;
- timestamp;
- event code;
- target ID;
- environment;
- actor/session reference;
- campaign ID;
- run ID;
- source/request correlation ID;
- detection classification;
- confidence;
- containment state.

Sensitive request headers, passwords and session secrets must not be copied into the event.

## 12.2 Expected event classes

The v1.0 design reserves event concepts such as:

```text
security.test.started
security.suspicious_activity.detected
security.authentication_abuse.detected
security.authorization_violation.detected
security.session_anomaly.detected
security.containment.actor_locked
security.containment.session_revoked
security.containment.system_locked
security.containment.released
security.test.completed
security.test.aborted
```

Exact event names may evolve, but the semantic contract must remain stable.

---

# 13. Containment and access-lock design

## 13.1 Principle

The Intruder does not become the final authority over the Command Center's access policy.

The Command Center decides whether containment is appropriate. The Intruder creates controlled conditions and verifies the resulting behavior.

## 13.2 Containment levels

| Level | Meaning | v1.0 default |
|---|---|---|
| L0 | Observe only | Allowed |
| L1 | Lock/revoke synthetic actor/session | Auto-test allowed |
| L2 | Restrict sensitive actions/resources | Explicit campaign authorization |
| L3 | System-wide lock/protective mode | Arm explicitly; auto-expire |

## 13.3 System-wide lock

A system-wide test must require:

- an explicitly armed campaign;
- target/environment match;
- short validity window;
- automatic expiry;
- a unique test-run identifier;
- an independent recovery path;
- audit evidence;
- verification that the lock applies only within its intended scope.

The Intruder must not possess a permanent "lock site" credential.

## 13.4 False-positive protection

Containment tests must verify that:

- the synthetic test actor is affected;
- unrelated legitimate actors remain usable where the scenario requires actor-level containment;
- the system-wide state, when intentionally tested, is released automatically;
- emergency unlock remains possible;
- a failed detection does not cause repeated uncontrolled lock loops.

---

# 14. Evidence model

Every material result produces an evidence bundle.

## 14.1 Evidence contents

- target ID;
- environment;
- target revision/build identifier;
- campaign ID/version;
- run ID;
- UTC timestamps;
- test case IDs;
- request/response metadata;
- redacted relevant response excerpts;
- expected result;
- observed result;
- security-event references;
- containment references;
- recovery references;
- final verdict;
- limitation notes;
- tool version;
- policy version;
- hashes of larger evidence files.

## 14.2 Evidence classification

Default:

**INTERNAL**

Findings involving security control weaknesses may be treated as:

**CONFIDENTIAL**

Critical secrets, if encountered unexpectedly, must not be written into evidence. The engine should record a redacted indicator such as:

```text
SENSITIVE_VALUE_DETECTED_REDACTED
```

rather than the secret.

## 14.3 Evidence integrity

Evidence bundles shall be:

- content-addressed;
- hashed;
- timestamped;
- immutable after run completion;
- linked to source commit and campaign revision.

---

# 15. Finding model

A finding contains:

- finding ID;
- category;
- affected target;
- affected route/resource;
- test case;
- preconditions;
- expected control;
- actual behavior;
- evidence references;
- reproducibility instructions;
- impact assessment;
- remediation recommendation;
- status.

Where appropriate, vulnerability findings use CVSS v4.0 metadata and vector strings.

Security-control findings must remain distinct from conventional vulnerabilities.

Example:

```text
VULN-001
Broken authorization

DETECT-004
Unauthorized object access was blocked but generated no security event

RESP-002
Detection fired, but containment did not revoke the synthetic session

REC-001
Containment did not recover after the configured expiry
```

A secure system requires all four dimensions to work where the target's policy says they should.

---

# 16. Oracle system

A test needs an authoritative answer.

Oracles include:

- HTTP response oracle;
- application-state oracle;
- database-state oracle through a safe test adapter;
- synthetic-canary oracle;
- security-event oracle;
- containment oracle;
- recovery oracle.

The Intruder must avoid inferring "success" from weak clues when a stronger target-side oracle can be provided.

---

# 17. Architecture

## 17.1 Architectural form

v1.0.0 is a **modular monolith with an ephemeral execution model**.

That means one codebase and one principal command-line/service executable, with strict internal module boundaries.

No microservices are required for the first release.

## 17.2 Components

```text
                         +---------------------------+
                         | Signed Target Registry     |
                         +-------------+-------------+
                                       |
                         +-------------v-------------+
                         | Target Gate / Policy       |
                         | authorization + safety     |
                         +-------------+-------------+
                                       |
                         +-------------v-------------+
                         | Campaign Engine             |
                         | state machine + budgets     |
                         +-------------+-------------+
                                       |
        +------------------------------+------------------------------+
        |              |               |              |              |
        v              v               v              v              v
   Auth Probe      API Probe      Browser Probe   Input Probe   Detection Probe
        |              |               |              |              |
        +------------------------------+------------------------------+
                                       |
                         +-------------v-------------+
                         | Oracle / Assertion Engine |
                         +-------------+-------------+
                                       |
             +-------------------------+----------------------+
             |                         |                      |
             v                         v                      v
      Security Event             Containment             Recovery
        Adapter                    Adapter                 Adapter
             |                         |                      |
             +-------------------------+----------------------+
                                       |
                         +-------------v-------------+
                         | Evidence + Report Engine  |
                         +---------------------------+
```

## 17.3 Core modules

### `target_gate`

The mandatory outbound-control boundary.

### `campaign`

Loads, validates and executes signed campaigns.

### `probes`

Contains safe built-in test families.

### `oracles`

Evaluates expected results.

### `defense`

Communicates with target security telemetry/containment interfaces.

### `evidence`

Sanitizes, hashes and records run evidence.

### `report`

Produces human and machine-readable reports.

### `scheduler`

Supports on-demand and scheduled execution.

### `policy`

Applies target-specific safety and security limits.

---

# 18. Technology selection

## 18.1 Primary language

**Rust**

Rationale:

- aligns with the Command Center;
- strong type and memory safety;
- explicit error handling;
- good asynchronous networking support;
- useful for a security-sensitive long-lived tool;
- enables one deployable binary for controlled runners.

## 18.2 Suggested libraries

The exact dependency versions should be selected and locked during implementation, but the architecture should support:

- Tokio — async runtime;
- Reqwest + rustls — controlled HTTP;
- Serde — typed serialization;
- Clap — CLI;
- Tracing — structured execution logs;
- Ed25519 implementation — campaign/authorization signatures;
- SQLx/PostgreSQL or an equivalent durable metadata store if durable campaign history is required;
- browser automation adapter only when required, with a bounded browser runtime.

The product should not add dependencies merely to imitate a large security framework.

---

# 19. Repository design

Proposed repository:

```text
gyliber-security-intruder/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security.yml
│       └── scheduled-assurance.yml
├── docs/
│   ├── DESIGN.md
│   ├── OPERATIONS.md
│   ├── TARGET_ENROLLMENT.md
│   ├── CAMPAIGN_AUTHORING.md
│   ├── DEFENSE_INTEGRATION.md
│   └── SECURITY_MODEL.md
├── campaigns/
│   ├── baseline/
│   ├── command-center/
│   ├── detection/
│   └── containment/
├── policies/
│   ├── production.yaml