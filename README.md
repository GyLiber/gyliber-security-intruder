# GyLiber Security Intruder

> Controlled adversarial security assurance for GyLiber-owned systems.

**Release candidate:** v0.2.0 — integrity and authenticity  
**Primary implementation language:** Rust  
**License posture:** proprietary / all rights reserved until GyLiber adopts a different written license  
**Authorization posture:** GyLiber-owned or explicitly authorized targets only

## Purpose

GyLiber Security Intruder is the adversarial-verification companion to the GyLiber Command Center. It exists to test whether security controls actually enforce their documented contracts under controlled hostile behavior.

It is not a general-purpose internet scanner and it is not a hidden administrative authority over the systems it tests.

The long-term assurance model evaluates five separate dimensions:

1. prevention;
2. detection;
3. containment;
4. recovery;
5. evidence integrity.

A successful HTTP status alone is not sufficient evidence of security.

## Security thesis

Security is treated as an empirical, continuously challenged property rather than a permanent certification.

The project is designed around several non-negotiable invariants:

- no normal arbitrary-target execution path;
- targets are enrolled and authorized before execution;
- outbound traffic is intended to pass through a non-bypassable Target Gate;
- internet-target policy denies private, loopback, link-local and metadata destinations;
- redirects are never blindly followed; v0.1.0 disables them, and any future redirect-following mode must re-authorize every hop;
- campaigns operate under request, concurrency and execution budgets;
- kill-switch state fails closed;
- synthetic identities and synthetic data are preferred over real client data;
- evidence is redacted before persistence;
- the Intruder does not hold production database master credentials;
- the target system remains the authority for authentication, authorization, containment and recovery.

## What this project is not

GyLiber Security Intruder is not intended to provide or become:

- an unrestricted penetration-testing platform;
- a credential-stuffing or password-cracking service;
- a DDoS tool;
- malware, persistence or lateral-movement infrastructure;
- a system for testing third-party targets without explicit authorization;
- a datastore for GyLiber banking records, staff records, trade secrets or other Command Center business data;
- proof that a system is absolutely secure.

No finite test suite can establish absolute security. Release evidence applies to the specific controls, revisions, environments and campaigns that were actually tested.

## Release progression

v0.1.0 established the closed-loop safety foundation: bounded target policy, Target Gate enforcement, one HTTP HEAD status probe, PASS/FAIL evidence, and tamper-detecting hashes.

v0.2.0 adds an explicit cryptographic trust layer around that loop:

```text
signed target + signed campaign
        ↓
signer role / validity / revocation / rollback verification
        ↓
existing Target Gate + safety budgets + kill switch
        ↓
bounded HTTP HEAD probe
        ↓
PASS / FAIL evidence
        ↓
signed evidence-bundle manifest
        ↓
independent bundle verification
```

A syntactically valid document is no longer sufficient to authorize execution. The signature, trusted key role, time window, revocation state, revision floor, and envelope/payload identity must all verify first.

## Current delivery status

v0.2.0 is the current minor-release candidate. It retains the v0.1.0 closed-loop safety controls and adds:

- canonical domain-separated Ed25519 signed envelopes;
- explicit target, campaign, and evidence signer roles;
- target/campaign validity windows and revocation checks;
- minimum-revision rollback protection;
- envelope identity binding to target/campaign payload identity;
- campaign envelope revision binding to `campaign_version`;
- evidence-signer preflight before network execution;
- signed evidence-bundle manifests;
- independent bundle verification that detects file tampering and unexpected bundle contents;
- private-key create-new handling, Unix `0600` output, redacted debug output, and zeroizing secret buffers;
- dependency license/source policy enforced with pinned `cargo-deny` in the Security workflow.

The release remains deliberately constrained: the armed network probe is still IP-literal `HTTP_HEAD_STATUS`; hostname/DNS execution, redirects, authentication/session campaigns, broader authorization/API testing, defense correlation, containment/recovery verification, and confidential durable evidence storage remain unarmed.

Release and operating material:

- [v0.2.0 release notes](docs/releases/v0.2.0.md)
- [v0.2.0 release evidence dossier](docs/releases/v0.2.0-evidence.md)
- [v0.2.0 operations](docs/OPERATIONS.md)
- [v0.2.0 client demonstration](docs/CLIENT_DEMO_v0.2.0.md)
- [v0.2.0 key management](docs/KEY_MANAGEMENT.md)
- [v0.2.0 threat model](docs/THREAT_MODEL_v0.2.0.md)
- [v0.2.0 progress report](docs/PROGRESS_2026-10-08.md)
- [Post-v0.2.0 next steps](docs/NEXT_STEPS.md)

## Architecture direction

v1.0.0 is designed as a **Rust Cargo workspace and modular monolith**, not a microservice fleet.

Planned crate boundaries:

- `intruder-core` — IDs, state machines, budgets and verdict taxonomy;
- `intruder-policy` — target authorization and environment policy;
- `intruder-net` — the only production owner of outbound HTTP, including the Target Gate;
- `intruder-evidence` — redaction, canonical evidence and integrity manifests;
- `intruder-report` — machine and human reports;
- `intruder-signing` — canonical signed envelopes, Ed25519 trust roles, validity, revocation and rollback protection;
- `intruder-cli` — constrained operator interface, signing/key authoring and independent bundle verification.

These boundaries are intended to scale to a future multi-developer team without prematurely distributing the runtime.

## Development and release controls

The automated v0.2.0 release gates are:

- `cargo fmt --check`;
- workspace compilation;
- unit/integration/fixture tests;
- Clippy with warnings denied;
- RustSec dependency audit;
- dependency license/source policy through pinned `cargo-deny`;
- CodeQL Rust analysis;
- release rebuild from the pinned toolchain;
- CycloneDX SBOM generation;
- SHA-256 release checksums;
- GitHub build-provenance and SBOM attestations.

All third-party GitHub Actions used by the repository are pinned to immutable commit SHAs. Dependabot opens bounded weekly update pull requests for Cargo and GitHub Actions dependencies.

Repository-level secret-scanning/push-protection verification, branch/ruleset enforcement evidence, and independent cross-provider backup/restore proof remain explicit governance follow-ups; they are not silently treated as complete by the v0.2.0 release.

Conventional Commits are used for repository history.

## Public-repository rule

The repository is initially public. Therefore every committed byte must be treated as permanently public.

Never commit:

- production credentials or session material;
- signing/private keys;
- real banking or financial records;
- staff personal information;
- private security evidence;
- private topology or operational secrets;
- proprietary payloads that GyLiber intends to keep as trade secrets.

Real security findings and sensitive evidence belong in an access-controlled system outside this repository.

## Hosting posture

v0.2.0 does not require a permanently exposed control-plane service.

The initial free deployment model is:

- GitHub as canonical source;
- GitHub Actions for CI and authorized ephemeral execution;
- GitHub Releases for versioned build outputs and checksums;
- an independent private backup/evidence provider before irreplaceable evidence is admitted.

A persistent hosted service is added only when operational requirements justify the extra attack surface.

## AI-assisted engineering disclosure

OpenAI models materially assist GyLiber with architecture, implementation, review and documentation for this project.

AI assistance is not a security trust anchor and does not constitute a security guarantee.

Generated work is subject to the same deterministic CI, security tests, fixture validation and release controls as human-authored work. AI systems are not intended to receive standing production credentials or hidden administrative authority.

## Responsible and authorized use

This software is for GyLiber-owned systems and systems for which GyLiber has explicit authorization to perform the configured security testing.

Do not use it against unrelated third-party systems.

## Versioning

The planned path to v1.0.0 is capability-gated rather than calendar-gated.

v0.1.0 established the closed-loop safety foundation. v0.2.0 adds cryptographic authorization and evidence authenticity. Later minor releases add synthetic authentication/session assurance, authorization/API testing, detection correlation, containment/recovery, extended safe adversarial coverage, durable assurance operations and final hardening.

The security gates are authoritative; version numbers may change if implementation evidence requires it.

## Ownership

Copyright © 2026 GyLiber. All rights reserved.

No permission to copy, modify, distribute, sublicense, sell, deploy or create derivative works is granted by publication of this repository unless GyLiber provides a separate written license.
