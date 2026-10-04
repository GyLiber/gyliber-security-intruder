# GyLiber Security Intruder

> Controlled adversarial security assurance for GyLiber-owned systems.

**Release:** v0.1.0 — closed-loop safety foundation  
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

## v0.1.0 objective

The first release is intentionally narrow and end-to-end. Its acceptance path is:

```text
approved local target definition
        |
        v
policy + Target Gate
        |
        v
bounded baseline HTTP request
        |
        v
typed oracle
        |
        v
redacted evidence
        |
        v
integrity hash
        |
        v
JSON + human report
```

The fixture laboratory must demonstrate both sides of the contract:

```text
secure fixture      -> expected PASS
vulnerable fixture  -> expected FAIL
fixed fixture       -> expected PASS
```

A scanner that can only report green is not accepted as security evidence.

## Current delivery status

v0.1.0 is the first release line of GyLiber Security Intruder. It provides a bounded, operator-executable assurance loop with:

- versioned target and campaign documents;
- strict target/campaign validation and non-executing planning;
- explicit kill-switch snapshots and centrally enforced safety budgets;
- IP-literal, no-redirect/no-retry HTTP HEAD probing through the Target Gate;
- PASS/FAIL oracle evaluation;
- metadata-only evidence with SHA-256 integrity sealing;
- checksummed create-new run bundles;
- repository-controlled secure → PASS, vulnerable → FAIL, fixed → PASS fixture proof;
- CI, RustSec, CodeQL, SBOM, checksum, provenance-attestation and SBOM-attestation release controls.

The release remains intentionally narrow: hostname execution, signed target/campaign authorization, authentication/session campaigns, broader API/authorization testing, defense correlation, containment/recovery verification, and confidential durable evidence storage are not yet armed.

Release material:

- [v0.1.0 release notes](docs/releases/v0.1.0.md)
- [v0.1.0 release evidence dossier](docs/releases/v0.1.0-evidence.md)
- [v0.1.0 operations](docs/OPERATIONS.md)
- [v0.1.0 delivery closure](docs/PROGRESS_2026-10-04.md)
- [v0.1.0 threat model](docs/THREAT_MODEL.md)
- [Disaster recovery and backup posture](docs/DISASTER_RECOVERY.md)
- [Post-v0.1.0 next steps](docs/NEXT_STEPS.md)

## Architecture direction

v1.0.0 is designed as a **Rust Cargo workspace and modular monolith**, not a microservice fleet.

Planned crate boundaries:

- `intruder-core` — IDs, state machines, budgets and verdict taxonomy;
- `intruder-policy` — target authorization and environment policy;
- `intruder-net` — the only production owner of outbound HTTP, including the Target Gate;
- `intruder-evidence` — redaction, canonical evidence and integrity manifests;
- `intruder-report` — machine and human reports;
- `intruder-cli` — constrained operator interface.

These boundaries are intended to scale to a future multi-developer team without prematurely distributing the runtime.

## Development and release controls

The automated v0.1.0 release gates are:

- `cargo fmt --check`;
- workspace compilation;
- unit/integration/fixture tests;
- Clippy with warnings denied;
- RustSec dependency audit;
- CodeQL Rust analysis;
- release rebuild from the pinned toolchain;
- CycloneDX SBOM generation;
- SHA-256 release checksums;
- GitHub build-provenance and SBOM attestations.

All third-party GitHub Actions used by the repository are pinned to immutable commit SHAs. Dependabot opens bounded weekly update pull requests for Cargo and GitHub Actions dependencies.

Controls that are **not** represented as complete merely because v0.1.0 shipped are tracked in the requirements/gap register. In particular, dedicated dependency-license/source policy, repository-level secret-scanning/push-protection verification, branch/ruleset enforcement evidence, and independent cross-provider backup/restore proof remain explicit follow-up work.

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

v0.1.0 does not require a permanently exposed control-plane service.

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

v0.1.0 establishes the closed-loop safety foundation. Later minor releases add signed campaign integrity, authentication/session assurance, authorization/API testing, detection correlation, containment/recovery, extended safe adversarial coverage, durable assurance operations and final hardening.

The security gates are authoritative; version numbers may change if implementation evidence requires it.

## Ownership

Copyright © 2026 GyLiber. All rights reserved.

No permission to copy, modify, distribute, sublicense, sell, deploy or create derivative works is granted by publication of this repository unless GyLiber provides a separate written license.
