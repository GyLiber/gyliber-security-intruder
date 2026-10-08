# Changelog

All notable GyLiber Security Intruder changes are recorded here.

## [0.2.0] — 2026-10-08

### Added

- Canonical domain-separated Ed25519 signed envelopes.
- Trusted signer roles for targets, campaigns, and evidence manifests.
- Signature validity windows, revocation checks, and minimum-revision rollback protection.
- Signed target/campaign identity and campaign-version binding.
- Evidence-signer preflight before network execution.
- Signed run-bundle manifests and independent bundle verification.
- CLI commands for key generation, LAB trust bootstrap, target/campaign signing and verification, verified planning, signed execution, and bundle verification.
- Private-key create-new handling, Unix `0600` output, redacted debug formatting, and zeroizing secret buffers.
- Dependency license/source policy using pinned `cargo-deny` in the Security workflow.
- v0.2 key-management, threat-model, client-demonstration, operations, and release documentation.

### Changed

- Network execution now requires cryptographically verified signed target and campaign documents.
- Run bundles now authenticate file digests with a signed evidence manifest in addition to SHA-256 checksums.
- Tokio maintenance line moved to `~1.53`, resolving Tokio 1.53.2 in the release dependency graph.

### Security boundaries

- File-based private keys are for controlled synthetic/LAB operation; production key custody/KMS/HSM integration remains unarmed.
- Hostname/DNS execution, redirect following, authentication/session campaigns, production Command Center authorization, and confidential durable evidence storage remain unarmed.
- Synthetic/security-test data only.

## [0.1.0] — 2026-10-04

### Added

- Rust modular-monolith workspace and constrained operator CLI.
- Versioned target and campaign contracts with JSON Schema references.
- Target Gate scheme/host/path and resolved-network authorization.
- Private/link-local/loopback/special-range and cloud-metadata defenses.
- Global/target/campaign kill-switch semantics.
- Request total/rate/concurrency/authentication/time budgets.
- Bounded IP-literal HTTP HEAD metadata probe.
- Metadata-only evidence records with deterministic SHA-256 integrity seals.
- Verified human and JSON reporting.
- Checksummed create-new run bundles with tool/source metadata.
- Persistent secure/vulnerable/fixed adversarial fixture triplet.
- CI, RustSec, CodeQL, SBOM, checksum, and provenance/SBOM attestation release gates.

### Security boundaries

- No unrestricted arbitrary-target scanner command.
- Hostname execution, redirects, retries, ambient proxies, and response-body/header-value capture remain disabled in v0.1.0.
- Synthetic/security-test data only.
