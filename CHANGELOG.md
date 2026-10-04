# Changelog

All notable GyLiber Security Intruder changes are recorded here.

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
