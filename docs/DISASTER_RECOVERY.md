# Disaster Recovery & Backup Posture

**Product:** GyLiber Security Intruder  
**Scope:** source, release material and synthetic v0.1.0 evidence  
**Last reviewed:** 2026-10-04

## 1. Current recoverable assets

The v0.1.0 project does not require a production database or authoritative hosted application state.

Current important assets are:

- Git source/history on GitHub;
- repository documentation and workflow definitions;
- `v0.1.0` Git tag;
- GitHub Release assets;
- SHA-256 checksum manifest;
- CycloneDX SBOM;
- GitHub build-provenance and SBOM attestations;
- synthetic fixtures, schemas, target/campaign examples;
- operator-created run bundles, when retained by the operator.

No real client/business/staff/banking data is admitted to the Intruder v0.1.0 storage model.

## 2. Recovery scenarios

### Developer laptop loss

Expected recovery:

1. restore account access using GyLiber-controlled account recovery;
2. clone the canonical GitHub repository on a clean machine;
3. verify the desired tag/commit;
4. install the pinned Rust toolchain;
5. run CI-equivalent local checks;
6. retrieve release assets/checksums from the GitHub Release when needed.

The project does not depend on a particular developer laptop for source or release continuity.

### Corrupted local working copy

Discard the local copy, clone from GitHub, and verify against the expected commit/tag.

### Lost local run bundle

v0.1.0 does **not** claim durable storage for local run bundles. If a run bundle is operationally important, it must be copied to an approved durable evidence store; that store does not yet exist.

### GitHub account or provider loss

This is the principal unresolved recovery gap. GitHub currently holds the canonical source and release record. Provider durability is not treated as an independent backup.

Before real confidential evidence or livelihood-critical reliance:

- create encrypted independent source/release archives in a separately protected provider/account;
- include a `git bundle` or equivalent full-history archive;
- preserve release assets, checksums, release notes and attestation references;
- protect backup credentials separately from normal development credentials;
- perform and evidence a restore drill.

## 3. Current RPO/RTO posture

No formal RPO/RTO has yet been accepted for GyLiber Security Intruder.

For v0.1.0 synthetic development/release material, GitHub availability is the operational dependency. Formal RPO/RTO becomes mandatory before the system carries irreplaceable evidence or production assurance obligations.

## 4. Restore verification

A backup is not considered proven until restored.

Current status:

- source recovery from GitHub: operational design documented;
- independent provider copy: **not yet implemented**;
- independent restore drill: **not yet performed**.

These remain explicit next actions.

## 5. Release verification record

The released v0.1.0 source identity is:

- tag: `v0.1.0`;
- commit: `b98e0a29864c70db3abc9ed023d33446d426fb89`;
- release: https://github.com/GyLiber/gyliber-security-intruder/releases/tag/v0.1.0.

Release consumers can additionally verify the published `SHA256SUMS`, CycloneDX SBOM and GitHub attestations recorded in `docs/releases/v0.1.0-evidence.md`.

## 6. Escalation gate

Do not admit real confidential/security evidence solely because the application version increases.

Independent backup, tested restore, key custody, access control, retention policy and accepted RPO/RTO must be evidenced before irreplaceable data becomes authoritative in this system.
