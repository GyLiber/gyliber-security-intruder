# Security Policy

## Scope

GyLiber Security Intruder is security-sensitive software. Security reports about this repository or its deployed GyLiber-owned test infrastructure must be handled privately.

## Do not disclose exploitable details publicly

Do not open a public issue containing:

- exploitable vulnerabilities;
- credentials, tokens or session material;
- private target topology;
- production security evidence;
- attack transcripts against live GyLiber infrastructure;
- personally identifiable or financial information.

Until a dedicated private disclosure channel is established, the repository owner should be contacted privately through an authenticated channel already controlled by GyLiber.

## Supported versions

| Line | Support status |
|---|---|
| v0.2.x | Supported; only the latest patch release in this line receives fixes |
| v0.1.x | Superseded by v0.2.x |
| `main` | Active development toward v0.3.0 |

The project remains pre-1.0, so compatibility may change between minor versions when a security boundary requires it. Release notes and migration guidance must document externally material changes.

Release artifacts are distributed with SHA-256 checksums, a CycloneDX SBOM, build-provenance attestation, and binary-SBOM attestation. v0.2.0 additionally requires dependency license/source policy success before release publication.

## Authorization boundary

This project is intended only for GyLiber-owned targets or targets for which GyLiber has explicit authorization to test.

Reports that depend on attacking unrelated third-party systems are out of scope.

## Security guarantees

No release is represented as absolutely secure. Assurance statements apply only to the controls, target revision, environment, test profile and date that were actually exercised.

## Response expectations

Security reports are triaged by severity, reproducibility, affected trust boundary and potential exposure. Remediation may include code changes, credential rotation, target isolation, evidence invalidation and incident-response procedures.
