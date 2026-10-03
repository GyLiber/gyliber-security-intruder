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

The project is pre-1.0. Only the latest development line receives security fixes unless a release notice states otherwise.

## Authorization boundary

This project is intended only for GyLiber-owned targets or targets for which GyLiber has explicit authorization to test.

Reports that depend on attacking unrelated third-party systems are out of scope.

## Security guarantees

No release is represented as absolutely secure. Assurance statements apply only to the controls, target revision, environment, test profile and date that were actually exercised.

## Response expectations

Security reports are triaged by severity, reproducibility, affected trust boundary and potential exposure. Remediation may include code changes, credential rotation, target isolation, evidence invalidation and incident-response procedures.
