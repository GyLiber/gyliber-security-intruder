# Threat Model — v0.2.0

**Product:** GyLiber Security Intruder  
**Scope:** v0.2.0 integrity/authenticity release  
**Last reviewed:** 2026-10-08

## 1. Security objective

v0.2.0 must ensure that the existing bounded assurance loop cannot execute merely because a target/campaign document is syntactically valid. Authorization must be attributable to trusted signing identities, while emitted evidence bundles must be independently attributable to a trusted evidence signer.

The Intruder remains a constrained verifier, not a general-purpose attack platform.

## 2. New protected assets

In addition to the v0.1.0 assets, v0.2.0 protects:

- target enrollment authority;
- campaign authorization authority;
- signing-key role separation;
- authorization validity/revocation state;
- minimum accepted authorization revisions;
- evidence-manifest authenticity;
- operator confidence that signed evidence belongs to the claimed run identity.

## 3. New trust boundaries

### Signing key boundary

Private Ed25519 keys are authorization secrets. Public keys and trust policy determine which identities may sign targets, campaigns, or evidence.

LAB tooling may combine roles in one key for demonstration. Production role separation remains required before non-fixture authorization.

### Signed document boundary

Canonical, domain-separated envelope bytes are signed. Verification checks cryptographic validity plus trust role, validity, revocation, revision floor, and payload identity.

### Evidence-manifest boundary

The signed manifest binds run identity and file SHA-256 digests to an evidence signer. Bundle verification rejects altered files and unexpected bundle contents.

## 4. Principal threats and controls

| Threat | v0.2.0 control |
|---|---|
| Unsigned document used for execution | `intruder run` accepts signed target/campaign envelopes only |
| Signed document reused with different payload identity | Envelope ID must match target/campaign payload identity |
| Valid but stale authorization rolled back | Minimum trusted revision floors |
| Campaign version misrepresented by envelope | Signed revision must equal `campaign_version` |
| Signer has wrong authority | Explicit target/campaign/evidence signer roles |
| Expired authorization reused | Envelope and trusted-key validity checks |
| Revoked key continues authorizing work | Revocation-time enforcement |
| Evidence key misconfigured after authorization | Evidence private-key/public-key trust preflight before network execution |
| Signed payload modified | Ed25519 strict verification fails |
| Run file modified after execution | Signed manifest digest verification fails |
| Extra file smuggled into verified bundle | Exact expected bundle file set enforced |
| Private key leaked through debug output | Redacted debug representation |
| Private key left in transient serialization buffers | Zeroizing secret buffers/types |
| Dependency source/license drifts outside policy | Permanent `cargo-deny` license/source Security gate |

## 5. Archival evidence semantics

Target and campaign authorization are evaluated against current trust state.

Historical evidence is verified against signer trust at evidence issuance time so normal later key expiry does not destroy archival verifiability. Evidence created at or after a recorded revocation time is rejected.

Retrospective distrust after key compromise requires an explicit incident decision; it is not silently inferred from routine expiry.

## 6. Residual risks

Still unresolved before production/high-consequence use:

- file-based key custody is not a KMS/HSM;
- GitHub branch/ruleset protection requires repository-administration verification;
- GitHub secret-scanning/push-protection requires repository-administration verification;
- independent cross-provider source/release backup and restore drill remain outstanding;
- no production Command Center target has been authorized;
- hostname/DNS execution remains unarmed;
- confidential durable evidence storage is not implemented;
- incident-specific retrospective signer distrust is procedural rather than a separate cryptographic revocation ledger.

## 7. Review triggers

Update this threat model when:

- production key custody is introduced;
- signer-role ownership changes;
- hostname/redirect execution is armed;
- a new probe family is enabled;
- authentication/session testing is added;
- persistent confidential evidence storage is introduced;
- Command Center staging/production becomes a target;
- a signing-key compromise occurs.
