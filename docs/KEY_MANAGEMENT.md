# Key Management — v0.2.0

**Product:** GyLiber Security Intruder  
**Scope:** signed target/campaign authorization and signed run-bundle manifests  
**Status:** v0.2.0 trust policy

## 1. Purpose

v0.2.0 adds Ed25519 signatures so authorization and evidence authenticity are no longer represented by hashes alone.

A valid signature is **necessary but not sufficient**. The verifier also requires:

- the signing key to be explicitly trusted;
- the key to have the required role;
- target/campaign authorization to be inside the key's current validity period;
- the key not to be revoked;
- target/campaign revisions not to fall below the configured rollback floor;
- envelope identity to match the signed payload identity.

## 2. Roles

The trust model defines three roles:

| Role | Authority |
|---|---|
| `TARGET_SIGNER` | Enrolls a target boundary that the Intruder may assess |
| `CAMPAIGN_SIGNER` | Authorizes a specific campaign against an enrolled target |
| `EVIDENCE_SIGNER` | Authenticates the manifest of a produced run bundle |

For the **synthetic LAB client demo only**, `intruder trust bootstrap-lab` may grant all three roles to one generated key. That is deliberately convenient for demonstration and local fixtures.

For staging/production authorization, role separation is the target posture:

- target signer: high-trust/offline or tightly controlled;
- campaign signer: operational authorization, narrower custody;
- evidence signer: runtime/service identity scoped only to evidence signing.

A single all-powerful permanent production key is prohibited.

## 3. Private-key custody

Private signing-key files are secrets.

Repository rules:

- never commit a private signing key;
- `*.signing-key.json`, `keys/private/`, and `trust/private/` are git-ignored;
- private-key output uses create-new semantics;
- on Unix, generated private-key files are created with mode `0600`;
- serialized private-key bytes used during file creation are held in zeroizing memory;
- the Rust signing-key type zeroizes secret material on drop;
- debug formatting redacts secret key bytes.

The public repository may contain public keys and trust-policy examples, but no production private key.

## 4. Validity and rotation

Signed target/campaign documents have bounded validity. The CLI defaults to one day and rejects requested document validity beyond 30 days.

The LAB bootstrap trust policy defaults to seven days and rejects requested trust windows beyond one year.

Recommended production rotation policy is intentionally not hard-coded before GyLiber selects its operational key custody provider. Before non-fixture targets are authorized, GyLiber must explicitly choose:

- key custody technology/account;
- responsible role/owner;
- routine rotation interval;
- emergency rotation procedure;
- backup/recovery method;
- audit/log retention.

## 5. Revocation

Trust policy supports `revoked_at_unix`.

For target and campaign authorization, a key at or beyond its revocation time is rejected immediately.

Evidence verification differs deliberately: historical evidence is checked against signer trust **at the evidence issuance time**. A later routine key expiry does not make old authentic evidence unverifiable. Evidence signed at or after a recorded revocation time is rejected.

If future incident policy requires retrospective distrust of a compromised key, that must be represented explicitly as an incident/revocation decision rather than silently changing normal archival semantics.

## 6. Rollback protection

Every trusted target/campaign identity has a minimum accepted revision.

A correctly signed but older authorization document is rejected when its revision falls below that floor.

Campaign envelopes additionally bind their signed revision to the campaign's own `campaign_version`, preventing an envelope from presenting one revision while carrying a different campaign version.

## 7. Signing-key preflight

Before a network run begins, the evidence private key is checked against the trusted public key, required evidence role, validity window, and revocation state.

If this preflight fails, the Intruder does not perform the HTTP probe.

This avoids producing an otherwise valid security result that cannot be authenticated afterward.

## 8. v0.2.0 limits

v0.2.0 does not claim production KMS/HSM integration.

The file-based private-key path exists for controlled synthetic/LAB operation and client demonstration. Production authorization remains gated on a GyLiber key-custody decision and the broader infrastructure controls recorded in `docs/NEXT_STEPS.md`.
