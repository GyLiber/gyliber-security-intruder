# Operations — v0.2.0

GyLiber Security Intruder v0.2.0 is a constrained command-line security assurance tool for GyLiber-owned or explicitly authorized targets.

v0.2.0 retains the v0.1.0 Target Gate, budgets, kill-switch, bounded HTTP HEAD probe, evidence sealing, and PASS/FAIL fixture proof, then adds cryptographic authorization and authenticated bundle manifests.

## Supported release platform

The prebuilt v0.2.0 release target is Linux x86_64 using the GNU userspace target.

Other platforms may build from source but are not release-supported by v0.2.0.

## Data and authorization posture

Use synthetic/security-test data only.

Do not place production credentials, real staff/client data, banking information, production sessions, or private production topology in repository-controlled target/campaign material.

A network run requires:

- a signed target envelope;
- a signed campaign envelope;
- a trust policy authorizing the relevant signer roles;
- a currently trusted evidence private key;
- an explicit resolved kill-switch snapshot.

## 1. Generate a LAB signing identity

Use a private working directory outside the repository:

```bash
mkdir -p /tmp/gyliber-intruder-v020

intruder key generate \
  --key-id client-demo-authority \
  --private-out /tmp/gyliber-intruder-v020/client-demo.signing-key.json \
  --public-out /tmp/gyliber-intruder-v020/client-demo.public-key.json
```

Private-key output uses create-new semantics. On Unix it is created with mode `0600`.

## 2. Bootstrap LAB trust

```bash
intruder trust bootstrap-lab \
  --public-key /tmp/gyliber-intruder-v020/client-demo.public-key.json \
  --target-id fixture-local \
  --campaign-id baseline-health \
  --out /tmp/gyliber-intruder-v020/trust-policy.json
```

The LAB bootstrap may assign target, campaign, and evidence roles to one key for demonstration. That is not the intended production key-separation model.

## 3. Author and sign the target

Unsigned target validation remains available while authoring:

```bash
intruder target validate policies/lab/fixture-local.target.json
```

Sign it:

```bash
intruder target sign \
  policies/lab/fixture-local.target.json \
  --key /tmp/gyliber-intruder-v020/client-demo.signing-key.json \
  --revision 1 \
  --out /tmp/gyliber-intruder-v020/fixture-local.target.signed.json
```

Verify it:

```bash
intruder target verify \
  /tmp/gyliber-intruder-v020/fixture-local.target.signed.json \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

## 4. Author and sign the campaign

```bash
intruder campaign validate \
  --target policies/lab/fixture-local.target.json \
  campaigns/baseline/fixture-health.campaign.json
```

```bash
intruder campaign sign \
  --target policies/lab/fixture-local.target.json \
  campaigns/baseline/fixture-health.campaign.json \
  --key /tmp/gyliber-intruder-v020/client-demo.signing-key.json \
  --out /tmp/gyliber-intruder-v020/fixture-health.campaign.signed.json
```

Verify both signed authorization documents:

```bash
intruder campaign verify \
  --target /tmp/gyliber-intruder-v020/fixture-local.target.signed.json \
  /tmp/gyliber-intruder-v020/fixture-health.campaign.signed.json \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

## 5. Inspect the verified non-executing plan

```bash
intruder campaign plan \
  --target /tmp/gyliber-intruder-v020/fixture-local.target.signed.json \
  /tmp/gyliber-intruder-v020/fixture-health.campaign.signed.json \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

A successful plan states:

```text
authorization=SIGNED_VERIFIED
execution=NOT_STARTED
```

## 6. Execute an authorized LAB campaign

The example campaign references a local IP-literal service at `127.0.0.1:8080/health`. An authorized local fixture/service must be running before this manual example is executed.

```bash
intruder run \
  --target /tmp/gyliber-intruder-v020/fixture-local.target.signed.json \
  --campaign /tmp/gyliber-intruder-v020/fixture-health.campaign.signed.json \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json \
  --evidence-signing-key /tmp/gyliber-intruder-v020/client-demo.signing-key.json \
  --kill-switch policies/lab/kill-switch-clear.json \
  --run-id client-demo-001 \
  --out-dir /tmp/gyliber-intruder-v020/client-demo-001
```

Evidence-signer trust is checked before the network request is allowed.

## 7. Verify the emitted bundle independently

```bash
intruder bundle verify \
  --dir /tmp/gyliber-intruder-v020/client-demo-001 \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

The verifier authenticates the signed manifest, verifies every manifested file digest, checks the checksum manifest, and rejects unexpected/non-regular bundle contents.

## Fail-closed behavior

v0.2.0 rejects, before or during verification as appropriate:

- an untrusted signer;
- a signer without the required role;
- expired or not-yet-valid authorization;
- authorization signed by a revoked key;
- target/campaign revision below the trusted floor;
- envelope identity that does not match the payload identity;
- campaign envelope revision that does not match `campaign_version`;
- a private evidence key that does not match the trusted public key;
- a modified signed payload;
- a modified evidence-bundle file;
- unexpected files in a verified bundle.

## Network safety retained from v0.1.0

v0.2.0 still arms only `HTTP_HEAD_STATUS` on IP-literal targets. Redirects, automatic retries, ambient proxy inheritance, and hostname execution remain disabled. Private/special network ranges remain controlled by the Target Gate and environment policy.

## Key custody boundary

File-based private keys are a controlled LAB mechanism, not a production KMS/HSM claim.

Before production/non-fixture authorization, GyLiber must select key custody, role ownership, backup, rotation, and emergency revocation procedures.

## Release verification

Release artifacts include SHA-256 checksums, CycloneDX SBOM, build-provenance attestation, and binary-SBOM attestation. The exact release commit must also pass normal CI, RustSec, dependency license/source policy, and CodeQL before publication.
