# Client Demonstration — v0.2.0

This demonstration is designed to externalize the v0.2.0 trust improvement without requiring production credentials or a production GyLiber target.

It uses only the repository's synthetic LAB target/campaign.

## What the client should see

The central change from v0.1.0 is:

```text
v0.1.0
validated document → safety gates → probe → hashed evidence

v0.2.0
signed + trusted document
        ↓
role / time / revocation / rollback verification
        ↓
safety gates
        ↓
probe
        ↓
signed evidence-bundle manifest
        ↓
independent bundle verification
```

A hash can tell us that bytes changed. v0.2.0 additionally lets us verify **which trusted signing identity authorized the document or authenticated the evidence bundle**.

## 1. Generate a LAB signing identity

Use a private working directory outside Git:

```bash
mkdir -p /tmp/gyliber-intruder-v020
intruder key generate \
  --key-id client-demo-authority \
  --private-out /tmp/gyliber-intruder-v020/client-demo.signing-key.json \
  --public-out /tmp/gyliber-intruder-v020/client-demo.public-key.json
```

The private key must never be committed.

## 2. Bootstrap synthetic LAB trust

```bash
intruder trust bootstrap-lab \
  --public-key /tmp/gyliber-intruder-v020/client-demo.public-key.json \
  --target-id fixture-local \
  --campaign-id baseline-health \
  --out /tmp/gyliber-intruder-v020/trust-policy.json
```

The LAB bootstrap deliberately grants target, campaign, and evidence roles to one key for a compact demonstration. This is not the intended production separation model.

## 3. Sign the target

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

## 4. Sign the campaign

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

## 5. Show the verified, non-executing plan

```bash
intruder campaign plan \
  --target /tmp/gyliber-intruder-v020/fixture-local.target.signed.json \
  /tmp/gyliber-intruder-v020/fixture-health.campaign.signed.json \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

The plan must state:

```text
authorization=SIGNED_VERIFIED
execution=NOT_STARTED
```

and identify target/campaign signer IDs and revisions.

## 6. Demonstrate fail-closed tamper rejection

Make a disposable copy of the signed campaign and alter any signed payload value—for example the expected HTTP status.

Verification must fail with Ed25519 signature verification failure.

This is an important client demonstration: the file can still be syntactically valid JSON while being cryptographically unauthorized.

Automated tests also cover:

- wrong signer;
- expired authorization;
- revoked signer;
- signer role mismatch;
- rollback below the trusted revision floor;
- envelope/payload identity mismatch;
- campaign revision mismatch;
- evidence-file tampering.

## 7. Execute and authenticate a run

The existing synthetic campaign points to `127.0.0.1:8080/health`; an authorized local fixture/service must be running there before executing this manual step.

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

The resulting bundle contains the v0.1 report material plus a signed manifest.

## 8. Verify the bundle independently

```bash
intruder bundle verify \
  --dir /tmp/gyliber-intruder-v020/client-demo-001 \
  --trust-policy /tmp/gyliber-intruder-v020/trust-policy.json
```

Changing a manifested report/run file or adding unexpected content to the bundle must cause verification to fail.

## Client takeaway

v0.2.0 is not “more attack capability.” It is a stronger **trust boundary** around the existing safe assurance loop:

- authorization must be cryptographically attributable;
- stale/expired/revoked/rolled-back authorization fails closed;
- evidence bundles are cryptographically attributable;
- tampering remains detectable independently of the original run.
