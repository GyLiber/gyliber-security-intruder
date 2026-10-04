# Operations — v0.1.0

GyLiber Security Intruder v0.1.0 is a constrained command-line security assurance tool. This document covers only the capabilities armed in the v0.1.0 release.

## Supported release platform

The v0.1.0 binary release is built and tested for Linux x86_64 using the GNU userspace target. Other platforms may build from source but are not release-supported by v0.1.0.

## Authorized-use boundary

Use the Intruder only against GyLiber-owned systems or systems for which GyLiber has explicit authorization to perform the configured security testing. v0.1.0 is intentionally limited to synthetic/LAB-style baseline assurance. It is not an unrestricted scanner.

## Operator flow

Validate a target:

```bash
intruder target validate policies/lab/fixture-local.target.json
```

Validate a campaign against that target:

```bash
intruder campaign validate   --target policies/lab/fixture-local.target.json   campaigns/baseline/fixture-health.campaign.json
```

Inspect the non-executing plan:

```bash
intruder campaign plan   --target policies/lab/fixture-local.target.json   campaigns/baseline/fixture-health.campaign.json
```

Run an authorized campaign:

```bash
intruder run   --target policies/lab/fixture-local.target.json   --campaign campaigns/baseline/fixture-health.campaign.json   --kill-switch policies/lab/kill-switch-clear.json   --run-id example-run-001   --out-dir evidence/example-run-001
```

The example campaign references a local IP-literal endpoint. The operator is responsible for running an authorized fixture or service at the configured address and port.

## Run bundle

A successful run creates a new output directory containing `report.json`, `report.txt`, `run.json`, and `SHA256SUMS`. The output directory must not already exist. Individual files are also opened with create-new semantics.

## Safety behavior

v0.1.0 requires versioned target and campaign documents plus an explicit kill-switch snapshot; enforces target scheme/host/path and resolved-address policy; enforces total/rate/concurrency/authentication/time budgets; performs only the armed `HTTP_HEAD_STATUS` probe; disables redirects, retries, ambient proxies, and hostname execution; and never persists response bodies or HTTP header values.

## Evidence handling

Evidence is metadata-only in v0.1.0. SHA-256 sealing detects modification but does not prove signer identity. Digital signatures and signed target/campaign registries are planned for v0.2.0.

## Kill-switch posture

`intruder kill-switch-status` reports unresolved state as `SAFE_DEFAULT_STOP`. Execution requires an explicit kill-switch snapshot file.

## Recovery and preservation

Source and tagged release artifacts are stored by GitHub. The release includes binary checksums, a CycloneDX SBOM, and GitHub artifact attestations. Before real confidential GyLiber evidence is admitted, a private independent backup/evidence store and tested restore procedure remain required.
