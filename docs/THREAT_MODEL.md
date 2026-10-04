# Threat Model — v0.1.0

**Product:** GyLiber Security Intruder  
**Scope:** released v0.1.0 closed-loop safety foundation  
**Last reviewed:** 2026-10-04  
**Authoritative release:** `v0.1.0` at `b98e0a29864c70db3abc9ed023d33446d426fb89`

## 1. Security objective

The Intruder must provide controlled adversarial verification without becoming a reusable unrestricted attack framework or a privileged authority over the systems it tests.

v0.1.0 therefore prioritizes **containment of the verifier itself** over breadth of offensive capability.

## 2. Protected assets

v0.1.0 protects:

- target authorization boundaries;
- safety-budget state;
- kill-switch decisions;
- release/build integrity;
- test and run evidence integrity;
- the public repository's freedom from production secrets and restricted business data;
- operator trust in PASS/FAIL results for the exact tested fixture/campaign.

The Intruder does not own GyLiber banking records, staff records, production session stores, production database master credentials or other Command Center business data.

## 3. Trust boundaries

### Repository / CI boundary

Source, workflows and release configuration are public and reviewed through Git history and automated gates. Workflow tokens are least-privilege by job.

### Operator / configuration boundary

The operator supplies versioned target, campaign and kill-switch documents. Unknown fields and target mismatches are rejected. v0.1.0 documents are not digitally signed; signed authorization is the primary v0.2.0 trust objective.

### Network boundary

All armed HTTP execution passes through `intruder-net` and the Target Gate. v0.1.0 executes only IP-literal targets; hostname execution is unarmed.

### Evidence boundary

The HTTP probe retains metadata only: status, content length and header names. Response bodies and header values are not evidence inputs. Evidence is SHA-256 sealed and reverified before reporting.

### Release boundary

The release workflow independently rebuilds and tests, waits for exact-commit CI and Security success, generates SBOM/checksums, creates attestations, and only then creates the GitHub Release/tag.

## 4. Principal threats and v0.1.0 controls

| Threat | v0.1.0 control |
|---|---|
| Intruder repurposed for arbitrary targets | No normal `scan <url>` interface; versioned target/campaign validation |
| SSRF/private-network escape | Resolved/literal IP policy; private/link-local/loopback/special-range controls; cloud metadata denial |
| DNS rebinding | Hostname execution is not armed in v0.1.0 |
| Redirect escape | Redirects are disabled in v0.1.0 |
| Proxy-based egress bypass | Ambient proxy inheritance disabled |
| Unbounded request behavior | Total/rate/concurrency/time/auth budgets enforced centrally |
| Kill-switch bypass | Kill-switch authorization occurs before request capacity is consumed |
| Evidence tampering | Deterministic SHA-256 integrity sealing + bundle checksum manifest |
| Evidence over-collection | Metadata-only HTTP evidence; no body/header-value persistence |
| Secret leakage from public repo | Synthetic/public-safe fixtures/configuration only; no production credentials required |
| Dependency compromise | Locked dependencies, RustSec audit, Dependabot, CodeQL; dedicated license/source policy still open |
| CI/release tampering | SHA-pinned Actions, least-privilege permissions, exact-commit release gates, attestations |
| AI becomes hidden trust principal | No AI runtime identity/standing production credential; deterministic gates remain authoritative |
| False claim of absolute security | Release/docs scope claims to tested controls/revision/mode and list known limitations |

## 5. Assumptions

v0.1.0 assumes:

- GitHub account/repository access is controlled by GyLiber;
- the operator uses the Intruder only against GyLiber-owned or explicitly authorized targets;
- the kill-switch snapshot supplied for execution is the intended snapshot;
- the local/CI fixture environment is synthetic and non-sensitive;
- release consumers verify release identity/checksums/attestations as appropriate.

## 6. Known residual risks

Not yet solved in v0.1.0:

- target/campaign documents are unsigned;
- signer identity, rotation, revocation and authorization expiry are not implemented;
- no hostname/DNS execution exists yet, so DNS-rebinding-safe connection binding is not implemented;
- no independent cross-provider source/release backup or restore drill has been evidenced;
- dedicated dependency-license/source policy is not yet enforced;
- GitHub secret-scanning/push-protection and branch/ruleset settings require repository-administration verification;
- SHA-256 evidence integrity does not authenticate who produced the evidence;
- no production Command Center exercise has been authorized.

## 7. Review triggers

Update this threat model when any of the following becomes true:

- a new probe family is armed;
- hostname or redirect execution is enabled;
- signed authorization is introduced;
- persistent evidence storage is introduced;
- real confidential/security findings are admitted;
- a public network service/control plane is deployed;
- Command Center staging/production becomes a target;
- staff roles or multi-user access are introduced;
- a security incident invalidates an assumption.
