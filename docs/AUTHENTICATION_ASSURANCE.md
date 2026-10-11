# Synthetic Authentication Assurance — v0.3.0 Contract

**Product:** GyLiber Security Intruder  
**Milestone:** v0.3.0 synthetic authentication/session assurance  
**Status:** contract foundation implemented; network authentication executor not yet armed

## Purpose

This unit introduces the typed authorization contract for synthetic authentication testing while preserving the v0.2.0 signed-target/signed-campaign trust boundary.

It does **not** implement credential stuffing, password guessing, production login testing, or storage of real credentials.

## Contract boundary

An authentication campaign contains only:

- campaign and target identifiers;
- one enrolled login endpoint;
- a synthetic actor reference;
- an opaque synthetic credential reference;
- a bounded number of attempts;
- the expected HTTP status;
- the expected authentication outcome.

It has no fields for:

- username values;
- passwords;
- bearer tokens;
- cookies;
- session IDs;
- MFA secrets;
- recovery codes;
- production client/staff credentials.

Unknown JSON fields are rejected. A campaign that attempts to include a raw `password` field therefore fails parsing before authorization.

## Synthetic references

`actor_id` and `credential_ref` are identifiers, not secrets.

They use a deliberately narrow identifier alphabet:

```text
A-Z a-z 0-9 . _ -
```

and are limited to 128 bytes.

A later credential-provider adapter may resolve `credential_ref` to a synthetic fixture secret at execution time. That secret-resolution mechanism is intentionally outside the campaign document.

## Environment gate

Authentication campaigns are initially armed only for:

- `LAB`;
- `STAGING`.

They fail closed for:

- `CANARY`;
- `PRODUCTION`.

Production Command Center authentication testing remains gated on explicit target ownership, workload identity, synthetic-account lifecycle, key custody, evidence storage, and operational authorization.

## Attempt budget

The target's existing `max_auth_attempts` safety budget is now a required positive invariant.

Campaign validation requires:

```text
1 <= requested attempts <= target.max_auth_attempts
```

The mutable `BudgetTracker::try_record_auth_attempt()` remains the execution-time accounting primitive. The later executor must consume that budget before each actual login attempt.

This keeps document authorization and runtime consumption separate:

```text
campaign validation
    ↓
requested attempts fit target ceiling
    ↓
signed campaign verification
    ↓
future executor
    ↓
consume one auth-attempt unit BEFORE each login request
```

## Outcomes

The v1 authentication contract defines:

- `AUTHENTICATED`;
- `REJECTED`;
- `LOCKED_OUT`.

A `LOCKED_OUT` expectation requires at least two bounded attempts. This avoids describing a one-request scenario as lockout verification.

## Signed authorization

Authentication campaigns are signed with the existing v0.2.0 campaign-signing role.

Verification still enforces:

- campaign signer trust;
- signer validity and revocation;
- campaign revision rollback floor;
- envelope campaign ID = payload campaign ID;
- signed revision = payload `campaign_version`;
- verified signed target;
- target URL enrollment;
- LAB/STAGING gate;
- authentication-attempt ceiling.

The v0.3.0 feature therefore extends v0.2.0 rather than bypassing it.

## Current example

`campaigns/authentication/fixture-login.campaign.json` is a contract/example document for the upcoming synthetic fixture executor.

It is not yet an executable end-to-end login demonstration. The next implementation unit must add:

1. a synthetic authentication fixture/target profile;
2. safe credential-reference resolution;
3. an authentication HTTP executor;
4. one-attempt budget consumption before each request;
5. redacted authentication evidence;
6. PASS/FAIL/LOCKED_OUT fixture proofs.

## Non-goals

This contract must not become a general password-testing format.

v0.3.0 does not arm:

- arbitrary username/password lists;
- credential spraying;
- password cracking;
- MFA bypass;
- CAPTCHA bypass;
- production account lockout;
- real employee/client credentials.
