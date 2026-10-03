# Contributing

GyLiber Security Intruder is currently developed under direct GyLiber engineering control.

## Change discipline

Use Conventional Commits. Keep commits as correct, reviewable units of work.

Examples:

- `feat(policy): validate target authorization window`
- `fix(net): reject redirect to private destination`
- `test(safety): cover IPv6 loopback rejection`
- `docs: record target gate ADR`
- `ci: add dependency audit`

## Required checks

Code changes are expected to pass formatting, compilation, tests, Clippy, dependency/advisory checks and repository security analysis.

## Security-sensitive changes

The following require heightened review:

- target authorization;
- outbound networking;
- URL/DNS/redirect handling;
- campaign integrity/signatures;
- secrets;
- evidence redaction;
- kill switches;
- safety budgets;
- containment/recovery integration;
- CI/CD permissions and release signing.

## Public repository rule

Do not commit production credentials, real client data, private findings, staff records, banking information or proprietary material intended to remain secret.

## AI-assisted changes

AI-assisted contributions are allowed. They receive the same review, deterministic tests and security controls as human-authored changes. AI output is never accepted as a security guarantee.
