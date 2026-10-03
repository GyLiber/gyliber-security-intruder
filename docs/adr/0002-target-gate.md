# ADR-0002: Make the Target Gate non-bypassable

- Status: Accepted
- Date: 2026-10-03

## Context

The product deliberately performs adversarial network activity. A generic HTTP client available to arbitrary probe code would make authorization policy optional and would create an unacceptable repurposing risk.

## Decision

Production probe crates do not own raw outbound HTTP clients. All outbound target requests traverse `intruder-net`, whose Target Gate validates enrolled target identity, scheme, host, path, destination network class, redirect destination, execution budget, kill-switch state and environment policy.

## Consequences

- arbitrary target URLs are not a normal operator input;
- redirect and DNS policy are centralized;
- safety tests focus on one trusted networking boundary;
- adding a probe must not add a second networking stack.
