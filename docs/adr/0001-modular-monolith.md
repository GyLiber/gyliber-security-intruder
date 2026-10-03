# ADR-0001: Use a Rust modular monolith for v1.0.0

- Status: Accepted
- Date: 2026-10-03

## Context

The Intruder is security-sensitive, early in its lifecycle, and expected to grow to a multi-developer project. Premature service decomposition would add network trust boundaries, deployment identities and operational failure modes before those costs are justified.

## Decision

Implement v1.0.0 as a Rust Cargo workspace deployed as one principal executable with strict crate boundaries. Crates may be extracted into independently deployed services only when a concrete scaling, isolation or ownership requirement justifies the new trust boundary.

## Consequences

- one deployment and release unit initially;
- compile-time internal boundaries;
- smaller attack surface;
- easier reproducibility;
- future extraction remains possible without redesigning domain contracts.
