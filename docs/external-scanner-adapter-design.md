# External Scanner Adapter Design

This design note describes the public boundary for imported external scanner
evidence.

## Purpose

Imported scanner output can raise risk, add limitations, or reinforce existing
evidence. It does not become execution authorization.

## Safety Boundary

- Do not install scanners on the host
- Do not execute host scanners by default
- Do not persist raw scanner output in committed fixtures or reports
- Keep redaction and validation fail-closed
- Treat scanner no-finding results as limited evidence, not safety proof

## Scope

The public repository currently includes schemas, adapters, synthetic fixtures,
and compatibility tests for imported evidence. Operational scanner execution
remains optional, bounded, and separate from the default local review path.
