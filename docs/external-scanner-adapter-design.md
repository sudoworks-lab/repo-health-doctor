# External Scanner Adapter Design

This design note describes the public boundary for imported and real external
scanner evidence.

## Purpose

Imported scanner output and explicitly invoked real scanner adapters can raise
risk, add limitations, or reinforce existing evidence. They do not become
execution authorization.

## Safety Boundary

- Do not install scanners on the host
- Do not execute host scanners by default
- Do not persist raw scanner output in committed fixtures or reports
- Keep redaction and validation fail-closed
- Treat scanner no-finding results as limited evidence, not safety proof
- Treat scanner unavailable, unsupported, timed out, missing, or malformed
  output as fail-closed evidence, not PASS

## Scope

The public repository includes schemas, imported adapters, real Gitleaks,
OSV-Scanner, and Trivy adapters, synthetic fixtures, redacted compatibility
fixtures, and compatibility tests. Operational scanner execution remains
explicit, bounded, and separate from the default local review path.
