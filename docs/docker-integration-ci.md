# Docker Integration CI

This document covers the bounded CI path for Docker-related external-scanner
tests.

## Always-On Path

The default CI path uses fake or synthetic runner coverage for Docker command
construction and boundary validation. It is an always-on path because it does
not require a local Docker daemon. This path does not require a local Docker daemon on contributor machines.

## Optional Real Docker Path

Any real Docker-based scanner execution remains optional, approval-bound, and
outside the default CI contract. It must preserve the existing no-host-install,
no-host-credential, and no-raw-output rules.
