# Project Pitch

## One Sentence

`repo-health-doctor` is a local-first preflight gate for maintainers reviewing AI-generated repository changes before share, publish, or automation handoff.

## Problem

Maintainers often need a fast, local check that catches obvious repository hygiene issues, pre-publish safety signals, tracked artifacts, and broken policy before deeper review or CI handoff.

## Who It Helps

- OSS maintainers reviewing AI-generated diffs
- Individual developers shipping small repositories
- Coding agents working under maintainer-defined safety boundaries

## Current Capabilities

- Repository health checks for core files and directories
- Public-safety scanning with redacted findings
- Policy validation for ignore and allow configuration
- Text and JSON output with stable `rule_id`, `severity`, and `schema_version`

## Why Codex Helps

Codex can expand fixtures, golden cases, docs, and small schema-compatible improvements while staying inside local verification and redaction boundaries.

## Non-Claims

- Not a complete secret scanner
- Not a vulnerability scanner
- Not a GitHub settings auditor
- Not an AI agent framework

## Japanese Draft

repo-health-doctorは、AI生成差分を受け入れるOSS maintainer向けのlocal-first preflight gateです。README、LICENSE、CI、tests、公開前チェックpattern、secretらしき文字列、tracked artifacts、policy validityを確認し、redacted JSONとPASS/WARN/BLOCKで公開前判断を支援します。具体的な作業として、rule追加、fixture/golden整備、false positive改善、docs同期、schema互換性確認をCodexに任せる想定です。

## English Draft

repo-health-doctor is a local-first preflight gate for maintainers reviewing AI-generated repository changes. It checks basic repo health, pre-publish safety signals, secret-like patterns, tracked artifacts, policy validity, and redacted JSON output so maintainers can make publish-or-hold decisions. Codex would help expand rules, fixtures, golden cases, docs, and schema-compatible improvements in small safe changes.

## After Application

This file is a pre-application draft. After the application phase, fold durable content into the README or roadmap, then remove the standalone pitch document.
