# Security Model

## What This Tool Protects

- Raw secret candidates are not printed in text or JSON output
- Private paths are reported as neutral categories
- Local IPs are reported as neutral categories
- Policy allow targets are not echoed back as raw values
- Tracked generated artifacts, cache candidates, and env file candidates can be blocked before publish
- The tool works local-first and does not depend on network transmission

## What This Tool Does Not Protect

- Complete secret scanning coverage
- Dependency vulnerability detection
- GitHub settings auditing
- Legal or license review
- Prevention of malicious contributors
- Enterprise DLP use cases

## Redaction Contract

- Secret candidates, token candidates, private paths, local IPs, and policy allow target raw values must not appear in text output or JSON output
- Reports should expose `rule_id`, `severity`, repo-relative path, line number, size, category, and safe policy metadata only
- `redacted: true` means the raw value was replaced by a category or fixed mask
- Debugging output must not print raw values to stdout, JSON, CI artifacts, or issue templates

## Change Management

- If redaction behavior changes, update tests and any affected golden outputs together
- Keep `schema_version` stable unless the maintainer explicitly approves a contract change
- Explain backward-compatibility impact in the change description when output behavior intentionally changes
