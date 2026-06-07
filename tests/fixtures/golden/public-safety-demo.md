# Repo Health Doctor Report

- Target Repo Path: `<demo-repo>`
- Overall Status: `PASS`
- Schema Version: `1.1`

## Summary Counts

| PASS | WARN | BLOCK |
| --- | --- | --- |
| 12 | 0 | 0 |

## Status Meanings

- `PASS`: ok
- `WARN`: review
- `BLOCK`: release blocker

## Checks

| Status | Check | Summary |
| --- | --- | --- |
| `PASS` | `readme` | README found. |
| `PASS` | `license` | License file found. |
| `PASS` | `gitignore` | .gitignore found. |
| `PASS` | `ci` | Workflow file found. |
| `PASS` | `tests` | Test directory found. |
| `PASS` | `docs` | Docs directory found. |
| `PASS` | `scripts` | Scripts directory found. |
| `PASS` | `secrets_scan` | No obvious unallowed secrets detected. |
| `PASS` | `large_files` | No unallowed large files detected. |
| `PASS` | `public_text_safety` | No obvious public-facing text issues detected. |
| `PASS` | `tracked_artifacts` | Tracked generated or environment files were not detected. |
| `PASS` | `policy` | Policy configuration loaded. |

### `readme`

- Status: `PASS`
- Summary: README found.
- Found: `README.md`
- Findings: none

### `license`

- Status: `PASS`
- Summary: License file found.
- Found: `LICENSE`
- Findings: none

### `gitignore`

- Status: `PASS`
- Summary: .gitignore found.
- Found: `.gitignore`, `.git/info/exclude`
- Findings: none

### `ci`

- Status: `PASS`
- Summary: Workflow file found.
- Found: `.github/workflows/ci.yml`
- Findings: none

### `tests`

- Status: `PASS`
- Summary: Test directory found.
- Found: `tests`
- Findings: none

### `docs`

- Status: `PASS`
- Summary: Docs directory found.
- Found: `docs`
- Findings: none

### `scripts`

- Status: `PASS`
- Summary: Scripts directory found.
- Found: `scripts`
- Findings: none

### `secrets_scan`

- Status: `PASS`
- Summary: No obvious unallowed secrets detected.
- Scanned Files: `6`
- Findings: none

### `large_files`

- Status: `PASS`
- Summary: No unallowed large files detected.
- Threshold MB: `10`
- Threshold Bytes: `10485760`
- Findings: none

### `public_text_safety`

- Status: `PASS`
- Summary: No obvious public-facing text issues detected.
- Scanned Files: `6`
- Scan Scope: `tracked`
- Findings: none

### `tracked_artifacts`

- Status: `PASS`
- Summary: Tracked generated or environment files were not detected.
- Scan Scope: `tracked`
- Findings: none

### `policy`

- Status: `PASS`
- Summary: Policy configuration loaded.
- Policy Sources: `repo`
- Ignore Path Count: `1`
- Allow Finding Count: `0`
- Findings: none
