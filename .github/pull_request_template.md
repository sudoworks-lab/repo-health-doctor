## Summary

- Explain the maintainer-facing purpose of this change.

## Checks

- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests -v`
- [ ] `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`
- [ ] `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .`
- [ ] Docs updated when public behavior, limitations, or release wording changed

## Safety

- [ ] No raw secrets, tokens, private paths, local IPs, or policy raw values are included
- [ ] No raw scanner output is persisted, displayed, or committed
- [ ] No host private path is included
- [ ] Redaction behavior is unchanged or intentionally documented
- [ ] Fixture, test, and doc updates are included when rules change
- [ ] No finding is not described as proof of safety
- [ ] Gate decision and execution authorization remain separate
- [ ] Sandbox-run changes keep local-image-only, no-auto-pull, no-Docker-socket boundaries
- [ ] Completed sandbox-run is not described as safe or authorization to continue
- [ ] No generated artifacts, caches, local config, or history files are committed

## Compatibility And Contracts

- [ ] Default v3 JSON output compatibility is preserved or explicitly approved for change
- [ ] Default CLI behavior is preserved or explicitly approved for change
- [ ] Public contract impact is documented
- [ ] Stable versus experimental surface impact is documented
- [ ] Third-party security review is not claimed unless it actually happened
