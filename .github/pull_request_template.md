## Summary

- Explain the maintainer-facing purpose of this change.

## Checks

- [ ] `PYTHONPATH=src python3 -m unittest discover -s tests -v`
- [ ] `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`
- [ ] `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .`

## Safety

- [ ] No raw secrets, tokens, private paths, local IPs, or policy raw values are included
- [ ] Redaction behavior is unchanged or intentionally documented
- [ ] Fixture, test, and doc updates are included when rules change
