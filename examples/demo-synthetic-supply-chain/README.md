# Demo: Synthetic Supply-Chain Chain

This safe synthetic repository demonstrates the shape of a suspicious package
install chain without shipping malware.

Signals represented:

- postinstall script present
- environment variable enumeration shape
- redacted credential path reference
- GitHub Actions workflow write-risk shape
- outbound network target string limited to `example.invalid`
- obfuscated eval candidate string that is never executed

Do not use this as a real scanner compatibility fixture. It is a static demo
for repo-health-doctor gate behavior.
