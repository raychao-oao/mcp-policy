# Changelog

## v0.1.1 - 2026-10-22

- Security: bump `go` directive to 1.27.3 (GO-2026-6809, crypto/x509). govulncheck reports no vulnerabilities.
- No `golang.org/x/crypto` dependency, so no upgrade needed.

## v0.1.0

- Initial release: shared policy engine (`pkg/policy`, `pkg/yamlengine`, `pkg/audit`).
