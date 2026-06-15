# Changelog

All notable changes to RepoGuard AI are documented here.

## 0.6.0 - 2026-06-15

### Added

- Agent and MCP configuration checks for excessive agency, literal credentials, mutable containers, temporary executables, insecure transport, and unpinned runtime packages.
- Exact staged-content scans and committed diff scans with `--changed-since`.
- Stable finding fingerprints, adoption baselines, and auditable inline suppressions with expiry policy.
- Portable SARIF 2.1.0 output with OWASP, GitHub, CWE, and OpenSSF metadata.
- Standalone GitHub Action bundle, OpenSSF Scorecard, dependency review, CycloneDX release evidence, and staged npm publishing through OIDC.

### Changed

- Runtime support now targets Node.js 22.14 and 24, TypeScript 6, Commander 15, Zod 4, Vitest 4, and Biome 2.
- The canary command now explicitly creates inert test credentials and no longer claims active intrusion detection.
- Configuration and baseline files are validated strictly; baseline writes are atomic and private.

### Fixed

- GitHub Actions event-list detection, SARIF paths and upload ordering, Unicode normalization state, secret-provider overlap, pre-commit staged-content accuracy, and false claims in project documentation.
