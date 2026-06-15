# Release Checklist

- [ ] Version and Git tag match exactly (`vX.Y.Z`).
- [ ] `npm ci && npm run check` passes on Node.js 22 and 24.
- [ ] `npm audit --omit=dev` reports no production vulnerabilities.
- [ ] `npm pack --dry-run` contains only the bundle, public docs, license, security policy, example config, and package metadata.
- [ ] The bundled CLI scans `examples` and emits valid JSON and SARIF.
- [ ] New rules redact credentials and include safe-counterexample tests.
- [ ] README, rules, threat model, and changelog reflect the release.
- [ ] The npm trusted publisher points to `.github/workflows/stage-release.yml` with stage-only permission.
- [ ] The staged package is downloaded and inspected before 2FA approval.
- [ ] The release evidence artifact contains the npm tarball and a valid CycloneDX SBOM.
- [ ] OpenSSF Scorecard and dependency review workflows are green.
- [ ] Traditional npm automation tokens remain disabled after OIDC is verified.
