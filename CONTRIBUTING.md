# Contributing to RepoGuard AI

Thank you for your interest in contributing!

## Development Setup
1. Clone the repository
2. Use Node.js 22.14 or newer
3. Run `npm ci`
4. Run `npm run check` to verify types, tests, and the production bundle
5. Use `npm run dev -- scan examples` to test the CLI locally

## Adding New Rules
1. Create a new file in `src/rules/`
2. Implement the `Rule` interface
3. Write a test case in `tests/`
4. Register the rule in `src/rules/index.ts`
5. Open a Pull Request

New findings must redact credentials, include a concrete remediation, and have tests for both detection and a safe counterexample.

Please keep changes focused and small!
