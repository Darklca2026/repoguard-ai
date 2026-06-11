# RepoGuard AI

[![npm version](https://img.shields.io/npm/v/repoguard-ai.svg)](https://npmjs.org/package/repoguard-ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

Security scanner for AI-assisted repositories.

RepoGuard AI scans repositories for leaked AI/API secrets, prompt injection patterns, risky GitHub Actions, dangerous scripts, and unsafe AI-assisted code patterns.

## Why

AI coding tools, agents, prompts, and automated workflows are now part of everyday development. But they can introduce hidden risks:

- leaked API keys
- unsafe GitHub Actions
- prompt injection patterns
- dangerous shell commands
- risky AI-generated code

RepoGuard AI gives maintainers a fast local check before pushing or opening a pull request.

## Install

```bash
npm install -g repoguard-ai
```

## Usage

```bash
repoguard-ai scan .
```

JSON output:

```bash
repoguard-ai scan . --json
```

Custom config:

```bash
repoguard-ai scan . --config repoguard.config.yml
```

## Example output

```
RepoGuard AI Report

Risk score: HIGH
Files scanned: 42
Findings: 4

[CRITICAL] .env:1 secret.openai_api_key
Possible OpenAI API key detected.
Fix: Remove the key, rotate it, and use environment variables or GitHub Secrets.

[HIGH] .github/workflows/deploy.yml:4 actions.pull_request_target
Workflow uses pull_request_target.
Fix: Avoid pull_request_target for untrusted pull requests or restrict permissions.

[MEDIUM] prompts/system.md:12 prompt.injection_phrase
Prompt injection phrase detected: "ignore previous instructions".
Fix: Treat external content as data, not instructions.
```

## What it detects
- AI/API secrets
- prompt injection phrases
- risky GitHub Actions
- dangerous shell/code patterns
- AI instruction files

## Configuration

`repoguard.config.yml`:

```yaml
ignore:
  - node_modules/**
  - dist/**
  - build/**
  - .git/**

rules:
  secrets: true
  promptInjection: true
  githubActions: true
  dangerousCode: true
  aiGenerated: true

severity:
  failOn: HIGH
```

## Roadmap
- [x] Local CLI scanner
- [x] Secret detection
- [x] Prompt injection detection
- [x] GitHub Actions risk detection
- [x] Dangerous code detection
- [ ] GitHub Action integration
- [ ] SARIF output
- [ ] Custom rule packs
- [ ] VS Code extension

## Limitations
RepoGuard AI is a static scanner. It may produce false positives and does not replace manual security review.

## License
MIT
