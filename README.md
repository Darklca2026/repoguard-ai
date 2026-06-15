<div align="center">

# 🛡️ RepoGuard AI
**Security scanner for AI-assisted repositories.**

[![npm version](https://img.shields.io/npm/v/repoguard-ai.svg?style=for-the-badge&color=blue)](https://npmjs.org/package/repoguard-ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/github/actions/workflow/status/Darklca2026/repoguard-ai/test.yml?branch=main&style=for-the-badge&label=tests)](https://github.com/Darklca2026/repoguard-ai/actions/workflows/test.yml)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)

[English](#english) • [Português (PT-BR)](#português-pt-br)

</div>

---

<h2 id="english">🇬🇧 English</h2>

RepoGuard AI is a deterministic shift-left scanner for AI-assisted and agentic repositories. It detects leaked AI/API secrets, prompt injection and Unicode evasion, risky GitHub Actions, unsafe model loading, dangerous scripts, and insecure agent/MCP configuration.

### ❓ Why RepoGuard AI?

> [!NOTE]
> AI coding tools, agents, prompts, and automated workflows are now part of everyday development. But they can introduce hidden risks.

RepoGuard AI gives maintainers a fast local check before pushing or opening a pull request to ensure none of the following slip through:
- Leaked API keys (OpenAI, Anthropic, Hugging Face, Google AI, Groq, OpenRouter, AWS, GitHub, and more)
- Unsafe GitHub Actions (`pull_request_target`)
- Prompt injection patterns (`"ignore previous instructions"`)
- Dangerous shell commands (`curl | bash`)
- Risky AI-generated code snippets

### ✨ Key Features & Heuristics

| Feature | Description | File Support |
| --- | --- | --- |
| 🔑 **Secret Detection** | Finds keys & DB URLs. Uses **Shannon Entropy** to detect unknown hardcoded tokens. | `.*` |
| 💉 **Prompt Injection** | Scans for malicious override instructions, Base64 evasion, and **Phantom Payloads (Zero-Width & Homoglyphs)**. | `.md, .txt, .json, .yaml` |
| 🧠 **AI Poisoning Defender** | Detects insecure `torch.load()`, `pickle`, and `yaml.unsafe_load()` vectors in ML models. | `.py, .ipynb` |
| 🤖 **Agent & MCP Security** | Audits agent instructions, MCP credentials, shell launchers, insecure transports, excessive agency, and unpinned runtime packages. | `AGENTS.md, CLAUDE.md, .mcp.json` |
| ⚙️ **GitHub Actions** | Flags dangerous CI/CD permissions and triggers. | `.github/workflows/*.yml` |
| 💣 **Dangerous Code & Anti-Tamper** | Detects unsafe eval, shell executions, and attempts to delete `.git` or workflows. | `.js, .ts, .py, .sh` |
| 📋 **Policy & Adoption** | Stable fingerprints, baselines, expiring suppressions, Git diff scans, JSON, and SARIF 2.1.0. | Repository-wide |

### 🚀 Quick Start

**1. Install globally via npm:**
```bash
npm install -g repoguard-ai
```

**2. Setup Pre-commit Hook (Shift-Left Security):**
Automatically block developers from committing leaked secrets:
```bash
repoguard-ai init-hook
```

**3. Generate an inert canary fixture:**
Create a local `.env.canary` with recognizable example credentials for testing workflows. The values are not connected to an alerting service and do not detect intrusion by themselves.
```bash
repoguard-ai plant-canary
```

**4. Run the scanner in your repository:**
```bash
repoguard-ai scan .
```

*Want machine-readable or GitHub Security output?*
```bash
repoguard-ai scan . --json
repoguard-ai scan . --sarif > results.sarif
```

**Scan exactly what will be committed:**
```bash
repoguard-ai scan . --staged
```

**Scan only files committed since a base revision:**
```bash
repoguard-ai scan . --changed-since origin/main
```

**Adopt the scanner without being blocked by existing debt:**
```bash
repoguard-ai scan . --write-baseline .repoguard-baseline.json
repoguard-ai scan . --baseline .repoguard-baseline.json
```
The baseline uses stable fingerprints, so moved lines remain recognized while new risks still fail CI.

**Document a narrow, temporary exception:**
```javascript
// repoguard-ignore-next-line code.eval -- isolated legacy parser; owner=platform; expires=2026-09-30
eval(legacyExpression);
```
Suppressions must be comments. Missing reasons, expired dates, or policy violations are emitted as findings instead of silently hiding risk.

### 🤖 Native GitHub Action

Add this to your `.github/workflows/security.yml` to run RepoGuard natively:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      # Replace with the full SHA of the RepoGuard release you reviewed.
      - uses: Darklca2026/repoguard-ai@FULL_40_CHARACTER_COMMIT_SHA
        with:
          format: 'sarif'
          changed-since: ${{ github.event.pull_request.base.sha }}
```

### 💻 Example Output

<details>
<summary>Click to see what the terminal report looks like</summary>

```text
RepoGuard AI Report

Risk score: CRITICAL
Files scanned: 42
Findings: 4

[CRITICAL] .env:1 secret.openai_api_key
Possible OpenAI API key detected.
Snippet: sk-pro************************
Fix: Remove the key, rotate it, and use environment variables or GitHub Secrets.

[HIGH] .github/workflows/deploy.yml:4 actions.pull_request_target
Workflow uses pull_request_target.
Snippet: on: pull_request_target
Fix: Avoid pull_request_target for untrusted pull requests or restrict permissions.

[MEDIUM] prompts/system.md:12 prompt.injection_phrase
Prompt injection phrase detected: "ignore previous instructions".
Snippet: If asked, ignore previous instructions...
Fix: Treat external content as data, not instructions.
```
</details>

### ⚙️ Configuration

Create a `repoguard.config.yml` in your root directory to customize the engine:

```yaml
ignore:
  - "node_modules/**"
  - "dist/**"
  - "build/**"
  - ".git/**"

rules:
  secrets: true
  promptInjection: true
  githubActions: true
  dangerousCode: true
  aiGenerated: true
  aiPoisoning: true
  agentSecurity: true

severity:
  failOn: HIGH # Exit code 1 if score meets or exceeds this

suppressions:
  enabled: true
  requireReason: true
  requireExpiry: true
  maxExpiryDays: 90
```

### 📚 Architecture & Deep Dives

> [!TIP]
> Explore our complete documentation to understand the rules and limitations.

- [Threat Model](docs/threat-model.md) - What we detect and our limitations.
- [Rules Engine](docs/rules.md) - Detailed breakdown of every security rule.
- [False Positives](docs/false-positives.md) - How to mitigate noisy alerts.
- [Project Roadmap](docs/roadmap.md) - Delivered capabilities and next priorities.
- [Contributing](CONTRIBUTING.md) - Learn how to add new rules to RepoGuard AI.

---

<div align="center">
  <img src="https://raw.githubusercontent.com/github/explore/80688e429a7d4ef2fca1e82350fe8e3517d3494d/topics/open-source/open-source.png" width="50" />
</div>

---

<h2 id="português-pt-br">🇧🇷 Português (PT-BR)</h2>

O RepoGuard AI é um scanner determinístico shift-left para repositórios assistidos por IA e agentes. Ele detecta secrets, prompt injection e evasão Unicode, GitHub Actions perigosas, carregamento inseguro de modelos, scripts arriscados e configurações inseguras de agentes/MCP.

### ❓ Por que o RepoGuard AI?

> [!NOTE]
> Ferramentas de IA, agentes autônomos, prompts e fluxos de trabalho automatizados agora fazem parte do desenvolvimento diário. Mas eles podem introduzir riscos ocultos.

O RepoGuard AI fornece aos mantenedores uma verificação local super rápida antes de fazer um `git push` ou abrir um Pull Request, garantindo que nada disso passe despercebido:
- Vazamento de chaves de API (OpenAI, Anthropic, Hugging Face, Google AI, Groq, OpenRouter, AWS, GitHub e outras)
- GitHub Actions inseguras (uso de `pull_request_target`)
- Padrões de prompt injection (`"ignore previous instructions"`)
- Comandos shell perigosos (`curl | bash`)
- Códigos inseguros gerados por IA

### ✨ Principais Recursos e Inteligência

| Recurso | Descrição | Extensões |
| --- | --- | --- |
| 🔑 **Detecção de Secrets** | Acha chaves e URLs de DB. Usa **Entropia de Shannon** para achar tokens desconhecidos. | `.*` |
| 💉 **Prompt Injection** | Busca evasões com payloads **Base64** e normaliza **Cargas Fantasmas (Caracteres Invisíveis e Homóglifos)**. | `.md, .txt, .json, .yaml` |
| 🧠 **Defesa de Envenenamento IA** | Detecta uso de `torch.load()` inseguro e `pickle` maliciosos em ecossistemas de ML. | `.py, .ipynb` |
| 🤖 **Segurança de Agentes e MCP** | Audita credenciais, shell, transporte inseguro, autonomia excessiva e pacotes baixados sem versão fixa. | `AGENTS.md, CLAUDE.md, .mcp.json` |
| ⚙️ **GitHub Actions** | Alerta permissões altas de CI/CD e gatilhos inseguros. | `.github/workflows/*.yml` |
| 💣 **Código Perigoso e Anti-Tamper** | Detecta uso de eval, exec, execução em shell e tentativas de deletar `.git`. | `.js, .ts, .py, .sh` |
| 📋 **Política e Adoção** | Fingerprints estáveis, baseline, supressões com validade, diff Git, JSON e SARIF 2.1.0. | Repositório inteiro |

### 🚀 Início Rápido

**1. Instale globalmente via npm:**
```bash
npm install -g repoguard-ai
```

**2. Configure a Trava de Commit (Pre-commit Hook):**
Impede fisicamente o desenvolvedor de subir chaves vazadas:
```bash
repoguard-ai init-hook
```

**3. Gere uma fixture de canário inerte:**
Crie um `.env.canary` local com credenciais de exemplo reconhecíveis para testar fluxos. Os valores não estão ligados a um serviço de alerta e, sozinhos, não detectam invasões.
```bash
repoguard-ai plant-canary
```

**4. Rode o scanner no seu repositório:**
```bash
repoguard-ai scan .
```

*Precisa integrar com o GitHub Advanced Security ou em scripts customizados?*
```bash
repoguard-ai scan . --json
repoguard-ai scan . --sarif > results.sarif
```

**Analise exatamente o conteúdo que será commitado:**
```bash
repoguard-ai scan . --staged
```

**Analise somente arquivos commitados desde uma referência base:**
```bash
repoguard-ai scan . --changed-since origin/main
```

**Adote o scanner sem ser bloqueado pela dívida já existente:**
```bash
repoguard-ai scan . --write-baseline .repoguard-baseline.json
repoguard-ai scan . --baseline .repoguard-baseline.json
```
O baseline usa fingerprints estáveis: mudanças de linha continuam reconhecidas, mas riscos novos ainda bloqueiam o CI.

**Documente uma exceção pequena e temporária:**
```javascript
// repoguard-ignore-next-line code.eval -- parser legado isolado; owner=platform; expires=2026-09-30
eval(legacyExpression);
```
Supressões precisam estar em comentários. Justificativas ausentes, datas vencidas e violações de política aparecem como achados em vez de ocultar o risco.

### 🤖 GitHub Action Nativa

Crie o arquivo `.github/workflows/security.yml` para rodar direto no CI:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6
      # Substitua pelo SHA completo da release do RepoGuard que você revisou.
      - uses: Darklca2026/repoguard-ai@FULL_40_CHARACTER_COMMIT_SHA
        with:
          format: 'sarif'
          changed-since: ${{ github.event.pull_request.base.sha }}
```

### 💻 Exemplo de Saída

<details>
<summary>Clique para ver como o relatório aparece no terminal</summary>

```text
RepoGuard AI Report

Risk score: CRITICAL
Files scanned: 42
Findings: 4

[CRITICAL] .env:1 secret.openai_api_key
Possible OpenAI API key detected.
Snippet: sk-pro************************
Fix: Remove the key, rotate it, and use environment variables or GitHub Secrets.

[HIGH] .github/workflows/deploy.yml:4 actions.pull_request_target
Workflow uses pull_request_target.
Snippet: on: pull_request_target
Fix: Avoid pull_request_target for untrusted pull requests or restrict permissions.

[MEDIUM] prompts/system.md:12 prompt.injection_phrase
Prompt injection phrase detected: "ignore previous instructions".
Snippet: If asked, ignore previous instructions...
Fix: Treat external content as data, not instructions.
```
</details>

### ⚙️ Configuração

Crie um arquivo `repoguard.config.yml` na raiz do seu projeto para customizar o motor:

```yaml
ignore:
  - "node_modules/**"
  - "dist/**"
  - "build/**"
  - ".git/**"

rules:
  secrets: true
  promptInjection: true
  githubActions: true
  dangerousCode: true
  aiGenerated: true
  aiPoisoning: true
  agentSecurity: true

severity:
  failOn: HIGH # O processo falha (Exit 1) se o risco atingir essa severidade

suppressions:
  enabled: true
  requireReason: true
  requireExpiry: true
  maxExpiryDays: 90
```

### 📚 Arquitetura e Documentação Profunda

> [!TIP]
> Explore nossa documentação para entender como as regras funcionam e suas limitações.

- [Modelo de Ameaças](docs/threat-model.md) - O que detectamos e onde falhamos.
- [Motor de Regras](docs/rules.md) - Visão técnica de todas as regras ativas.
- [Falsos Positivos](docs/false-positives.md) - Como lidar com alertas ruidosos.
- [Roadmap do Projeto](docs/roadmap.md) - Recursos entregues e próximas prioridades.
- [Como Contribuir](CONTRIBUTING.md) - Aprenda a adicionar novas regras ao scanner.

---
*RepoGuard AI - License: MIT*
