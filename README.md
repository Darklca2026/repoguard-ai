<div align="center">

# 🛡️ RepoGuard AI
**Security scanner for AI-assisted repositories.**

[![npm version](https://img.shields.io/npm/v/repoguard-ai.svg?style=for-the-badge&color=blue)](https://npmjs.org/package/repoguard-ai)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg?style=for-the-badge)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)

[English](#english) • [Português (PT-BR)](#português-pt-br)

</div>

---

<h2 id="english">🇬🇧 English</h2>

RepoGuard AI scans repositories for leaked AI/API secrets, prompt injection patterns, risky GitHub Actions, dangerous scripts, and unsafe AI-assisted code patterns.

### ❓ Why RepoGuard AI?

> [!NOTE]
> AI coding tools, agents, prompts, and automated workflows are now part of everyday development. But they can introduce hidden risks.

RepoGuard AI gives maintainers a fast local check before pushing or opening a pull request to ensure none of the following slip through:
- Leaked API keys (OpenAI, Anthropic, AWS, GitHub)
- Unsafe GitHub Actions (`pull_request_target`)
- Prompt injection patterns (`"ignore previous instructions"`)
- Dangerous shell commands (`curl | bash`)
- Risky AI-generated code snippets

### ✨ Key Features & Heuristics

| Feature | Description | File Support |
| --- | --- | --- |
| 🔑 **Secret Detection** | Finds keys & DB URLs. Uses **Shannon Entropy** to detect unknown hardcoded tokens. | `.*` |
| 💉 **Prompt Injection** | Scans for malicious override instructions and evading **Base64 payloads**. | `.md, .txt, .json, .yaml` |
| ⚙️ **GitHub Actions** | Flags dangerous CI/CD permissions and triggers. | `.github/workflows/*.yml` |
| 💣 **Dangerous Code & Anti-Tamper** | Detects unsafe eval, shell executions, and attempts to delete `.git` or workflows. | `.js, .ts, .py, .sh` |

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

**3. Run the scanner in your repository:**
```bash
repoguard-ai scan .
```

*Want machine-readable or GitHub Security output?*
```bash
repoguard-ai scan . --json
repoguard-ai scan . --sarif > results.sarif
```

### 🤖 Native GitHub Action

Add this to your `.github/workflows/security.yml` to run RepoGuard natively:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Darklca2026/repoguard-ai@main
        with:
          format: 'sarif' # Uploads to GitHub Security Tab natively!
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

severity:
  failOn: HIGH # Exit code 1 if score meets or exceeds this
```

### 📚 Architecture & Deep Dives

> [!TIP]
> Explore our complete documentation to understand the rules and limitations.

- [Threat Model](docs/threat-model.md) - What we detect and our limitations.
- [Rules Engine](docs/rules.md) - Detailed breakdown of every security rule.
- [False Positives](docs/false-positives.md) - How to mitigate noisy alerts.
- [Project Roadmap](docs/roadmap.md) - Future integrations (SARIF, VS Code).
- [Contributing](CONTRIBUTING.md) - Learn how to add new rules to RepoGuard AI.

---

<div align="center">
  <img src="https://raw.githubusercontent.com/github/explore/80688e429a7d4ef2fca1e82350fe8e3517d3494d/topics/open-source/open-source.png" width="50" />
</div>

---

<h2 id="português-pt-br">🇧🇷 Português (PT-BR)</h2>

O RepoGuard AI analisa repositórios em busca de vazamentos de chaves de API/IA, padrões de prompt injection, GitHub Actions perigosas, scripts arriscados e padrões inseguros de código gerado por IA.

### ❓ Por que o RepoGuard AI?

> [!NOTE]
> Ferramentas de IA, agentes autônomos, prompts e fluxos de trabalho automatizados agora fazem parte do desenvolvimento diário. Mas eles podem introduzir riscos ocultos.

O RepoGuard AI fornece aos mantenedores uma verificação local super rápida antes de fazer um `git push` ou abrir um Pull Request, garantindo que nada disso passe despercebido:
- Vazamento de chaves de API (OpenAI, Anthropic, AWS, GitHub)
- GitHub Actions inseguras (uso de `pull_request_target`)
- Padrões de prompt injection (`"ignore previous instructions"`)
- Comandos shell perigosos (`curl | bash`)
- Códigos inseguros gerados por IA

### ✨ Principais Recursos e Inteligência

| Recurso | Descrição | Extensões |
| --- | --- | --- |
| 🔑 **Detecção de Secrets** | Acha chaves e URLs de DB. Usa **Entropia de Shannon** para achar tokens desconhecidos. | `.*` |
| 💉 **Prompt Injection** | Busca por instruções de sobreposição e evasão com payloads **Base64**. | `.md, .txt, .json, .yaml` |
| ⚙️ **GitHub Actions** | Alerta permissões altas de CI/CD e gatilhos inseguros. | `.github/workflows/*.yml` |
| 💣 **Código Perigoso e Anti-Tamper** | Detecta uso de eval, exec, execução em shell e tentativas de deletar `.git`. | `.js, .ts, .py, .sh` |

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

**3. Rode o scanner no seu repositório:**
```bash
repoguard-ai scan .
```

*Precisa integrar com o GitHub Advanced Security ou em scripts customizados?*
```bash
repoguard-ai scan . --json
repoguard-ai scan . --sarif > results.sarif
```

### 🤖 GitHub Action Nativa

Crie o arquivo `.github/workflows/security.yml` para rodar direto no CI:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Darklca2026/repoguard-ai@main
        with:
          format: 'sarif' # Mostra os erros nativamente na aba Security do GitHub!
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

severity:
  failOn: HIGH # O processo falha (Exit 1) se o risco atingir essa severidade
```

### 📚 Arquitetura e Documentação Profunda

> [!TIP]
> Explore nossa documentação para entender como as regras funcionam e suas limitações.

- [Modelo de Ameaças](docs/threat-model.md) - O que detectamos e onde falhamos.
- [Motor de Regras](docs/rules.md) - Visão técnica de todas as regras ativas.
- [Falsos Positivos](docs/false-positives.md) - Como lidar com alertas ruidosos.
- [Roadmap do Projeto](docs/roadmap.md) - Futuras integrações (SARIF, GitHub nativo).
- [Como Contribuir](CONTRIBUTING.md) - Aprenda a adicionar novas regras ao scanner.

---
*RepoGuard AI - License: MIT*
