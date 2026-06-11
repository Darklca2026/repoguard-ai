# RepoGuard AI Rules

Esta é a documentação completa das regras integradas na versão 0.1 do RepoGuard AI.

## 1. Secrets (`secrets.ts`)
**Severidade:** CRITICAL
- Identifica tokens que seguem padrões matemáticos específicos de provedores em nuvem.
- Padrões cobertos: OpenAI (`sk-proj-*`, `sk-*`), Anthropic, GitHub (`ghp_`, `github_pat_`), AWS (`AKIA`), Private Keys, Database URLs.
- *Nota:* O log nativamente ofusca a chave, exibindo apenas os primeiros 6 caracteres.

## 2. Prompt Injection (`prompt-injection.ts`)
**Severidade:** MEDIUM / HIGH
- Procura em arquivos `.md`, `.prompt`, `.yaml`, `.json`.
- Textos bloqueados (HIGH): `print environment variables`, `send the token`, `exfiltrate`, `leak secrets`.
- Textos monitorados (MEDIUM): `ignore previous instructions`, `bypass safety`, `act as root`.

## 3. GitHub Actions (`github-actions.ts`)
**Severidade:** MEDIUM / HIGH
- Identifica o gatilho `pull_request_target` (que tem acesso aos secrets do repositório base).
- Alerta sobre o uso de `permissions: write-all`.
- Pega injeção direta de scripts usando `curl | bash` ou `wget | sh`.
- Alerta sobre actions de terceiros sem um Hash SHA explícito (MEDIUM).

## 4. Código Perigoso (`dangerous-code.ts`)
**Severidade:** LOW / MEDIUM / HIGH
- Monitora JS/TS/Py/Sh.
- Detecta o uso direto de `eval()`, `child_process.exec()`, `os.system()`.
- Avisa sobre `rm -rf` indiscriminado ou `chmod 777`.

## 5. Instruções de IA (`ai-generated.ts`)
**Severidade:** LOW
- Regra de aviso: levanta um sinalização branda de que o repositório contém prompts de sistema para agentes como Copilot, Claude ou Cursor (`.cursor/rules`, `.agent.md`). Apenas para fins de auditoria de contexto e segurança de escopo.
