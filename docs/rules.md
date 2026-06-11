# RepoGuard AI Rules

Esta é a documentação completa das regras integradas na versão 0.1 do RepoGuard AI.

## 1. Secrets (`secrets.ts`)
**Severidade:** CRITICAL / MEDIUM
- Identifica tokens que seguem padrões matemáticos específicos de provedores em nuvem.
- Padrões cobertos: OpenAI (`sk-proj-*`, `sk-*`), Anthropic, GitHub (`ghp_`, `github_pat_`), AWS (`AKIA`), Private Keys, Database URLs.
- **Detecção Heurística (Entropia de Shannon):** Mede o grau de aleatoriedade de strings. Se uma string contínua de mais de 20 caracteres tiver Entropia > 4.5, ela é sinalizada como um potencial Secret desconhecido.
- *Nota:* O log nativamente ofusca a chave, exibindo apenas os primeiros 6 caracteres.

## 2. Prompt Injection (`prompt-injection.ts`)
**Severidade:** HIGH / MEDIUM
- Procura em arquivos `.md`, `.prompt`, `.yaml`, `.json`.
- Textos bloqueados (HIGH): `print environment variables`, `send the token`, `exfiltrate`, `leak secrets`.
- Textos monitorados (MEDIUM): `ignore previous instructions`, `bypass safety`, `act as root`.
- **Prevenção de Evasão (Base64):** Varre palavras longas tentando decodificar em Base64 para detectar payloads ofuscados que contenham frases de injeção.

## 3. GitHub Actions (`github-actions.ts`)
**Severidade:** HIGH / MEDIUM
- Identifica o gatilho `pull_request_target` (que tem acesso aos secrets do repositório base).
- Alerta sobre o uso de `permissions: write-all`.
- Pega injeção direta de scripts usando `curl | bash` ou `wget | sh`.
- Alerta sobre actions de terceiros sem um Hash SHA explícito (MEDIUM).

## 4. Código Perigoso e Anti-Tampering (`dangerous-code.ts`)
**Severidade:** CRITICAL / HIGH / MEDIUM / LOW
- Monitora JS/TS/Py/Sh.
- Detecta o uso direto de `eval()`, `child_process.exec()`, `os.system()`.
- **Anti-Tampering (Contra Exclusão):** Sinaliza como CRÍTICO tentativas de deletar o versionamento (`rm -rf .git`), fluxos de trabalho (`rm -rf .github`), ou o silenciamento cego de logs de erro (`> /dev/null`).

## 5. Instruções de IA (`ai-generated.ts`)
**Severidade:** LOW
- Regra de aviso: levanta um sinalização branda de que o repositório contém prompts de sistema para agentes como Copilot, Claude ou Cursor (`.cursor/rules`, `.agent.md`). Apenas para fins de auditoria de contexto e segurança de escopo.
