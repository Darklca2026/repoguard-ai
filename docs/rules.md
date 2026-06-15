# RepoGuard AI Rules

Esta é a documentação das regras integradas no RepoGuard AI.

## 1. Secrets (`secrets.ts`)
**Severidade:** CRITICAL / MEDIUM
- Identifica tokens que seguem padrões matemáticos específicos de provedores em nuvem.
- Padrões cobertos: OpenAI, Anthropic, Hugging Face, Google AI, Groq, OpenRouter, GitHub, AWS, npm, PyPI, Slack, Stripe, chaves privadas e URLs de banco.
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
- Alerta sobre qualquer Action externa sem um commit SHA completo de 40 caracteres (MEDIUM).
- Detecta contextos controláveis por um atacante interpolados diretamente em scripts `run:` (HIGH).

## 4. Código Perigoso e Anti-Tampering (`dangerous-code.ts`)
**Severidade:** CRITICAL / HIGH / MEDIUM / LOW
- Monitora JS/TS/Py/Sh.
- Detecta o uso direto de `eval()`, `child_process.exec()`, `os.system()`.
- **Anti-Tampering (Contra Exclusão):** Sinaliza como CRÍTICO tentativas de deletar o versionamento (`rm -rf .git`), fluxos de trabalho (`rm -rf .github`), ou o silenciamento cego de logs de erro (`> /dev/null`).

## 5. Instruções de IA (`ai-generated.ts`)
**Severidade:** LOW
- Regra de aviso: levanta um sinalização branda de que o repositório contém prompts de sistema para agentes como Copilot, Claude ou Cursor (`.cursor/rules`, `.agent.md`). Apenas para fins de auditoria de contexto e segurança de escopo.

## 6. Configuração de Agentes e MCP (`agent-security.ts`)
**Severidade:** CRITICAL / HIGH / MEDIUM
- Detecta credenciais literais em configurações MCP.
- Sinaliza execução intermediada por shell e flags que removem autenticação ou limites de capacidade.
- Exige HTTPS para servidores MCP remotos.
- Alerta quando `npx`, `bunx` ou `pnpx` baixa um servidor MCP sem versão exata.
- Exige digest imutável em imagens Docker, evita executáveis temporários e detecta credenciais literais em headers.
- Identifica instruções de agente que removem aprovação humana ou concedem acesso irrestrito.

## Baseline e fingerprints
Cada achado recebe um fingerprint SHA-256 estável baseado na regra, severidade, caminho e evidência. O baseline permite registrar dívida conhecida e bloquear somente achados novos sem depender do número da linha. Aumento de severidade volta a exibir o achado.

## Supressões auditáveis
Uma exceção pontual deve estar em comentário, indicar a regra e trazer justificativa:

```text
# repoguard-ignore-next-line secret.* -- fixture de teste revisada; owner=security; expires=2026-09-30
```

O arquivo de configuração pode exigir data de expiração. Diretivas vencidas, sem justificativa ou fora da política viram o achado `policy.invalid_suppression` em vez de esconder o risco.
