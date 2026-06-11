# Roadmap Oficial do RepoGuard AI

Aqui está a visão geral das etapas de entrega e de evolução do projeto.

## v0.1 (Concluída)
- [x] Estrutura TypeScript CLI
- [x] Scanner Recursivo (.gitignore / config YAML)
- [x] Regras Essenciais (Secrets, Prompts, Actions, Dangerous Code)
- [x] Saída colorida no Terminal e JSON 

## v0.2
- [ ] Construir a GitHub Action oficial nativa.
- [ ] Adicionar comentários diretamente na Pull Request via API do GitHub.

## v0.3
- [ ] Adicionar saída no padrão **SARIF** (Static Analysis Results Interchange Format).
- [ ] Integrar nativamente com a aba Security > Code Scanning do GitHub.

## v0.4
- [ ] Suporte a Custom Rules injetáveis pelo usuário via JS.
- [ ] Rule Packs comunitários.

## v0.5
- [ ] Hook de pré-commit automatizado.
- [ ] Suporte robusto a monorepos (múltiplos configs em subpastas).
- [ ] Extensão experimental opcional para o VS Code.
