# 🛡️ RepoGuard AI (Engine 2026 em Go)

> **"Shift Smart, Not Just Left."** - A ferramenta DevSecOps definitiva projetada para velocidade absoluta, foco em exploração real (ASPM) e bloqueio de ataques contra Agentes Autônomos de Inteligência Artificial.

[![Security: Otimizado em Go](https://img.shields.io/badge/Engine-Go_Lang-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![Auto-Fix](https://img.shields.io/badge/Auto--Fix-Ativo-4CAF50?style=for-the-badge)](https://github.com/Darklca2026/repoguard-ai)
[![OWASP ASI](https://img.shields.io/badge/OWASP-Agentic_Top_10-blue?style=for-the-badge)](https://genai.owasp.org)

O **RepoGuard AI** abandonou motores pesados em Javascript e foi completamente reescrito para um binário de Sistema Operacional de Baixo Nível. Ele escaneia dezenas de milhares de arquivos em questão de milissegundos usando todos os núcleos do seu processador, caçando senhas, injeções em LLMs e vulnerabilidades sistêmicas antes de entrarem em produção.

---

## 🚀 Arquitetura de Vanguarda

*   ⚡ **Worker Pools (Concorrência Real):** Escaneia repositórios massivos de forma assíncrona, despachando a varredura para N *Goroutines*.
*   🧠 **ASPM Exploitability Engine:** Redução inteligente de Falsos Positivos. Se o RepoGuard encontra uma chave complexa dentro de um arquivo de teste (`.test.ts`), ele automaticamente rebaixa o alerta de `CRITICAL` para `LOW`, mantendo o seu fluxo de CI limpo e silenciando o "ruído".
*   🤖 **Focado no Agentic Top 10 (ASI):** Detecção pronta para a geração de IA autônoma, protegendo contra *Prompt Injections*, Desserializações Perigosas (`yaml.unsafe_load`) e envenenamento de pesos do PyTorch.
*   🩹 **Auto-Correção Instantânea:** Em vez de apenas acusar o erro, o RepoGuard reescreve seu arquivo e conserta as brechas graves nativamente na memória RAM em milissegundos.
*   🚦 **Guardrail Pre-commit Local:** Chega de gastar minutos esperando as Actions rodarem na Nuvem. Bloqueie os desenvolvedores de comitarem códigos perigosos instalando uma trava local na própria máquina.

---

## 🛠️ Instruções de Uso e Instalação

O motor do RepoGuard agora é um executável nativo.

### 1. Escaneamento Padrão (Super Rápido)
Varre todo o diretório atual usando 12 processadores simultâneos.
```bash
./repoguard-go/repoguard.exe -path . -workers 12
```

### 2. Auto-Cura de Código (Auto-Fix)
Se você quer que o RepoGuard encontre E resolva seus problemas. Senhas serão mascaradas nativamente e funções perigosas da IA serão blindadas sem quebrar o código.
```bash
./repoguard-go/repoguard.exe -path . -workers 12 -autofix
```

### 3. Instalar o Guardrail na IDE (Pre-commit Hook)
Para proteger o seu repositório de vez, instale a armadilha do RepoGuard no Git local. Se qualquer membro da equipe der um `git commit` com injeção de prompt ou senhas vazadas, o commit será abortado silenciosamente na mesma hora.
```bash
./repoguard-go/repoguard.exe -install-hook
```

---

## 📂 Visão Interna do Motor em Go

O RepoGuard funciona baseado em **Buffer Streams** e uma tabela otimizada de **Entropia de Shannon** (Lookup Arrays). O consumo de Memória RAM nunca excede os limites definidos, já que as Regras (`regexp.MustCompile`) viram código de máquina durante o boot (que leva 2ms).

### Construindo a Ferramenta Manualmente
Se você quiser recompilar o executável com novas regras:
```bash
cd repoguard-go
go mod tidy
go build -ldflags="-s -w" -o repoguard.exe
```
