# Threat Model

RepoGuard AI helps detect common repository risks associated with AI-assisted development tools and practices.

## O que detectamos
*   **Vazamento de Secrets em texto plano:** Chaves da OpenAI, Anthropic, AWS, GitHub, etc., que frequentemente são esquecidas em arquivos copiados por IAs (`.env`, `.json`).
*   **Prompt Injection:** Frases comuns como "ignore previous instructions" ou "reveal your system prompt" embutidas em `.md` ou `.json`.
*   **GitHub Actions Perigosas:** Uso de `pull_request_target` ou `permissions: write-all` que permitem a execução de código não confiável com altos privilégios no CI.
*   **Padrões de Execução em Shell:** Uso indiscriminado de `curl | bash` ou `eval()` que podem expor o sistema a RCE (Remote Code Execution) caso o script origem seja comprometido.

## Limitações (O que NÃO detectamos)
*   **Lógica Semântica:** Não entendemos o propósito do código, apenas padrões estáticos perigosos.
*   **Ataques em Tempo de Execução:** Este é um scanner estático. Não detecta ataques ocorrendo enquanto seu aplicativo roda.
*   **Secrets em Arquivos Binários:** Não varremos imagens, PDFs, arquivos compilados, etc.
*   **Falsos Negativos:** Pode haver formatos de chaves que o scanner não reconhece nativamente. Se você possui um token com formato não padrão, ele não será pego pelas regras padrão atuais.

## Falsos Positivos
Como o RepoGuard AI utiliza expressões regulares e correspondência de padrões:
*   Pode alertar sobre a string `ignore previous instructions` dentro da sua própria documentação se você estiver ensinando sobre isso.
*   Pode alertar sobre secrets "falsos" usados em mocks de teste (para resolver isso, inclua o diretório no `.gitignore` ou na configuração do RepoGuard AI).

## Uso Responsável
O RepoGuard AI **NÃO substitui** uma auditoria de segurança rigorosa, pentests ou as ferramentas nativas de Secret Scanning do GitHub. Ele deve ser utilizado como uma camada adicional para desenvolvedores locais, ajudando a prevenir que erros acidentais subam para o repositório principal através de commits.
