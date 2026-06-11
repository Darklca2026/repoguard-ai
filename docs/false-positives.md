# Falsos Positivos

Como o RepoGuard AI opera através de varredura estática baseada em expressões regulares, ele não tem contexto de execução, resultando em possíveis falsos positivos.

### Exemplos comuns de Falsos Positivos:
1. **Documentação Educacional:** Se o seu `README.md` contiver tutoriais sobre como mitigar prompt injection (ex: "Do not use ignore previous instructions"), o scanner irá sinalizar essa linha.
2. **Secrets Falsos em Mocks de Teste:** O arquivo `tests/mock.env` com uma chave fake gerada para o seu test runner será apontada como um secret genuíno (`sk-proj-abc...`).
3. **Strings semânticas idênticas:** Uso de varíaveis ou frases normais em JSONs de internacionalização que acidentalmente correspondem a chaves (mais raro, mas possível no futuro).

### Como Mitigar:
Para remover o ruído de arquivos que você sabe que são seguros (como mocks e documentação intencional):
Utilize o `repoguard.config.yml` para adicionar o arquivo na chave `ignore`. Exemplo:
```yaml
ignore:
  - "tests/mocks/**"
  - "docs/security-tutorial.md"
```
