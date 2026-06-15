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

Para adotar o RepoGuard em um repositório com achados legítimos já revisados, prefira um baseline em vez de ignorar diretórios inteiros:

```bash
repoguard-ai scan . --write-baseline .repoguard-baseline.json
repoguard-ai scan . --baseline .repoguard-baseline.json
```

Revise o arquivo antes de commitá-lo. Um baseline não marca o código como seguro; ele apenas separa dívida conhecida de regressões novas.

Para uma exceção pequena e localizada, use uma supressão auditável em comentário:

```javascript
// repoguard-ignore-next-line code.eval -- parser legado isolado; owner=platform; expires=2026-09-30
eval(legacyExpression);
```

Prefira uma regra exata ou um prefixo como `secret.*`; evite `*`. Supressões vencidas ou sem justificativa são reportadas como violações de política.
