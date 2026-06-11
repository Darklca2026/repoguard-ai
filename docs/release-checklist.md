# Release Checklist

Antes de publicar uma nova versão, verifique esta lista para garantir excelência.

- [ ] Os testes unitários (`vitest`) estão passando? (`npm run test`)
- [ ] O build roda sem erros? (`npm run build`)
- [ ] A CLI acha vulnerabilidades no diretório de exemplo? (`npx tsx src/cli.ts scan examples`)
- [ ] Nenhuma nova regra imprime secrets inteiros acidentalmente?
- [ ] O `package.json` está com a versão incrementada?
- [ ] O `README.md` reflete fielmente o que a ferramenta faz agora?
- [ ] Não há APIs pagas ou chamadas ocultas a bancos de dados incluídas?
- [ ] O release passará sem avisos pesados de vulnerabilidades de dependências no `npm audit`?
