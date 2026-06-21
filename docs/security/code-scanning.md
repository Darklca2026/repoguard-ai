# Política de Code Scanning (PT-BR)

## 1. Objetivo
Estabelecer um processo padronizado de detecção, triagem e tratamento de vulnerabilidades de código via Code Scanning.

## 2. Escopo
Aplica-se a este repositório para:
- análise em Pull Requests;
- análise em push para branch principal;
- análise agendada semanal.

## 3. Ferramenta
- GitHub Code Scanning com CodeQL.

## 4. Fluxo operacional
1. Workflow executa em PR/push/schedule.
2. Alertas são publicados em **Security > Code scanning alerts**.
3. Time responsável realiza triagem.
4. Cada alerta recebe uma ação: corrigir, false positive, ou won’t fix (com justificativa).

## 5. SLA de tratamento
- Critical: até 24 horas
- High: até 7 dias
- Medium: até 30 dias
- Low: até 90 dias

## 6. Critérios de decisão
### 6.1 Corrigir
Quando houver risco real explorável ou impacto relevante de segurança.

### 6.2 False Positive
Quando a detecção não representa risco real no contexto da aplicação.
**Obrigatório** registrar justificativa técnica.

### 6.3 Won’t Fix
Quando o risco for aceito formalmente por motivo de negócio/técnico.
**Obrigatório** registrar:
- motivo;
- responsável pela aprovação;
- prazo de revisão dessa decisão.

## 7. Papéis e responsabilidades
- **Autores de PR**: tratar alertas introduzidos na mudança.
- **Revisores/CODEOWNERS**: validar correção ou justificativa.
- **Responsável de segurança**: acompanhar backlog e SLA.

## 8. Métricas mínimas
- Alertas abertos por severidade.
- Tempo médio de correção (MTTR).
- % de alertas dentro do SLA.
- Top regras recorrentes.

## 9. Exceções
Toda exceção (false positive ou won’t fix) deve conter justificativa auditável no próprio alerta/PR.
