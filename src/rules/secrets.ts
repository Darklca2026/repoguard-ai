import { Rule, Finding } from "../types";
import { calculateShannonEntropy } from "../utils/crypto";

const SECRET_PATTERNS = [
  { id: "secret.openai_api_key", regex: /sk-[a-zA-Z0-9\-]{20,}/g, name: "OpenAI API Key" },
  { id: "secret.anthropic_api_key", regex: /sk-ant-api[0-9a-zA-Z\-_]{20,}/g, name: "Anthropic API Key" },
  { id: "secret.github_token", regex: /(ghp|github_pat)_[a-zA-Z0-9]{36,}/g, name: "GitHub Token" },
  { id: "secret.aws_key", regex: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key" },
  { id: "secret.private_key", regex: /-----BEGIN PRIVATE KEY-----/g, name: "Private Key" },
  { id: "secret.database_url", regex: /(postgres|mysql|mongodb\+srv):\/\/[^:\s]+:[^@\s]+@/g, name: "Database URL" }
];

// Heurística: se tiver mais que 20 chars contínuos sem espaço, avaliamos a entropia
const HIGH_ENTROPY_REGEX = /[a-zA-Z0-9\-_]{20,}/g;

export const secretsRule: Rule = {
  id: "secrets",
  name: "Secrets and Credentials",
  scan: (input) => {
    const findings: Finding[] = [];
    
    // 1. Checagem Baseada em Assinaturas Conhecidas
    for (const pattern of SECRET_PATTERNS) {
      const matches = input.content.matchAll(pattern.regex);
      for (const match of matches) {
        findings.push({
          ruleId: pattern.id,
          severity: "CRITICAL",
          file: input.filePath,
          line: input.content.substring(0, match.index).split("\n").length,
          snippet: match[0].substring(0, 6) + "************************", // Ofusca a chave
          recommendation: "Remove the key, rotate it, and use environment variables or GitHub Secrets."
        });
      }
    }

    // 2. Checagem Baseada em Alta Entropia (Heurística)
    const entropyMatches = input.content.matchAll(HIGH_ENTROPY_REGEX);
    for (const match of entropyMatches) {
      const token = match[0];
      const entropy = calculateShannonEntropy(token);
      
      // Se a entropia for maior que 4.5 (muito aleatório) e não tiver sido pego pelos patterns acima
      if (entropy > 4.5) {
        // Evita duplicatas checando se já foi logado
        const alreadyLogged = findings.some(f => f.snippet.startsWith(token.substring(0, 6)));
        if (!alreadyLogged) {
           findings.push({
            ruleId: "secret.high_entropy_string",
            severity: "MEDIUM",
            file: input.filePath,
            line: input.content.substring(0, match.index).split("\n").length,
            snippet: token.substring(0, 6) + "************************",
            recommendation: `High entropy string detected (Entropy: ${entropy.toFixed(2)}). Verify if this is an unknown hardcoded credential.`
          });
        }
      }
    }
    
    return findings;
  }
};
