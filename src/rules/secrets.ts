import { Rule, Finding } from "../types";

const SECRET_PATTERNS = [
  { id: "secret.openai_api_key", regex: /sk-[a-zA-Z0-9\-]{20,}/g, name: "OpenAI API Key" },
  { id: "secret.anthropic_api_key", regex: /sk-ant-api[0-9a-zA-Z\-_]{20,}/g, name: "Anthropic API Key" },
  { id: "secret.github_token", regex: /(ghp|github_pat)_[a-zA-Z0-9]{36,}/g, name: "GitHub Token" },
  { id: "secret.aws_key", regex: /AKIA[0-9A-Z]{16}/g, name: "AWS Access Key" },
  { id: "secret.private_key", regex: /-----BEGIN PRIVATE KEY-----/g, name: "Private Key" },
  { id: "secret.database_url", regex: /postgres(ql)?:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^?\s]+/g, name: "Database URL" }
];

function redactSecret(secret: string): string {
  if (secret.length <= 6) return "******";
  return secret.substring(0, 6) + "*".repeat(secret.length - 6);
}

export const secretsRule: Rule = {
  id: "secrets.leaked_credentials",
  description: "Detects leaked API keys, tokens, and credentials",
  severity: "CRITICAL",
  scan: (input) => {
    const findings: Finding[] = [];

    input.lines.forEach((line, index) => {
      for (const pattern of SECRET_PATTERNS) {
        let match;
        while ((match = pattern.regex.exec(line)) !== null) {
          const matchedSecret = match[0];
          findings.push({
            ruleId: pattern.id,
            severity: "CRITICAL",
            filePath: input.filePath,
            line: index + 1,
            message: `Possible ${pattern.name} detected.`,
            snippet: redactSecret(matchedSecret),
            fix: "Remove the key, rotate it, and use environment variables or GitHub Secrets."
          });
        }
      }
    });

    return findings;
  }
};
