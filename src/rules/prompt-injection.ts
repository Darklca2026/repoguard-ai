import { Rule, Finding } from "../types";
import { isSuspiciousBase64 } from "../utils/crypto";

const INJECTION_PHRASES = [
  { phrase: "ignore previous instructions", severity: "MEDIUM" as const },
  { phrase: "print environment variables", severity: "HIGH" as const },
  { phrase: "send the token", severity: "HIGH" as const },
  { phrase: "exfiltrate", severity: "HIGH" as const },
  { phrase: "leak secrets", severity: "HIGH" as const },
  { phrase: "bypass safety", severity: "MEDIUM" as const },
  { phrase: "act as root", severity: "MEDIUM" as const }
];

export const promptInjectionRule: Rule = {
  id: "prompt-injection",
  name: "Prompt Injection Detection",
  scan: (input) => {
    // Apenas varre extensões que podem conter texto ou prompts
    if (!/\.(md|txt|json|yaml|yml|prompt)$/i.test(input.filePath)) {
      return [];
    }

    const findings: Finding[] = [];
    const contentLower = input.content.toLowerCase();
    const lines = input.content.split("\n");

    // 1. Checagem Padrão (Texto Claro)
    for (const pattern of INJECTION_PHRASES) {
      if (contentLower.includes(pattern.phrase)) {
        findings.push({
          ruleId: "prompt.injection_phrase",
          severity: pattern.severity,
          file: input.filePath,
          line: lines.findIndex(line => line.toLowerCase().includes(pattern.phrase)) + 1 || 1,
          snippet: `...${pattern.phrase}...`,
          recommendation: "Treat external content as data, not instructions. Verify inputs and use clear separation."
        });
      }
    }

    // 2. Checagem de Evasão (Payloads em Base64)
    // Procuramos palavras longas que possam ser B64
    const words = input.content.split(/[\s"']/);
    for (const word of words) {
      if (word.length > 20) {
        const decodedInjection = isSuspiciousBase64(word);
        if (decodedInjection) {
          findings.push({
            ruleId: "prompt.injection_base64_evasion",
            severity: "HIGH",
            file: input.filePath,
            line: lines.findIndex(line => line.includes(word)) + 1 || 1,
            snippet: `[Base64 Decoded]: ...${decodedInjection.substring(0, 30)}...`,
            recommendation: "Malicious base64-encoded prompt injection detected. Remove immediately."
          });
        }
      }
    }

    return findings;
  }
};
