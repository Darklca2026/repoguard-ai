import { Rule, Finding } from "../types";
import { isSuspiciousBase64 } from "../utils/crypto";
import { detectPhantomEvasion } from "../utils/phantom";

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
  description: "Prompt Injection Detection",
  severity: "HIGH",
  scan: (input) => {
    // Apenas varre extensões que podem conter texto ou prompts
    if (!/\.(md|txt|json|yaml|yml|prompt)$/i.test(input.filePath)) {
      return [];
    }

    const findings: Finding[] = [];
    const lines = input.content.split("\n");

    // Pre-processing: Apply Phantom Evasion Detector
    const phantomData = detectPhantomEvasion(input.content);
    
    // Alerta Imediato para Caracteres Bi-Direcionais Escondidos (Muito Suspeito)
    if (phantomData.hasBidiOverride) {
      findings.push({
        ruleId: "phantom.bidi_override_detected",
        severity: "CRITICAL",
        filePath: input.filePath,
        line: 1, // Assumimos que o arquivo está envenenado estruturalmente
        message: "Malicious Right-to-Left Override character detected.",
        snippet: "Bi-directional text spoofing",
        fix: "Remove BiDi characters. They are often used to spoof file extensions or hide malware."
      });
    }

    const contentLower = phantomData.cleanText.toLowerCase();

    // 1. Checagem Padrão (Texto Limpo de Evasões)
    for (const pattern of INJECTION_PHRASES) {
      if (contentLower.includes(pattern.phrase)) {
        findings.push({
          ruleId: "prompt.injection_phrase",
          severity: pattern.severity,
          filePath: input.filePath,
          line: lines.findIndex(line => detectPhantomEvasion(line.toLowerCase()).cleanText.includes(pattern.phrase)) + 1 || 1,
          snippet: `...${pattern.phrase}...`,
          message: `Prompt injection phrase detected: "${pattern.phrase}".`,
          fix: "Treat external content as data, not instructions. Verify inputs and use clear separation."
        });
      }
    }

    // 2. Checagem de Evasão (Payloads em Base64)
    const words = phantomData.cleanText.split(/[\s"']/);
    for (const word of words) {
      if (word.length > 20) {
        const decodedInjection = isSuspiciousBase64(word);
        if (decodedInjection) {
          findings.push({
            ruleId: "prompt.injection_base64_evasion",
            severity: "HIGH",
            filePath: input.filePath,
            line: lines.findIndex(line => line.includes(word)) + 1 || 1,
            snippet: `[Base64 Decoded]: ...${decodedInjection.substring(0, 30)}...`,
            message: "Malicious base64-encoded prompt injection detected.",
            fix: "Remove immediately."
          });
        }
      }
    }

    return findings;
  }
};
