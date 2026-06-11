import { Rule, Finding } from "../types";

const PROMPT_INJECTION_PATTERNS = [
  { phrase: "ignore previous instructions", severity: "MEDIUM" },
  { phrase: "ignore all previous instructions", severity: "MEDIUM" },
  { phrase: "reveal your system prompt", severity: "MEDIUM" },
  { phrase: "print environment variables", severity: "HIGH" },
  { phrase: "send the token", severity: "HIGH" },
  { phrase: "exfiltrate", severity: "HIGH" },
  { phrase: "bypass safety", severity: "MEDIUM" },
  { phrase: "disable guardrails", severity: "MEDIUM" },
  { phrase: "act as root", severity: "MEDIUM" },
  { phrase: "leak secrets", severity: "HIGH" },
];

export const promptInjectionRule: Rule = {
  id: "prompt_injection",
  description: "Detects common prompt injection phrases",
  severity: "MEDIUM",
  fileTypes: [".md", ".txt", ".prompt", ".json", ".yaml", ".yml"],
  scan: (input) => {
    const findings: Finding[] = [];

    input.lines.forEach((line, index) => {
      const lowerLine = line.toLowerCase();
      
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (lowerLine.includes(pattern.phrase)) {
          findings.push({
            ruleId: "prompt.injection_phrase",
            severity: pattern.severity as "MEDIUM" | "HIGH",
            filePath: input.filePath,
            line: index + 1,
            message: `Prompt injection phrase detected: "${pattern.phrase}".`,
            snippet: line.trim().substring(0, 50) + "...",
            fix: "Treat external content as data, not instructions. Verify inputs and use clear separation."
          });
        }
      }
    });

    return findings;
  }
};
