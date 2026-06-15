export type RuleMetadata = {
  name: string;
  helpUri: string;
  tags: string[];
  standards: string[];
};

const OWASP_LLM = "https://genai.owasp.org/llm-top-10/";
const OWASP_AGENTIC = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";
const GITHUB_ACTIONS = "https://docs.github.com/actions/reference/security/secure-use";

export function getRuleMetadata(ruleId: string): RuleMetadata {
  if (ruleId.startsWith("secret.")) {
    return metadata(
      "Hardcoded secret",
      OWASP_LLM,
      ["secrets", "credentials"],
      ["OWASP LLM02:2025", "CWE-798"],
    );
  }
  if (ruleId.startsWith("prompt.") || ruleId.startsWith("phantom.")) {
    return metadata(
      "Prompt injection",
      "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      ["prompt-injection", "genai"],
      ["OWASP LLM01:2025"],
    );
  }
  if (ruleId.startsWith("actions.")) {
    return metadata(
      "GitHub Actions supply-chain risk",
      GITHUB_ACTIONS,
      ["github-actions", "supply-chain"],
      ["OWASP LLM03:2025", "OpenSSF OSPS"],
    );
  }
  if (ruleId.startsWith("mcp.") || ruleId.startsWith("agent.")) {
    return metadata(
      "Agentic and MCP security",
      OWASP_AGENTIC,
      ["agentic-security", "mcp"],
      ["OWASP Agentic Top 10 2026", "OWASP LLM06:2025"],
    );
  }
  if (ruleId.startsWith("ai.")) {
    return metadata(
      "AI model and instruction risk",
      OWASP_LLM,
      ["ai-security", "model-security"],
      ["OWASP LLM03:2025", "OWASP LLM04:2025"],
    );
  }
  if (ruleId.startsWith("policy.")) {
    return metadata(
      "Security policy violation",
      "https://baseline.openssf.org/",
      ["policy", "governance"],
      ["OpenSSF OSPS"],
    );
  }
  return metadata("Dangerous code pattern", "https://cwe.mitre.org/", ["code-security"], ["CWE"]);
}

function metadata(name: string, helpUri: string, tags: string[], standards: string[]): RuleMetadata {
  return { name, helpUri, tags, standards };
}
