import * as path from "node:path";
import type { Finding, Rule } from "../types";

export const aiGeneratedRule: Rule = {
  id: "ai_generated_files",
  description: "Detects AI instruction files or directories",
  severity: "LOW",
  scan: (input) => {
    const findings: Finding[] = [];
    const normalizedPath = input.filePath.replace(/\\/g, "/");
    const basename = path.basename(normalizedPath).toLowerCase();

    if (
      normalizedPath.includes("prompts/") ||
      basename === ".prompt" ||
      basename === ".system.md" ||
      basename === ".agent.md" ||
      normalizedPath.includes(".cursor/rules") ||
      normalizedPath.includes(".claude/") ||
      basename === "copilot-instructions.md" ||
      basename === "agents.md" ||
      basename === "claude.md" ||
      basename === "gemini.md" ||
      basename === "skill.md" ||
      basename === ".mcp.json"
    ) {
      // Add a single finding for the file itself
      findings.push({
        ruleId: "ai.instruction_file",
        severity: "LOW",
        filePath: input.filePath,
        message: "AI instruction file detected.",
        fix: "Ensure that system prompts and instructions do not expose sensitive internal logic.",
      });
    }

    return findings;
  },
};
