import { describe, expect, it } from "vitest";
import { secretsRule } from "../src/rules/secrets";

describe("Secrets Rule", () => {
  it("detects OPENAI_API_KEY", () => {
    const input = {
      filePath: ".env",
      content: "OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij",
      lines: ["OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij"],
    };

    const findings = secretsRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe("CRITICAL");
    expect(findings[0].snippet).toBe("sk-pro************************");
  });

  it("ignores safe values", () => {
    const input = {
      filePath: ".env",
      content: "OPENAI_API_KEY=your_key_here",
      lines: ["OPENAI_API_KEY=your_key_here"],
    };

    const findings = secretsRule.scan(input);
    expect(findings.length).toBe(0);
  });

  it("detects current AI provider token formats", () => {
    const content = [
      `HF_TOKEN=hf_${"A".repeat(30)}`,
      `GOOGLE_API_KEY=AIza${"A".repeat(35)}`,
      `GROQ_API_KEY=gsk_${"A".repeat(40)}`,
      `OPENROUTER_API_KEY=sk-or-v1-${"A".repeat(32)}`,
    ].join("\n");
    const findings = secretsRule.scan({ filePath: ".env", content, lines: content.split("\n") });

    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "secret.huggingface_token",
      "secret.google_api_key",
      "secret.groq_api_key",
      "secret.openrouter_api_key",
    ]);
  });
});
