import { describe, it, expect } from "vitest";
import { secretsRule } from "../src/rules/secrets";

describe("Secrets Rule", () => {
  it("detects OPENAI_API_KEY", () => {
    const input = {
      filePath: ".env",
      content: "OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij",
      lines: ["OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij"]
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
      lines: ["OPENAI_API_KEY=your_key_here"]
    };
    
    const findings = secretsRule.scan(input);
    expect(findings.length).toBe(0);
  });
});
