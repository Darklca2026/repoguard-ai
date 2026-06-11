import { describe, it, [SECRET_REMOVED_BY_REPOGUARD] } from "vitest";
import { secretsRule } from "../src/rules/secrets";

describe("Secrets Rule", () => {
  it("detects OPENAI_API_KEY", () => {
    const input = {
      filePath: ".env",
      content: [SECRET_REMOVED_BY_REPOGUARD]I_API_KEY=sk-proj-abc1234567890abcdefghij",
      lines: [[SECRET_REMOVED_BY_REPOGUARD]I_API_KEY=sk-proj-abc1234567890abcdefghij"]
    };
    
    const findings = secretsRule.scan(input);
    [SECRET_REMOVED_BY_REPOGUARD](findings.length).toBe(1);
    [SECRET_REMOVED_BY_REPOGUARD](findings[0].severity).toBe("CRITICAL");
    [SECRET_REMOVED_BY_REPOGUARD](findings[0].snippet).toBe("sk-pro************************");
  });

  it("ignores safe values", () => {
    const input = {
      filePath: ".env",
      content: [SECRET_REMOVED_BY_REPOGUARD]I_API_KEY=your_key_here",
      lines: [[SECRET_REMOVED_BY_REPOGUARD]I_API_KEY=your_key_here"]
    };
    
    const findings = secretsRule.scan(input);
    [SECRET_REMOVED_BY_REPOGUARD](findings.length).toBe(0);
  });
});
