import { describe, it, expect } from "vitest";
import { dangerousCodeRule } from "../src/rules/dangerous-code";

describe("Dangerous Code Rule", () => {
  it("detects eval", () => {
    const input = {
      filePath: "src/index.js",
      content: "eval('console.log(1)')",
      lines: ["eval('console.log(1)')"]
    };
    
    const findings = dangerousCodeRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("code.eval");
  });

  it("detects rm -rf", () => {
    const input = {
      filePath: "scripts/clean.sh",
      content: "rm -rf /",
      lines: ["rm -rf /"]
    };
    
    const findings = dangerousCodeRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("code.rm_rf");
  });
});
