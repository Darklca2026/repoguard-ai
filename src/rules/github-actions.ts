import { Rule, Finding } from "../types";

export const githubActionsRule: Rule = {
  id: "github_actions.risky_workflow",
  description: "Detects dangerous GitHub Actions configurations",
  severity: "HIGH",
  fileTypes: [".yml", ".yaml"],
  scan: (input) => {
    const findings: Finding[] = [];

    // Only scan files in .github/workflows
    if (!input.filePath.includes(".github/workflows")) {
      return findings;
    }

    let isPullRequestWorkflow = false;

    input.lines.forEach((line, index) => {
      const trimmedLine = line.trim();

      if (trimmedLine.includes("on:") && input.lines.slice(index, index + 5).some(l => l.includes("pull_request"))) {
        isPullRequestWorkflow = true;
      }

      if (trimmedLine === "on: pull_request_target" || trimmedLine.includes("pull_request_target:")) {
        findings.push({
          ruleId: "actions.pull_request_target",
          severity: "HIGH",
          filePath: input.filePath,
          line: index + 1,
          message: "Workflow uses pull_request_target.",
          snippet: line.trim(),
          fix: "Avoid pull_request_target for untrusted pull requests or restrict permissions."
        });
      }

      if (trimmedLine.includes("permissions:") && trimmedLine.includes("write-all")) {
         findings.push({
          ruleId: "actions.write_all",
          severity: "HIGH",
          filePath: input.filePath,
          line: index + 1,
          message: "Workflow requests write-all permissions.",
          snippet: line.trim(),
          fix: "Use principle of least privilege. Explicitly request only needed permissions."
        });
      }
      
      if (trimmedLine.includes("curl") && trimmedLine.includes("| bash")) {
         findings.push({
          ruleId: "actions.curl_pipe_bash",
          severity: "HIGH",
          filePath: input.filePath,
          line: index + 1,
          message: "Dangerous pattern found in workflow: curl | bash.",
          snippet: line.trim(),
          fix: "Download and verify scripts before execution."
        });
      }

      if (trimmedLine.includes("wget") && trimmedLine.includes("| sh")) {
         findings.push({
          ruleId: "actions.wget_pipe_sh",
          severity: "HIGH",
          filePath: input.filePath,
          line: index + 1,
          message: "Dangerous pattern found in workflow: wget | sh.",
          snippet: line.trim(),
          fix: "Download and verify scripts before execution."
        });
      }

      if (trimmedLine.match(/uses:\s*[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+@(?!(.*[a-f0-9]{40}))/)) {
        // Checking for uses without SHA
        // e.g. actions/checkout@v3 or owner/repo@main
        const usesMatch = trimmedLine.match(/uses:\s*([^@\s]+@[^\s]+)/);
        if (usesMatch) {
          const actionRef = usesMatch[1];
          if (!actionRef.startsWith("actions/")) { // Ignore official GitHub Actions for less noise
             findings.push({
              ruleId: "actions.unpinned_dependency",
              severity: "MEDIUM",
              filePath: input.filePath,
              line: index + 1,
              message: "Third-party action is not pinned to a full commit SHA.",
              snippet: line.trim(),
              fix: "Pin actions to a full 40-character commit SHA for security."
            });
          }
        }
      }
    });

    return findings;
  }
};
