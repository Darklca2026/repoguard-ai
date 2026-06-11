import { Rule, Finding } from "../types";

export const githubActionsRule: Rule = {
  id: "github_actions.risky_workflow",
  description: "Detects dangerous GitHub Actions configurations",
  severity: "HIGH",
  fileTypes: [".yml", ".yaml"],
  scan: (input) => {
    const findings: Finding[] = [];

    // Only scan files in .github/workflows
    if [SECRET_REMOVED_BY_REPOGUARD]t.filePath.includes(".github/workflows")) {
      return findings;
    }

    let isPullRequestWorkflow = false;

    input.lines.forEach((line, index) => {
      const [SECRET_REMOVED_BY_REPOGUARD]dLine = line.trim();

      if [SECRET_REMOVED_BY_REPOGUARD]edLine.includes("on:") && input.lines.slice(index, index + 5).some(l => l.includes("pull_request"))) {
        isPullRequestWorkflow = true;
      }

      if [SECRET_REMOVED_BY_REPOGUARD]edLine === "on: pull_request_target" || [SECRET_REMOVED_BY_REPOGUARD]dLine.includes("pull_request_target:")) {
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

      if [SECRET_REMOVED_BY_REPOGUARD]edLine.includes("permissions:") && [SECRET_REMOVED_BY_REPOGUARD]dLine.includes("write-all")) {
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
      
      if [SECRET_REMOVED_BY_REPOGUARD]edLine.includes("curl") && [SECRET_REMOVED_BY_REPOGUARD]dLine.includes("| bash")) {
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

      if [SECRET_REMOVED_BY_REPOGUARD]edLine.includes("wget") && [SECRET_REMOVED_BY_REPOGUARD]dLine.includes("| sh")) {
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

      if [SECRET_REMOVED_BY_REPOGUARD]edLine.match(/uses:\s*[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+@(?!(.*[a-f0-9]{40}))/)) {
        // Checking for uses without SHA
        // e.g. actions/checkout@v3 or owner/repo@main
        const usesMatch = [SECRET_REMOVED_BY_REPOGUARD]dLine.match(/uses:\s*([^@\s]+@[^\s]+)/);
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
