import type { Finding, Rule } from "../types";

const UNTRUSTED_CONTEXT =
  /\$\{\{[^}]*(?:github\.event\.(?:issue|pull_request|comment|review|discussion|head_commit)|github\.head_ref)[^}]*\}\}/i;

export const githubActionsRule: Rule = {
  id: "github_actions.risky_workflow",
  description: "Detects dangerous GitHub Actions configurations",
  severity: "HIGH",
  fileTypes: [".yml", ".yaml"],
  scan: (input) => {
    if (!/(?:^|\/)\.github\/workflows\//.test(input.filePath)) return [];

    const findings: Finding[] = [];
    const usesPullRequestTarget =
      /(?:^|\n)\s*(?:on\s*:\s*(?:\[[^\]]*\bpull_request_target\b[^\]]*\]|pull_request_target)|pull_request_target\s*:)/m.test(
        input.content,
      );
    let runBlockIndent: number | undefined;

    input.lines.forEach((line, index) => {
      const trimmed = line.trim();
      const indent = line.length - line.trimStart().length;
      if (runBlockIndent !== undefined && trimmed && indent <= runBlockIndent) runBlockIndent = undefined;
      const isRunLine = /^run\s*:/.test(trimmed) || runBlockIndent !== undefined;
      if (/^run\s*:\s*[|>]\s*$/.test(trimmed)) runBlockIndent = indent;

      if (
        /^pull_request_target\s*:|^on\s*:\s*(?:pull_request_target|\[[^\]]*\bpull_request_target\b[^\]]*\])\s*$/.test(
          trimmed,
        )
      ) {
        findings.push(
          finding(
            "actions.pull_request_target",
            "HIGH",
            input.filePath,
            index,
            line,
            "Workflow uses pull_request_target, which runs with base-repository privileges.",
            "Prefer pull_request. If pull_request_target is required, never execute untrusted PR code and minimize permissions.",
          ),
        );
      }

      if (/^permissions\s*:\s*write-all\s*$/.test(trimmed)) {
        findings.push(
          finding(
            "actions.write_all",
            "HIGH",
            input.filePath,
            index,
            line,
            "Workflow requests write-all permissions.",
            "Declare only the specific read or write permissions required by each job.",
          ),
        );
      }

      if (/curl\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(trimmed)) {
        findings.push(
          finding(
            "actions.curl_pipe_bash",
            "HIGH",
            input.filePath,
            index,
            line,
            "Workflow pipes a remote script directly into a shell.",
            "Download a versioned artifact, verify its checksum or signature, then execute it.",
          ),
        );
      }

      if (/wget\b.*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i.test(trimmed)) {
        findings.push(
          finding(
            "actions.wget_pipe_sh",
            "HIGH",
            input.filePath,
            index,
            line,
            "Workflow pipes a remote script directly into a shell.",
            "Download a versioned artifact, verify its checksum or signature, then execute it.",
          ),
        );
      }

      const usesMatch = trimmed.match(/^uses\s*:\s*([^\s#]+)/);
      if (usesMatch && !usesMatch[1].startsWith("./") && !usesMatch[1].startsWith("docker://")) {
        const actionRef = usesMatch[1];
        const ref = actionRef.split("@").pop() ?? "";
        if (!/^[a-f0-9]{40}$/i.test(ref)) {
          findings.push(
            finding(
              "actions.unpinned_dependency",
              "MEDIUM",
              input.filePath,
              index,
              line,
              "Action is not pinned to a full commit SHA.",
              "Pin every external action to a reviewed 40-character commit SHA and keep the release tag in a comment.",
            ),
          );
        }
      }

      if (isRunLine && UNTRUSTED_CONTEXT.test(line)) {
        findings.push(
          finding(
            "actions.untrusted_input_in_script",
            "HIGH",
            input.filePath,
            index,
            line,
            "Potentially attacker-controlled GitHub context is interpolated directly into a shell script.",
            "Assign the expression to an environment variable and treat it as untrusted data, or pass it to a non-shell action input.",
          ),
        );
      }

      if (
        usesPullRequestTarget &&
        /github\.event\.pull_request\.(?:head\.(?:sha|ref)|head\.repo)/.test(line)
      ) {
        findings.push(
          finding(
            "actions.privileged_untrusted_checkout",
            "CRITICAL",
            input.filePath,
            index,
            line,
            "A pull_request_target workflow references untrusted pull request head data with base-repository privileges.",
            "Do not check out or execute pull request code in a privileged workflow. Split validation and privileged follow-up into separate workflows.",
          ),
        );
      }
    });

    return findings;
  },
};

function finding(
  ruleId: string,
  severity: "MEDIUM" | "HIGH" | "CRITICAL",
  filePath: string,
  zeroBasedLine: number,
  line: string,
  message: string,
  fix: string,
): Finding {
  return {
    ruleId,
    severity,
    filePath,
    line: zeroBasedLine + 1,
    message,
    snippet: line.trim().slice(0, 120),
    fix,
  };
}
