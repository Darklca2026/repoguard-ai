import { Rule, Finding } from "../types";

const DANGEROUS_PATTERNS = [
  { id: "code.eval", regex: /eval\s*\(/, severity: "MEDIUM", fix: "Avoid using eval(). It can execute arbitrary code." },
  { id: "code.exec", regex: /child_process\.exec\s*\(/, severity: "HIGH", fix: "Use execFile or spawn instead of exec to avoid shell injection." },
  { id: "code.execSync", regex: /execSync\s*\(/, severity: "MEDIUM", fix: "Use execFileSync instead of execSync to avoid shell injection." },
  { id: "code.os_system", regex: /os\.system\s*\(/, severity: "HIGH", fix: "Avoid os.system in Python. Use subprocess module safely." },
  { id: "code.subprocess_shell", regex: /subprocess\.(run|call|Popen).*shell=True/, severity: "MEDIUM", fix: "Avoid using shell=True in subprocess calls to prevent injection." },
  { id: "code.rm_rf", regex: /rm\s+-rf\s+/, severity: "HIGH", fix: "Use absolute paths or safer deletion methods." },
  { id: "code.curl_pipe_bash", regex: /curl.*\|\s*(bash|sh)/, severity: "HIGH", fix: "Download and verify scripts before execution." },
  { id: "code.wget_pipe_bash", regex: /wget.*\|\s*(bash|sh)/, severity: "HIGH", fix: "Download and verify scripts before execution." },
  { id: "code.chmod_777", regex: /chmod\s+777/, severity: "LOW", fix: "Avoid setting 777 permissions. Give only required permissions." },
  { id: "tamper.delete_git", regex: /rm\s+-rf\s+(.*\.git)/, severity: "CRITICAL", fix: "Deletion of .git directory detected. This is a potential tampering attempt." },
  { id: "tamper.delete_workflows", regex: /rm\s+-rf\s+(.*\.github)/, severity: "CRITICAL", fix: "Deletion of .github workflows detected. This is a potential tampering attempt." },
  { id: "tamper.clear_logs", regex: />\s*\/dev\/null/, severity: "LOW", fix: "Silencing execution output/errors is often used to hide tampering." }
];

export const dangerousCodeRule: Rule = {
  id: "dangerous_code",
  description: "Detects dangerous code or shell execution patterns",
  severity: "MEDIUM",
  fileTypes: [".js", ".ts", ".mjs", ".cjs", ".py", ".sh", ".bash", ".zsh", ".yaml", ".yml"],
  scan: (input) => {
    const findings: Finding[] = [];

    input.lines.forEach((line, index) => {
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.regex.test(line)) {
          findings.push({
            ruleId: pattern.id,
            severity: pattern.severity as "LOW" | "MEDIUM" | "HIGH",
            filePath: input.filePath,
            line: index + 1,
            message: `Dangerous code pattern found: ${pattern.id}.`,
            snippet: line.trim().substring(0, 80),
            fix: pattern.fix
          });
        }
      }
    });

    return findings;
  }
};
