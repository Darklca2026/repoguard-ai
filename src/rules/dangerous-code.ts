import { Rule, Finding } from "../types";

const DANGEROUS_PATTERNS = [
  { regex: /eval\s*\(/, severity: "MEDIUM", id: "code.eval", fix: "Avoid using eval(). It can execute arbitrary code." },
  { regex: /child_process\.exec\s*\(/, severity: "MEDIUM", id: "code.exec", fix: "Use execFile or spawn instead of exec to avoid shell injection." },
  { regex: /execSync\s*\(/, severity: "MEDIUM", id: "code.execSync", fix: "Use execFileSync instead of execSync to avoid shell injection." },
  { regex: /os\.system\s*\(/, severity: "MEDIUM", id: "code.os_system", fix: "Avoid os.system in Python. Use subprocess module safely." },
  { regex: /subprocess\.(run|call|Popen).*shell=True/, severity: "MEDIUM", id: "code.subprocess_shell", fix: "Avoid using shell=True in subprocess calls to prevent injection." },
  { regex: /rm\s+-rf\s+/, severity: "HIGH", id: "code.rm_rf", fix: "Use absolute paths or safer deletion methods." },
  { regex: /curl.*\|\s*bash/, severity: "HIGH", id: "code.curl_pipe_bash", fix: "Download and verify scripts before execution." },
  { regex: /wget.*\|\s*sh/, severity: "HIGH", id: "code.wget_pipe_sh", fix: "Download and verify scripts before execution." },
  { regex: /chmod\s+777/, severity: "LOW", id: "code.chmod_777", fix: "Avoid setting 777 permissions. Give only required permissions." },
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
