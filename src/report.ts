import pc from "picocolors";
import { Finding, Severity } from "./types";

export function printTerminalReport(findings: Finding[], filesScanned: number, score: Severity) {
  console.log(`\n${pc.bold(pc.blue("RepoGuard AI Report"))}\n`);
  
  const scoreColor = score === "CRITICAL" ? pc.red : score === "HIGH" ? pc.magenta : score === "MEDIUM" ? pc.yellow : pc.green;
  
  console.log(`Risk score: ${pc.bold(scoreColor(score))}`);
  console.log(`Files scanned: ${filesScanned}`);
  console.log(`Findings: ${findings.length}\n`);

  // Group by severity
  const grouped = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL"),
    HIGH: findings.filter(f => f.severity === "HIGH"),
    MEDIUM: findings.filter(f => f.severity === "MEDIUM"),
    LOW: findings.filter(f => f.severity === "LOW"),
  };

  const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  severityOrder.forEach(severity => {
    const severityFindings = grouped[severity];
    if (severityFindings.length === 0) return;

    const color = severity === "CRITICAL" ? pc.red : severity === "HIGH" ? pc.magenta : severity === "MEDIUM" ? pc.yellow : pc.green;

    severityFindings.forEach(finding => {
      const location = finding.line ? `${finding.filePath}:${finding.line}` : finding.filePath;
      console.log(`[${pc.bold(color(severity))}] ${location} ${pc.gray(finding.ruleId)}`);
      console.log(`${finding.message}`);
      if (finding.snippet) {
        console.log(`Snippet: ${pc.dim(finding.snippet)}`);
      }
      if (finding.fix) {
        console.log(`${pc.green("Fix:")} ${finding.fix}`);
      }
      console.log("");
    });
  });
}

export function printJsonReport(findings: Finding[], filesScanned: number, score: Severity) {
  const report = {
    riskScore: score,
    filesScanned,
    findingsCount: findings.length,
    findings
  };
  console.log(JSON.stringify(report, null, 2));
}
