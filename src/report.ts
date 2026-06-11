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

export function printJsonReport(findings: Finding[], filesScanned: number, riskScore: string): void {
  const report = {
    summary: { filesScanned, riskScore, totalFindings: findings.length },
    findings
  };
  console.log(JSON.stringify(report, null, 2));
}

export function printSarifReport(findings: Finding[]): void {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "RepoGuard AI",
            informationUri: "https://github.com/Darklca2026/repoguard-ai",
            version: "0.1.0"
          }
        },
        results: findings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === "CRITICAL" || f.severity === "HIGH" ? "error" : "warning",
          message: {
            text: `[${f.severity}] ${f.recommendation || f.snippet}`
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line }
              }
            }
          ]
        }))
      }
    ]
  };
  console.log(JSON.stringify(sarif, null, 2));
}
