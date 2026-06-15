import pc from "picocolors";
import { getRuleMetadata } from "./rule-metadata";
import type { Finding, ScanStats, Severity } from "./types";

export type ReportContext = {
  findings: Finding[];
  stats: ScanStats;
  riskScore: Severity;
  suppressedFindings?: number;
  version: string;
};

export function printTerminalReport(context: ReportContext): void {
  const { findings, stats, riskScore, suppressedFindings = 0 } = context;
  console.log(`\n${pc.bold(pc.blue("RepoGuard AI Report"))}\n`);
  console.log(`Risk score: ${pc.bold(colorSeverity(riskScore)(riskScore))}`);
  console.log(`Files scanned: ${stats.filesScanned}/${stats.filesDiscovered}`);
  console.log(`Findings: ${findings.length}`);
  if (suppressedFindings > 0) console.log(`Baseline suppressed: ${suppressedFindings}`);
  if (stats.skippedBinary > 0) console.log(`Binary files skipped: ${stats.skippedBinary}`);
  if (stats.skippedOversized > 0) console.log(`Oversized files skipped: ${stats.skippedOversized}`);
  if (stats.suppressedInline > 0) console.log(`Inline suppressed: ${stats.suppressedInline}`);
  if (stats.readErrors.length > 0) {
    console.log(pc.red(`Read errors: ${stats.readErrors.length}`));
  }
  console.log("");

  const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  for (const severity of severityOrder) {
    for (const finding of findings.filter((item) => item.severity === severity)) {
      const location = finding.line ? `${finding.filePath}:${finding.line}` : finding.filePath;
      console.log(`[${pc.bold(colorSeverity(severity)(severity))}] ${location} ${pc.gray(finding.ruleId)}`);
      console.log(finding.message);
      if (finding.snippet) console.log(`Snippet: ${pc.dim(finding.snippet)}`);
      if (finding.fix) console.log(`${pc.green("Fix:")} ${finding.fix}`);
      if (finding.fingerprint) console.log(`Fingerprint: ${pc.dim(finding.fingerprint.slice(0, 12))}`);
      console.log("");
    }
  }

  for (const diagnostic of stats.readErrors) {
    console.log(`${pc.red("[READ ERROR]")} ${diagnostic.filePath}: ${diagnostic.reason}`);
  }
}

export function printJsonReport(context: ReportContext): void {
  const { findings, stats, riskScore, suppressedFindings = 0, version } = context;
  console.log(
    JSON.stringify(
      {
        version,
        summary: {
          ...stats,
          readErrors: stats.readErrors.length,
          riskScore,
          totalFindings: findings.length,
          suppressedFindings,
        },
        diagnostics: stats.readErrors,
        findings,
      },
      null,
      2,
    ),
  );
}

export function printSarifReport(context: ReportContext): void {
  const { findings, stats, version, suppressedFindings = 0 } = context;
  const examplesByRule = new Map<string, Finding>();
  for (const finding of findings) {
    if (!examplesByRule.has(finding.ruleId)) examplesByRule.set(finding.ruleId, finding);
  }
  const rules = [...examplesByRule.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([ruleId, example]) => {
      const metadata = getRuleMetadata(ruleId);
      return {
        id: ruleId,
        name: metadata.name,
        shortDescription: { text: example.message },
        fullDescription: { text: example.message },
        helpUri: metadata.helpUri,
        help: { text: example.fix ?? "Review this finding and confirm the code is safe." },
        properties: {
          tags: ["security", "ai-security", example.severity.toLowerCase(), ...metadata.tags],
          standards: metadata.standards,
          "security-severity": sarifSecuritySeverity(example.severity),
        },
      };
    });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "RepoGuard AI",
            informationUri: "https://github.com/Darklca2026/repoguard-ai",
            version,
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: stats.readErrors.length === 0,
            properties: {
              filesScanned: stats.filesScanned,
              filesDiscovered: stats.filesDiscovered,
              skippedBinary: stats.skippedBinary,
              skippedOversized: stats.skippedOversized,
              suppressedInline: stats.suppressedInline,
              readErrors: stats.readErrors.length,
              suppressedFindings,
            },
          },
        ],
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: {
            text: `[${finding.severity}] ${finding.message}${finding.fix ? ` - ${finding.fix}` : ""}`,
          },
          partialFingerprints: finding.fingerprint ? { "repoguard/v1": finding.fingerprint } : undefined,
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.filePath, uriBaseId: "%SRCROOT%" },
                region: { startLine: finding.line || 1 },
              },
            },
          ],
        })),
      },
    ],
  };
  console.log(JSON.stringify(sarif, null, 2));
}

function colorSeverity(severity: Severity): (value: string) => string {
  if (severity === "CRITICAL") return pc.red;
  if (severity === "HIGH") return pc.magenta;
  if (severity === "MEDIUM") return pc.yellow;
  return pc.green;
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "CRITICAL" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

function sarifSecuritySeverity(severity: Severity): string {
  return { CRITICAL: "9.5", HIGH: "8.0", MEDIUM: "5.5", LOW: "2.0" }[severity];
}
