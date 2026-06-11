import { Finding, Severity } from "./types";

export function calculateRiskScore(findings: Finding[]): Severity {
  let hasMedium = false;
  let hasHigh = false;
  let hasCritical = false;

  for (const finding of findings) {
    if (finding.severity === "CRITICAL") hasCritical = true;
    if (finding.severity === "HIGH") hasHigh = true;
    if (finding.severity === "MEDIUM") hasMedium = true;
  }

  if (hasCritical) return "CRITICAL";
  if (hasHigh) return "HIGH";
  if (hasMedium) return "MEDIUM";
  if (findings.length > 0) return "LOW";
  return "LOW";
}
