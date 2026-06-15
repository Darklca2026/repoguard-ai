import { createHash } from "node:crypto";
import type { Finding, Severity } from "../types";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export function createFindingFingerprint(finding: Finding): string {
  const stableEvidence = (finding.snippet ?? finding.message).replace(/\s+/g, " ").trim().toLowerCase();
  return createHash("sha256")
    .update(
      [finding.ruleId, finding.severity, finding.filePath.replace(/\\/g, "/"), stableEvidence].join("\0"),
    )
    .digest("hex");
}

export function addFingerprints(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({
    ...finding,
    fingerprint: createFindingFingerprint(finding),
  }));
}

export function sortAndDedupeFindings(findings: Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const key = [
      finding.ruleId,
      finding.filePath,
      finding.line ?? 0,
      finding.snippet ?? finding.message,
    ].join("\0");
    if (!unique.has(key)) unique.set(key, finding);
  }

  return [...unique.values()].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.filePath.localeCompare(b.filePath) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}
