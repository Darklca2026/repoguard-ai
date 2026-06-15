import * as fs from "node:fs";
import * as path from "node:path";
import { z } from "zod";
import type { Finding } from "./types";

type BaselineFile = {
  version: 1;
  generatedAt: string;
  findings: Array<Pick<Finding, "ruleId" | "filePath" | "severity"> & { fingerprint: string }>;
};

const baselineSchema = z
  .object({
    version: z.literal(1),
    generatedAt: z.iso.datetime(),
    findings: z.array(
      z
        .object({
          fingerprint: z.string().min(1),
          ruleId: z.string().min(1),
          filePath: z.string().min(1),
          severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        })
        .strict(),
    ),
  })
  .strict();

export function filterBaseline(
  findings: Finding[],
  baselinePath: string,
): {
  findings: Finding[];
  suppressed: number;
} {
  const baseline = readBaseline(baselinePath);
  const fingerprints = new Set(baseline.findings.map((finding) => finding.fingerprint));
  const filtered = findings.filter(
    (finding) => !finding.fingerprint || !fingerprints.has(finding.fingerprint),
  );
  return { findings: filtered, suppressed: findings.length - filtered.length };
}

export function writeBaseline(findings: Finding[], baselinePath: string): void {
  const absolutePath = path.resolve(baselinePath);
  const baseline: BaselineFile = {
    version: 1,
    generatedAt: new Date().toISOString(),
    findings: findings
      .filter((finding): finding is Finding & { fingerprint: string } => Boolean(finding.fingerprint))
      .map(({ fingerprint, ruleId, filePath, severity }) => ({
        fingerprint,
        ruleId,
        filePath,
        severity,
      })),
  };
  fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
  const temporaryPath = `${absolutePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temporaryPath, `${JSON.stringify(baseline, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    fs.renameSync(temporaryPath, absolutePath);
    fs.chmodSync(absolutePath, 0o600);
  } finally {
    fs.rmSync(temporaryPath, { force: true });
  }
}

function readBaseline(baselinePath: string): BaselineFile {
  const absolutePath = path.resolve(baselinePath);
  if (!fs.existsSync(absolutePath)) throw new Error(`Baseline file not found: ${absolutePath}`);

  try {
    return baselineSchema.parse(JSON.parse(fs.readFileSync(absolutePath, "utf8")));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid baseline file: ${absolutePath}: ${detail}`);
  }
}
