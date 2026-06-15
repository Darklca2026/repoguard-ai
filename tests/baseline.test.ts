import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { filterBaseline, writeBaseline } from "../src/baseline";
import { addFingerprints } from "../src/utils/findings";

const tempDirs: string[] = [];
afterEach(() =>
  tempDirs.splice(0).forEach((dir) => {
    fs.rmSync(dir, { recursive: true, force: true });
  }),
);

describe("Finding baselines", () => {
  it("suppresses stable findings even when their line changes", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-baseline-"));
    tempDirs.push(tempDir);
    const baselinePath = path.join(tempDir, "baseline.json");
    const original = addFingerprints([
      {
        ruleId: "test.rule",
        severity: "HIGH" as const,
        filePath: "src/app.ts",
        line: 10,
        message: "Risk found",
        snippet: "dangerous(value)",
      },
    ]);
    writeBaseline(original, baselinePath);

    const moved = addFingerprints([{ ...original[0], line: 42, fingerprint: undefined }]);
    const result = filterBaseline(moved, baselinePath);
    expect(result.findings).toEqual([]);
    expect(result.suppressed).toBe(1);
  });

  it("does not suppress a finding whose severity increased", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-baseline-"));
    tempDirs.push(tempDir);
    const baselinePath = path.join(tempDir, "baseline.json");
    const medium = addFingerprints([
      {
        ruleId: "test.rule",
        severity: "MEDIUM" as const,
        filePath: "src/app.ts",
        message: "Risk found",
        snippet: "dangerous(value)",
      },
    ]);
    writeBaseline(medium, baselinePath);
    const critical = addFingerprints([
      { ...medium[0], severity: "CRITICAL" as const, fingerprint: undefined },
    ]);
    expect(filterBaseline(critical, baselinePath).findings).toHaveLength(1);
  });

  it("rejects malformed or forward-incompatible baseline files", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-baseline-"));
    tempDirs.push(tempDir);
    const baselinePath = path.join(tempDir, "baseline.json");
    fs.writeFileSync(baselinePath, JSON.stringify({ version: 2, generatedAt: "today", findings: [] }));
    expect(() => filterBaseline([], baselinePath)).toThrow("Invalid baseline file");
  });
});
