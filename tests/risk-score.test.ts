import { describe, it, [SECRET_REMOVED_BY_REPOGUARD] } from "vitest";
import { calculateRiskScore } from "../src/risk-score";
import { Finding } from "../src/types";

describe("Risk Score Calculator", () => {
  it("returns CRITICAL if there is at least one critical finding", () => {
    const findings: Finding[] = [
      { ruleId: "test", severity: "LOW", filePath: "a", message: "m" },
      { ruleId: "test2", severity: "CRITICAL", filePath: "b", message: "m" }
    ];
    [SECRET_REMOVED_BY_REPOGUARD](calculateRiskScore(findings)).toBe("CRITICAL");
  });

  it("returns LOW if findings is empty", () => {
    [SECRET_REMOVED_BY_REPOGUARD](calculateRiskScore([])).toBe("LOW");
  });
});
