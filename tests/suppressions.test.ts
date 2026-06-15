import { describe, expect, it } from "vitest";
import { applyInlineSuppressions } from "../src/suppressions";
import type { Finding } from "../src/types";

const finding: Finding = {
  ruleId: "secrets.openai_key",
  severity: "CRITICAL",
  filePath: "example.env",
  line: 2,
  message: "Secret detected",
};

describe("Inline suppressions", () => {
  it("suppresses the next line when a reason and valid expiry are present", () => {
    const lines = [
      "# repoguard-ignore-next-line secrets.* -- test fixture; owner=security; expires=2026-06-30",
      "OPENAI_API_KEY=fixture",
    ];
    const result = applyInlineSuppressions(
      [finding],
      lines,
      finding.filePath,
      {
        requireReason: true,
        requireExpiry: true,
      },
      new Date("2026-06-15T12:00:00Z"),
    );

    expect(result.findings).toEqual([]);
    expect(result.suppressed).toBe(1);
  });

  it("reports expired suppressions as policy findings", () => {
    const lines = [
      "# repoguard-ignore-next-line secrets.* -- old fixture; expires=2026-06-01",
      "OPENAI_API_KEY=fixture",
    ];
    const result = applyInlineSuppressions(
      [finding],
      lines,
      finding.filePath,
      {},
      new Date("2026-06-15T12:00:00Z"),
    );

    expect(result.findings.map((item) => item.ruleId)).toEqual([
      "secrets.openai_key",
      "policy.invalid_suppression",
    ]);
    expect(result.suppressed).toBe(0);
  });

  it("does not treat ordinary data as a suppression directive", () => {
    const lines = [
      "value=repoguard-ignore-next-line secrets.* -- attacker controlled",
      "OPENAI_API_KEY=fixture",
    ];
    expect(applyInlineSuppressions([finding], lines, finding.filePath).findings).toEqual([finding]);
  });
});
