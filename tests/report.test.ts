import { afterEach, describe, expect, it, vi } from "vitest";
import { printSarifReport } from "../src/report";

afterEach(() => vi.restoreAllMocks());

describe("SARIF reporting", () => {
  it("emits portable locations, fingerprints, policy metadata, and scan diagnostics", () => {
    const output: string[] = [];
    vi.spyOn(console, "log").mockImplementation((value) => output.push(String(value)));

    printSarifReport({
      version: "0.6.0",
      riskScore: "HIGH",
      suppressedFindings: 2,
      stats: {
        filesDiscovered: 3,
        filesScanned: 2,
        skippedBinary: 0,
        skippedOversized: 1,
        suppressedInline: 1,
        readErrors: [],
      },
      findings: [
        {
          ruleId: "prompt.injection_phrase",
          severity: "HIGH",
          filePath: "prompts/system.md",
          line: 4,
          message: "Prompt injection phrase detected.",
          fix: "Treat untrusted content as data.",
          fingerprint: "abc123",
        },
      ],
    });

    const sarif = JSON.parse(output[0]);
    const run = sarif.runs[0];
    expect(run.tool.driver.rules[0].helpUri).toContain("owasp.org");
    expect(run.tool.driver.rules[0].properties.standards).toContain("OWASP LLM01:2025");
    expect(run.results[0].locations[0].physicalLocation.artifactLocation).toEqual({
      uri: "prompts/system.md",
      uriBaseId: "%SRCROOT%",
    });
    expect(run.results[0].partialFingerprints["repoguard/v1"]).toBe("abc123");
    expect(run.invocations[0].properties).toMatchObject({ suppressedInline: 1, suppressedFindings: 2 });
  });
});
