import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG } from "../src/config";
import { secretsRule } from "../src/rules/secrets";
import { Scanner } from "../src/scanner";

const tempDirs: string[] = [];
afterEach(() =>
  tempDirs.splice(0).forEach((dir) => {
    fs.rmSync(dir, { recursive: true, force: true });
  }),
);

describe("Staged scanning", () => {
  it("scans the Git index instead of unstaged working-tree content", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-staged-"));
    tempDirs.push(tempDir);
    execFileSync("git", ["init", "-q"], { cwd: tempDir });
    const filePath = path.join(tempDir, "config.env");
    fs.writeFileSync(filePath, "OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij\n");
    execFileSync("git", ["add", "config.env"], { cwd: tempDir });
    fs.writeFileSync(filePath, "OPENAI_API_KEY=your_key_here\n");

    const result = await new Scanner(DEFAULT_CONFIG, [secretsRule]).scan(tempDir, true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe("config.env");
  });
});
