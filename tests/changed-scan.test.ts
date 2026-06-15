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

describe("Changed-since scanning", () => {
  it("scans committed HEAD blobs changed since the base revision", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-changed-"));
    tempDirs.push(tempDir);
    execFileSync("git", ["init", "-q"], { cwd: tempDir });
    execFileSync("git", ["config", "user.name", "RepoGuard Tests"], { cwd: tempDir });
    execFileSync("git", ["config", "user.email", "tests@repoguard.invalid"], { cwd: tempDir });
    fs.writeFileSync(path.join(tempDir, "safe.env"), "OPENAI_API_KEY=your_key_here\n");
    execFileSync("git", ["add", "."], { cwd: tempDir });
    execFileSync("git", ["commit", "-qm", "base"], { cwd: tempDir });
    const base = execFileSync("git", ["rev-parse", "HEAD"], { cwd: tempDir, encoding: "utf8" }).trim();

    fs.writeFileSync(path.join(tempDir, "unsafe.env"), "OPENAI_API_KEY=sk-proj-abc1234567890abcdefghij\n");
    execFileSync("git", ["add", "."], { cwd: tempDir });
    execFileSync("git", ["commit", "-qm", "add unsafe fixture"], { cwd: tempDir });
    fs.writeFileSync(path.join(tempDir, "unsafe.env"), "OPENAI_API_KEY=your_key_here\n");

    const result = await new Scanner(DEFAULT_CONFIG, [secretsRule]).scan(tempDir, false, base);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe("unsafe.env");
  });
});
