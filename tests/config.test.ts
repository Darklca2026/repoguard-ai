import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_CONFIG, loadConfig } from "../src/config";

const tempDirs: string[] = [];
afterEach(() =>
  tempDirs.splice(0).forEach((dir) => {
    fs.rmSync(dir, { recursive: true, force: true });
  }),
);

describe("Configuration", () => {
  it("keeps safe default ignores when custom ignores are added", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-config-"));
    tempDirs.push(tempDir);
    const configPath = path.join(tempDir, "repoguard.config.yml");
    fs.writeFileSync(configPath, "ignore:\n  - docs/**\n");

    const config = loadConfig(configPath);
    expect(config.ignore).toContain("node_modules/**");
    expect(config.ignore).toContain(".git/**");
    expect(config.ignore).toContain("docs/**");
    expect(config.ignore).toHaveLength((DEFAULT_CONFIG.ignore?.length ?? 0) + 1);
  });

  it("rejects unknown configuration keys", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-config-"));
    tempDirs.push(tempDir);
    const configPath = path.join(tempDir, "repoguard.config.yml");
    fs.writeFileSync(configPath, "failOpen: true\n");
    expect(() => loadConfig(configPath)).toThrow("Invalid configuration file");
  });
});
