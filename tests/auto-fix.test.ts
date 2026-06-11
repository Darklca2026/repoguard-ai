import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

describe("Auto-Fix Engine", () => {
  const tempDir = path.join(__dirname, "temp-autofix");
  
  beforeEach(() => {
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir);
    }
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should auto-fix yaml.unsafe_load in a python file", () => {
    const filePath = path.join(tempDir, "vuln.py");
    fs.writeFileSync(filePath, "import yaml\nconfig = yaml.unsafe_load(file)");
    
    // Call the CLI with auto-fix
    try {
      execSync(`npx ts-node ../src/cli.ts scan "${tempDir}" --auto-fix`, { cwd: __dirname });
    } catch (e) {
      // It might exit 1 if there are other findings, but we just want to see if it fixed it.
    }

    const fixedContent = fs.readFileSync(filePath, "utf-8");
    expect(fixedContent).toBe("import yaml\nconfig = yaml.safe_load(file)");
  });

  it("should auto-fix leaked secrets by obfuscating them", () => {
    const filePath = path.join(tempDir, "keys.ts");
    fs.writeFileSync(filePath, 'const token = "ghp_123456789012345678901234567890123456";');
    
    try {
      execSync(`npx ts-node ../src/cli.ts scan "${tempDir}" --auto-fix`, { cwd: __dirname });
    } catch (e) {}

    const fixedContent = fs.readFileSync(filePath, "utf-8");
    expect(fixedContent).toBe('const token = "[SECRET_REMOVED_BY_REPOGUARD]";');
  });
});
