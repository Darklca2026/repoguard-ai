import * as fs from "fs";
import { Rule, Finding, RepoGuardConfig } from "./types";
import { FileLoader } from "./file-loader";

export class Scanner {
  private fileLoader: FileLoader;

  constructor(private config: RepoGuardConfig, private rules: Rule[]) {
    this.fileLoader = new FileLoader(config);
  }

  public async scan(targetPath: string): Promise<{ filesScanned: number; findings: Finding[] }> {
    const files = await this.fileLoader.loadFiles(targetPath);
    const findings: Finding[] = [];
    let filesScanned = 0;

    for (const filePath of files) {
      try {
        const fileBuffer = fs.readFileSync(filePath);
        if (FileLoader.isBinary(fileBuffer)) {
          continue; // Skip binary files
        }

        const content = fileBuffer.toString("utf-8");
        const lines = content.split(/\r?\n/);

        const input = {
          filePath,
          content,
          lines,
        };

        for (const rule of this.rules) {
          if (rule.fileTypes && rule.fileTypes.length > 0) {
            const ext = filePath.split('.').pop() || '';
            const matchesExt = rule.fileTypes.some(t => filePath.endsWith(t) || ext === t || `.${ext}` === t);
            if (!matchesExt) continue;
          }

          const ruleFindings = rule.scan(input);
          findings.push(...ruleFindings);
        }

        filesScanned++;
      } catch (e) {
        // Skip files that cannot be read
      }
    }

    return { filesScanned, findings };
  }
}
