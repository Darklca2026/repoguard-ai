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

    // Processar em chunks de 50 para não estourar os File Descriptors do S.O.
    const CHUNK_SIZE = 50;
    for (let i = 0; i < files.length; i += CHUNK_SIZE) {
      const chunk = files.slice(i, i + CHUNK_SIZE);
      
      await Promise.all(chunk.map(async (filePath) => {
        try {
          const fileBuffer = await fs.promises.readFile(filePath);
          if (FileLoader.isBinary(fileBuffer)) {
            return; // Skip binary files
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
      }));
    }

    return { filesScanned, findings };
  }
}
