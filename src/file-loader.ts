import * as fs from "fs";
import * as path from "path";
import glob from "fast-glob";
import ignore, { Ignore } from "ignore";
import { RepoGuardConfig } from "./types";

export class FileLoader {
  private ig: Ignore;
  private maxSizeBytes: number;

  constructor(private config: RepoGuardConfig) {
    this.ig = ignore();
    
    // Padrões Globais que devem ser ignorados por padrão (Arquivos de lock que contêm hashes Base64/Hex)
    this.ig.add([
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
      "bun.lockb"
    ]);

    if (this.config.ignore) {
      this.ig.add(this.config.ignore);
    }
    this.maxSizeBytes = (this.config.maxFileSizeKb || 1024) * 1024;
  }

  public async loadFiles(targetPath: string): Promise<string[]> {
    const stat = fs.statSync(targetPath);

    if (stat.isFile()) {
      return [targetPath];
    }

    const gitignorePath = path.join(targetPath, ".gitignore");
    if (fs.existsSync(gitignorePath)) {
      const gitignoreContent = fs.readFileSync(gitignorePath, "utf-8");
      this.ig.add(gitignoreContent);
    }

    const files = await glob("**/*", {
      cwd: targetPath,
      dot: true,
      onlyFiles: true,
      absolute: true,
    });

    return files.filter((file) => {
      const relativePath = path.relative(targetPath, file);
      
      if (this.ig.ignores(relativePath)) {
        return false;
      }

      try {
        const fileStat = fs.statSync(file);
        if (fileStat.size > this.maxSizeBytes) {
          return false;
        }
      } catch (e) {
        return false;
      }

      return true;
    });
  }

  public static isBinary(content: Buffer): boolean {
    // A simple heuristic for binary files: checking for null bytes
    for (let i = 0; i < Math.min(8000, content.length); i++) {
      if (content[i] === 0) {
        return true;
      }
    }
    return false;
  }
}
