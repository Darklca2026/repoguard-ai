import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import glob from "fast-glob";
import ignore, { type Ignore } from "ignore";
import type { RepoGuardConfig } from "./types";

export type FileCandidate = {
  absolutePath: string;
  filePath: string;
  content?: Buffer;
};

export type FileSelection = {
  rootPath: string;
  files: FileCandidate[];
  skippedOversized: number;
};

export class FileLoader {
  private ig: Ignore;
  private maxSizeBytes: number;

  constructor(private config: RepoGuardConfig) {
    this.ig = ignore();

    // Padrões Globais que devem ser ignorados por padrão (Arquivos de lock que contêm hashes Base64/Hex)
    this.ig.add(["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]);

    if (this.config.ignore) {
      this.ig.add(this.config.ignore);
    }
    this.maxSizeBytes = (this.config.maxFileSizeKb || 1024) * 1024;
  }

  public async loadFiles(targetPath: string): Promise<FileSelection> {
    const absoluteTarget = path.resolve(targetPath);
    const stat = fs.statSync(absoluteTarget);
    const rootPath = stat.isFile() ? path.dirname(absoluteTarget) : absoluteTarget;

    if (stat.isFile()) {
      if (stat.size > this.maxSizeBytes) {
        return { rootPath, files: [], skippedOversized: 1 };
      }
      return {
        rootPath,
        files: [{ absolutePath: absoluteTarget, filePath: path.basename(absoluteTarget) }],
        skippedOversized: 0,
      };
    }

    this.addGitignore(rootPath);

    const files = await glob("**/*", {
      cwd: rootPath,
      dot: true,
      onlyFiles: true,
      absolute: true,
      followSymbolicLinks: false,
    });

    let skippedOversized = 0;
    const selected = files
      .sort()
      .filter((file) => {
        const relativePath = this.normalizePath(path.relative(rootPath, file));

        if (this.ig.ignores(relativePath)) return false;

        try {
          if (fs.statSync(file).size > this.maxSizeBytes) {
            skippedOversized++;
            return false;
          }
        } catch {
          return false;
        }

        return true;
      })
      .map((absolutePath) => ({
        absolutePath,
        filePath: this.normalizePath(path.relative(rootPath, absolutePath)),
      }));

    return { rootPath, files: selected, skippedOversized };
  }

  public loadStagedFiles(targetPath: string): FileSelection {
    const cwd = fs.statSync(path.resolve(targetPath)).isDirectory()
      ? path.resolve(targetPath)
      : path.dirname(path.resolve(targetPath));
    const rootPath = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf8",
    }).trim();

    this.addGitignore(rootPath);
    const output = execFileSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], {
      cwd: rootPath,
      encoding: "buffer",
    });
    const stagedPaths = output.toString("utf8").split("\0").filter(Boolean).sort();
    let skippedOversized = 0;
    const files: FileCandidate[] = [];

    for (const gitPath of stagedPaths) {
      const normalizedPath = this.normalizePath(gitPath);
      if (this.ig.ignores(normalizedPath)) continue;

      const size = Number(
        execFileSync("git", ["cat-file", "-s", `:${gitPath}`], {
          cwd: rootPath,
          encoding: "utf8",
        }).trim(),
      );
      if (size > this.maxSizeBytes) {
        skippedOversized++;
        continue;
      }

      const content = execFileSync("git", ["show", `:${gitPath}`], {
        cwd: rootPath,
        encoding: "buffer",
        maxBuffer: this.maxSizeBytes + 1024,
      });
      files.push({
        absolutePath: path.join(rootPath, gitPath),
        filePath: normalizedPath,
        content,
      });
    }

    return { rootPath, files, skippedOversized };
  }

  public loadChangedFiles(targetPath: string, baseRef: string): FileSelection {
    const cwd = fs.statSync(path.resolve(targetPath)).isDirectory()
      ? path.resolve(targetPath)
      : path.dirname(path.resolve(targetPath));
    const rootPath = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf8",
    }).trim();
    execFileSync("git", ["rev-parse", "--verify", `${baseRef}^{commit}`], { cwd: rootPath, stdio: "ignore" });

    this.addGitignore(rootPath);
    const output = execFileSync(
      "git",
      ["diff", "--name-only", "--diff-filter=ACMR", "-z", `${baseRef}...HEAD`],
      { cwd: rootPath, encoding: "buffer" },
    );
    const changedPaths = output.toString("utf8").split("\0").filter(Boolean).sort();
    return this.loadGitBlobs(rootPath, changedPaths, "HEAD");
  }

  private addGitignore(rootPath: string): void {
    const gitignorePath = path.join(rootPath, ".gitignore");
    if (fs.existsSync(gitignorePath)) {
      const gitignoreContent = fs.readFileSync(gitignorePath, "utf-8");
      this.ig.add(gitignoreContent);
    }
    if (this.config.ignore) this.ig.add(this.config.ignore);
  }

  private loadGitBlobs(rootPath: string, gitPaths: string[], revision: string): FileSelection {
    let skippedOversized = 0;
    const files: FileCandidate[] = [];
    for (const gitPath of gitPaths) {
      const normalizedPath = this.normalizePath(gitPath);
      if (this.ig.ignores(normalizedPath)) continue;
      const object = `${revision}:${gitPath}`;
      const size = Number(
        execFileSync("git", ["cat-file", "-s", object], {
          cwd: rootPath,
          encoding: "utf8",
        }).trim(),
      );
      if (size > this.maxSizeBytes) {
        skippedOversized++;
        continue;
      }
      const content = execFileSync("git", ["show", object], {
        cwd: rootPath,
        encoding: "buffer",
        maxBuffer: this.maxSizeBytes + 1024,
      });
      files.push({
        absolutePath: path.join(rootPath, gitPath),
        filePath: normalizedPath,
        content,
      });
    }
    return { rootPath, files, skippedOversized };
  }

  private normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, "/");
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
