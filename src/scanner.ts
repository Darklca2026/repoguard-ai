import * as fs from "node:fs";
import { FileLoader } from "./file-loader";
import { applyInlineSuppressions } from "./suppressions";
import type { Finding, RepoGuardConfig, Rule, ScanResult } from "./types";
import { addFingerprints, sortAndDedupeFindings } from "./utils/findings";

export class Scanner {
  private fileLoader: FileLoader;

  constructor(
    private config: RepoGuardConfig,
    private rules: Rule[],
  ) {
    this.fileLoader = new FileLoader(config);
  }

  public async scan(targetPath: string, staged = false, changedSince?: string): Promise<ScanResult> {
    const selection = staged
      ? this.fileLoader.loadStagedFiles(targetPath)
      : changedSince
        ? this.fileLoader.loadChangedFiles(targetPath, changedSince)
        : await this.fileLoader.loadFiles(targetPath);
    const files = selection.files;
    const findings: Finding[] = [];
    let filesScanned = 0;
    let skippedBinary = 0;
    let suppressedInline = 0;
    const readErrors: { filePath: string; reason: string }[] = [];

    // Processar em chunks de 50 para não estourar os File Descriptors do S.O.
    const CHUNK_SIZE = 50;
    for (let i = 0; i < files.length; i += CHUNK_SIZE) {
      const chunk = files.slice(i, i + CHUNK_SIZE);

      await Promise.all(
        chunk.map(async (file) => {
          try {
            const fileBuffer = file.content ?? (await fs.promises.readFile(file.absolutePath));
            if (FileLoader.isBinary(fileBuffer)) {
              skippedBinary++;
              return; // Skip binary files
            }

            const content = fileBuffer.toString("utf-8");
            const lines = content.split(/\r?\n/);

            const input = {
              filePath: file.filePath,
              content,
              lines,
            };

            const fileFindings: Finding[] = [];
            for (const rule of this.rules) {
              if (rule.fileTypes && rule.fileTypes.length > 0) {
                const ext = file.filePath.split(".").pop() || "";
                const matchesExt = rule.fileTypes.some(
                  (t) => file.filePath.endsWith(t) || ext === t || `.${ext}` === t,
                );
                if (!matchesExt) continue;
              }

              const ruleFindings = rule.scan(input);
              fileFindings.push(...ruleFindings);
            }

            const suppressionResult = applyInlineSuppressions(
              fileFindings,
              lines,
              file.filePath,
              this.config.suppressions,
            );
            suppressedInline += suppressionResult.suppressed;
            findings.push(...suppressionResult.findings);

            filesScanned++;
          } catch (error) {
            readErrors.push({
              filePath: file.filePath,
              reason: error instanceof Error ? error.message : String(error),
            });
          }
        }),
      );
    }

    const normalizedFindings = addFingerprints(sortAndDedupeFindings(findings));
    return {
      findings: normalizedFindings,
      stats: {
        filesDiscovered: files.length + selection.skippedOversized,
        filesScanned,
        skippedBinary,
        skippedOversized: selection.skippedOversized,
        suppressedInline,
        readErrors: readErrors.sort((a, b) => a.filePath.localeCompare(b.filePath)),
      },
    };
  }
}
