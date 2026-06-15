export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Finding = {
  ruleId: string;
  severity: Severity;
  filePath: string;
  line?: number;
  message: string;
  snippet?: string;
  fix?: string;
  fingerprint?: string;
};

export type InlineSuppressionConfig = {
  enabled?: boolean;
  requireReason?: boolean;
  requireExpiry?: boolean;
  maxExpiryDays?: number;
};

export type ScanInput = {
  filePath: string;
  content: string;
  lines: string[];
};

export type Rule = {
  id: string;
  description: string;
  severity: Severity;
  fileTypes?: string[];
  scan: (input: ScanInput) => Finding[];
};

export type RepoGuardConfig = {
  ignore?: string[];
  rules?: {
    secrets?: boolean;
    promptInjection?: boolean;
    githubActions?: boolean;
    dangerousCode?: boolean;
    aiGenerated?: boolean;
    aiPoisoning?: boolean;
    agentSecurity?: boolean;
  };
  severity?: {
    failOn?: Severity;
  };
  maxFileSizeKb?: number;
  suppressions?: InlineSuppressionConfig;
};

export type ScanDiagnostic = {
  filePath: string;
  reason: string;
};

export type ScanStats = {
  filesDiscovered: number;
  filesScanned: number;
  skippedBinary: number;
  skippedOversized: number;
  suppressedInline: number;
  readErrors: ScanDiagnostic[];
};

export type ScanResult = {
  findings: Finding[];
  stats: ScanStats;
};
