export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Finding = {
  ruleId: string;
  severity: Severity;
  filePath: string;
  line?: number;
  message: string;
  snippet?: string;
  fix?: string;
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
  };
  severity?: {
    failOn?: Severity;
  };
  maxFileSizeKb?: number;
};
