import * as fs from "node:fs";
import * as yaml from "js-yaml";
import { z } from "zod";
import type { RepoGuardConfig } from "./types";

const severitySchema = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

const configSchema = z
  .object({
    ignore: z.array(z.string()).optional(),
    rules: z
      .object({
        secrets: z.boolean().optional(),
        promptInjection: z.boolean().optional(),
        githubActions: z.boolean().optional(),
        dangerousCode: z.boolean().optional(),
        aiGenerated: z.boolean().optional(),
        aiPoisoning: z.boolean().optional(),
        agentSecurity: z.boolean().optional(),
      })
      .optional(),
    severity: z
      .object({
        failOn: severitySchema.optional(),
      })
      .optional(),
    maxFileSizeKb: z.number().int().positive().max(102400).optional(),
    suppressions: z
      .object({
        enabled: z.boolean().optional(),
        requireReason: z.boolean().optional(),
        requireExpiry: z.boolean().optional(),
        maxExpiryDays: z.number().int().positive().max(3650).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export const DEFAULT_CONFIG: RepoGuardConfig = {
  ignore: ["node_modules/**", "dist/**", "build/**", ".git/**", "coverage/**", ".env.canary"],
  rules: {
    secrets: true,
    promptInjection: true,
    githubActions: true,
    dangerousCode: true,
    aiGenerated: true,
    aiPoisoning: true,
    agentSecurity: true,
  },
  severity: {
    failOn: "HIGH",
  },
  maxFileSizeKb: 1024,
  suppressions: {
    enabled: true,
    requireReason: true,
    requireExpiry: false,
    maxExpiryDays: 365,
  },
};

export function loadConfig(configPath?: string): RepoGuardConfig {
  let config = { ...DEFAULT_CONFIG };

  if (configPath && !fs.existsSync(configPath)) {
    throw new Error(`Configuration file not found: ${configPath}`);
  }

  if (configPath) {
    try {
      const fileContent = fs.readFileSync(configPath, "utf8");
      let parsedYaml: unknown = yaml.load(fileContent);
      if (!parsedYaml) parsedYaml = {};

      const result = configSchema.safeParse(parsedYaml);
      if (!result.success) {
        throw new Error(`Invalid configuration file: ${result.error.message}`);
      }

      // Merge with default config
      config = {
        ...DEFAULT_CONFIG,
        ...result.data,
        ignore: [...new Set([...(DEFAULT_CONFIG.ignore ?? []), ...(result.data.ignore ?? [])])],
        rules: {
          ...DEFAULT_CONFIG.rules,
          ...(result.data.rules || {}),
        },
        severity: {
          ...DEFAULT_CONFIG.severity,
          ...(result.data.severity || {}),
        },
        suppressions: {
          ...DEFAULT_CONFIG.suppressions,
          ...(result.data.suppressions || {}),
        },
      };
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(`Error loading config file ${configPath}: ${message}`);
    }
  }

  return config;
}
