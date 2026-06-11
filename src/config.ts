import { z } from "zod";
import * as fs from "fs";
import * as yaml from "js-yaml";
import { RepoGuardConfig } from "./types";

const severitySchema = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);

const configSchema = z.object({
  ignore: z.array(z.string()).optional(),
  rules: z
    .object({
      secrets: z.boolean().optional(),
      promptInjection: z.boolean().optional(),
      githubActions: z.boolean().optional(),
      dangerousCode: z.boolean().optional(),
      aiGenerated: z.boolean().optional(),
    })
    .optional(),
  severity: z
    .object({
      failOn: severitySchema.optional(),
    })
    .optional(),
  maxFileSizeKb: z.number().optional(),
});

export const DEFAULT_CONFIG: RepoGuardConfig = {
  ignore: ["node_modules/**", "dist/**", "build/**", ".git/**", "coverage/**"],
  rules: {
    secrets: true,
    promptInjection: true,
    githubActions: true,
    dangerousCode: true,
    aiGenerated: true,
  },
  severity: {
    failOn: "HIGH",
  },
  maxFileSizeKb: 1024,
};

export function loadConfig(configPath?: string): RepoGuardConfig {
  let config = { ...DEFAULT_CONFIG };

  if (configPath && fs.existsSync(configPath)) {
    try {
      const fileContent = fs.readFileSync(configPath, "utf8");
      let parsedYaml = yaml.load(fileContent) as any;
      if (!parsedYaml) parsedYaml = {};
      
      const result = configSchema.safeParse(parsedYaml);
      if (!result.success) {
        console.error("Invalid configuration file:", result.error.message);
        process.exit(1);
      }
      
      // Merge with default config
      config = {
        ...DEFAULT_CONFIG,
        ...result.data,
        rules: {
          ...DEFAULT_CONFIG.rules,
          ...(result.data.rules || {}),
        },
        severity: {
          ...DEFAULT_CONFIG.severity,
          ...(result.data.severity || {}),
        }
      };
    } catch (e: any) {
      console.error(`Error loading config file ${configPath}:`, e.message);
      process.exit(1);
    }
  }

  return config;
}
