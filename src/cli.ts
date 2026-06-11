#!/usr/bin/env node
import { Command } from "commander";
import { loadConfig } from "./config";
import { Scanner } from "./scanner";
import { getEnabledRules } from "./rules";
import { printTerminalReport, printJsonReport } from "./report";
import { calculateRiskScore } from "./risk-score";
import { Severity } from "./types";
import pc from "picocolors";

const program = new Command();

program
  .name("repoguard-ai")
  .description("Security scanner for AI-assisted repositories.")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a directory for security risks")
  .argument("<path>", "Path to the directory to scan")
  .option("--json", "Output report in JSON format")
  .option("-c, --config <path>", "Path to custom config file (YAML)")
  .option("--fail-on <severity>", "Fail with exit code 1 if risk score meets or exceeds this severity (LOW, MEDIUM, HIGH, CRITICAL)")
  .action(async (targetPath: string, options: { json?: boolean; config?: string; failOn?: string }) => {
    try {
      const config = loadConfig(options.config);
      
      if (options.failOn) {
        const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        if (severities.includes(options.failOn.toUpperCase())) {
          if (!config.severity) config.severity = {};
          config.severity.failOn = options.failOn.toUpperCase() as Severity;
        } else {
          console.error(pc.red(`Invalid severity for --fail-on: ${options.failOn}`));
          process.exit(1);
        }
      }

      const rules = getEnabledRules(config);
      const scanner = new Scanner(config, rules);

      const { filesScanned, findings } = await scanner.scan(targetPath);
      const riskScore = calculateRiskScore(findings);

      if (options.json) {
        printJsonReport(findings, filesScanned, riskScore);
      } else {
        printTerminalReport(findings, filesScanned, riskScore);
      }

      const severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const failOnScore = config.severity?.failOn || "HIGH";
      const currentScoreIndex = severities.indexOf(riskScore);
      const failOnScoreIndex = severities.indexOf(failOnScore);

      if (findings.length > 0 && currentScoreIndex >= failOnScoreIndex) {
        if (!options.json) {
          console.error(pc.red(`\nScan failed. Risk score ${riskScore} meets or exceeds the failOn threshold of ${failOnScore}.`));
        }
        process.exit(1);
      } else {
        process.exit(0);
      }

    } catch (error: any) {
      console.error(pc.red(`Error during scan: ${error.message}`));
      process.exit(1);
    }
  });

program.parse();
