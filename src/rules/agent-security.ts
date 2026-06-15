import * as path from "node:path";
import * as yaml from "js-yaml";
import type { Finding, Rule, Severity } from "../types";

const INSTRUCTION_FILES = new Set([
  "agents.md",
  "claude.md",
  "gemini.md",
  "skill.md",
  "copilot-instructions.md",
  ".agent.md",
  ".system.md",
]);

const EXCESSIVE_AGENCY_PATTERNS = [
  /(?:never|do not)\s+ask\s+(?:for\s+)?(?:confirmation|approval)/i,
  /(?:run|execute)\s+(?:any|all)\s+commands?/i,
  /(?:unrestricted|full)\s+(?:filesystem|shell|network|tool)\s+access/i,
  /always\s+(?:approve|allow|execute)/i,
];

export const agentSecurityRule: Rule = {
  id: "agent-security",
  description: "Detects risky AI agent and MCP configuration",
  severity: "HIGH",
  scan: (input) => {
    const normalizedPath = input.filePath.replace(/\\/g, "/");
    const basename = path.basename(normalizedPath).toLowerCase();
    const findings: Finding[] = [];

    if (isMcpConfig(normalizedPath, basename)) {
      findings.push(...scanMcpConfig(input.filePath, input.content, input.lines));
    }

    if (isInstructionFile(normalizedPath, basename)) {
      input.lines.forEach((line, index) => {
        if (EXCESSIVE_AGENCY_PATTERNS.some((pattern) => pattern.test(line))) {
          findings.push({
            ruleId: "agent.excessive_agency_instruction",
            severity: "HIGH",
            filePath: input.filePath,
            line: index + 1,
            message: "Agent instruction appears to remove human approval or capability boundaries.",
            snippet: line.trim().slice(0, 120),
            fix: "Require confirmation for destructive or privileged actions and restrict tools to the minimum capability needed.",
          });
        }
      });
    }

    return findings;
  },
};

function scanMcpConfig(filePath: string, content: string, lines: string[]): Finding[] {
  let parsed: unknown;
  try {
    parsed = yaml.load(content);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];

  const root = parsed as Record<string, unknown>;
  const servers = asRecord(root.mcpServers) ?? asRecord(root.servers);
  if (!servers) return [];

  const findings: Finding[] = [];
  for (const [serverName, rawServer] of Object.entries(servers)) {
    const server = asRecord(rawServer);
    if (!server) continue;
    const command = typeof server.command === "string" ? server.command : "";
    const args = Array.isArray(server.args)
      ? server.args.filter((arg): arg is string => typeof arg === "string")
      : [];
    const combined = [command, ...args].join(" ");
    const line = findLine(lines, serverName);

    if (
      /^(?:ba)?sh$|^cmd(?:\.exe)?$|^powershell(?:\.exe)?$|^pwsh$/i.test(path.basename(command)) &&
      args.some((arg) => /^(?:-c|\/c|-command)$/i.test(arg))
    ) {
      findings.push(
        mcpFinding(
          "mcp.shell_command",
          "HIGH",
          filePath,
          line,
          `MCP server "${serverName}" executes through a command shell.`,
          combined,
          "Invoke a fixed executable directly and pass validated arguments without a shell.",
        ),
      );
    }

    if (/\b(?:--allow-all|--dangerously-allow-all|--no-auth|--disable-auth|--yolo)\b/i.test(combined)) {
      findings.push(
        mcpFinding(
          "mcp.unsafe_capability_flag",
          "CRITICAL",
          filePath,
          line,
          `MCP server "${serverName}" disables authorization or capability boundaries.`,
          combined,
          "Remove unrestricted flags and configure an explicit allowlist with least privilege.",
        ),
      );
    }

    if (/^(?:npx|bunx|pnpx)$/i.test(path.basename(command))) {
      const packageArg = args.find((arg) => !arg.startsWith("-"));
      if (packageArg && !hasExactPackageVersion(packageArg)) {
        findings.push(
          mcpFinding(
            "mcp.unpinned_package",
            "MEDIUM",
            filePath,
            line,
            `MCP server "${serverName}" downloads an unpinned package at runtime.`,
            packageArg,
            "Pin the MCP package to an exact reviewed version or install it from a lockfile.",
          ),
        );
      }
    }

    if (/^uvx$/i.test(path.basename(command))) {
      const packageArg = args.find((arg) => !arg.startsWith("-"));
      if (packageArg && !/^[A-Za-z0-9_.-]+==\d+\.\d+\.\d+(?:[A-Za-z0-9_.+-]*)$/.test(packageArg)) {
        findings.push(
          mcpFinding(
            "mcp.unpinned_package",
            "MEDIUM",
            filePath,
            line,
            `MCP server "${serverName}" downloads an unpinned Python package at runtime.`,
            packageArg,
            "Pin the MCP package with an exact package==version requirement.",
          ),
        );
      }
    }

    if (/^docker$/i.test(path.basename(command))) {
      const image = findContainerImage(args);
      if (image && !isPinnedContainerImage(image)) {
        findings.push(
          mcpFinding(
            "mcp.unpinned_container",
            "MEDIUM",
            filePath,
            line,
            `MCP server "${serverName}" runs a container image without an immutable digest.`,
            image,
            "Pin the reviewed container image by sha256 digest instead of a mutable tag.",
          ),
        );
      }
    }

    if (/^(?:\/tmp\/|\/var\/tmp\/|[A-Za-z]:[\\/]Temp[\\/])/i.test(command)) {
      findings.push(
        mcpFinding(
          "mcp.temporary_executable",
          "HIGH",
          filePath,
          line,
          `MCP server "${serverName}" executes a program from a temporary directory.`,
          command,
          "Install the server in a controlled, integrity-checked location that is not writable by untrusted users.",
        ),
      );
    }

    if (/filesystem/i.test(combined) && args.some((arg) => arg === "/" || /^[A-Za-z]:[\\/]?$/.test(arg))) {
      findings.push(
        mcpFinding(
          "mcp.unrestricted_filesystem_root",
          "HIGH",
          filePath,
          line,
          `MCP server "${serverName}" grants access to an entire filesystem root.`,
          combined,
          "Restrict the server to the smallest project directories required for the task.",
        ),
      );
    }

    const url =
      typeof server.url === "string"
        ? server.url
        : typeof server.endpoint === "string"
          ? server.endpoint
          : undefined;
    if (
      url &&
      /^http:\/\//i.test(url) &&
      !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)
    ) {
      findings.push(
        mcpFinding(
          "mcp.insecure_transport",
          "HIGH",
          filePath,
          line,
          `MCP server "${serverName}" uses unencrypted HTTP transport.`,
          url,
          "Use HTTPS and validate the remote server identity.",
        ),
      );
    }

    const env = asRecord(server.env);
    if (env) {
      for (const [name, value] of Object.entries(env)) {
        if (!/(?:token|secret|password|passwd|api[_-]?key|credential)/i.test(name)) continue;
        if (typeof value !== "string" || isEnvironmentReference(value)) continue;
        findings.push(
          mcpFinding(
            "mcp.inline_credential",
            "CRITICAL",
            filePath,
            findLine(lines, name),
            `MCP server "${serverName}" embeds a credential in its configuration.`,
            `${name}=<redacted>`,
            "Load credentials from a protected environment or secret manager and rotate the exposed value.",
          ),
        );
      }
    }

    const headers = asRecord(server.headers);
    if (headers) {
      for (const [name, value] of Object.entries(headers)) {
        if (typeof value !== "string" || isEnvironmentReference(value)) continue;
        if (!/(?:authorization|token|secret|api[_-]?key|credential)/i.test(name)) continue;
        findings.push(
          mcpFinding(
            "mcp.inline_credential",
            "CRITICAL",
            filePath,
            findLine(lines, name),
            `MCP server "${serverName}" embeds a credential in an HTTP header.`,
            `${name}: <redacted>`,
            "Load credentials from a protected environment or secret manager and rotate the exposed value.",
          ),
        );
      }
    }
  }
  return findings;
}

function isMcpConfig(filePath: string, basename: string): boolean {
  return (
    basename === ".mcp.json" ||
    basename === "mcp.json" ||
    basename === "mcp.yaml" ||
    basename === "mcp.yml" ||
    /(?:^|\/)\.cursor\/mcp\.json$/i.test(filePath)
  );
}

function isInstructionFile(filePath: string, basename: string): boolean {
  return (
    INSTRUCTION_FILES.has(basename) ||
    filePath.includes("/.claude/") ||
    filePath.includes("/.cursor/rules/") ||
    filePath.startsWith(".claude/") ||
    filePath.startsWith(".cursor/rules/")
  );
}

function hasExactPackageVersion(packageName: string): boolean {
  const match = packageName.match(/^(?:@[^/]+\/[^@]+|[^@]+)@(.+)$/);
  return Boolean(match && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(match[1]));
}

function findContainerImage(args: string[]): string | undefined {
  const runIndex = args.indexOf("run");
  if (runIndex < 0) return undefined;
  for (let index = runIndex + 1; index < args.length; index++) {
    const arg = args[index];
    if (arg.startsWith("-")) {
      if (["-v", "--volume", "-e", "--env", "--name", "--user", "-w", "--workdir"].includes(arg)) index++;
      continue;
    }
    return arg;
  }
  return undefined;
}

function isPinnedContainerImage(image: string): boolean {
  return /@sha256:[a-f0-9]{64}$/i.test(image);
}

function isEnvironmentReference(value: string): boolean {
  return (
    /^\$(?:[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})$/i.test(value) ||
    /^\{\{\s*(?:env|secrets)\./i.test(value) ||
    /^env:/i.test(value)
  );
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function findLine(lines: string[], value: string): number {
  const index = lines.findIndex((line) => line.includes(value));
  return index >= 0 ? index + 1 : 1;
}

function mcpFinding(
  ruleId: string,
  severity: Severity,
  filePath: string,
  line: number,
  message: string,
  snippet: string,
  fix: string,
): Finding {
  return { ruleId, severity, filePath, line, message, snippet: snippet.slice(0, 120), fix };
}
