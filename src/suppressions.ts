import type { Finding, InlineSuppressionConfig } from "./types";

type Directive = {
  line: number;
  targetLine: number;
  rulePattern: string;
  reason?: string;
  owner?: string;
  expires?: string;
  error?: string;
};

export function applyInlineSuppressions(
  findings: Finding[],
  lines: string[],
  filePath: string,
  config: InlineSuppressionConfig = {},
  now = new Date(),
): { findings: Finding[]; suppressed: number } {
  if (config.enabled === false) return { findings, suppressed: 0 };

  const directives = lines
    .map((line, index) => parseDirective(line, index + 1, config, now))
    .filter((directive): directive is Directive => Boolean(directive));
  if (directives.length === 0) return { findings, suppressed: 0 };

  const policyFindings = directives
    .filter((directive): directive is Directive & { error: string } => Boolean(directive.error))
    .map((directive) => ({
      ruleId: "policy.invalid_suppression",
      severity: "MEDIUM" as const,
      filePath,
      line: directive.line,
      message: directive.error,
      snippet: lines[directive.line - 1]?.trim().slice(0, 160),
      fix: "Use a justified suppression with valid metadata, or remove the directive and fix the underlying finding.",
    }));

  const validDirectives = directives.filter((directive) => !directive.error);
  const kept = findings.filter(
    (finding) =>
      !validDirectives.some(
        (directive) =>
          directive.targetLine === (finding.line ?? 1) && matchesRule(directive.rulePattern, finding.ruleId),
      ),
  );

  return {
    findings: [...kept, ...policyFindings],
    suppressed: findings.length - kept.length,
  };
}

function parseDirective(
  source: string,
  line: number,
  config: InlineSuppressionConfig,
  now: Date,
): Directive | undefined {
  const match = source.match(
    /^\s*(?:(?:\/\/|#|;|--|\/\*+|\*|<!--)\s*)repoguard-ignore(?<next>-next-line)?\s+(?<rule>[A-Za-z0-9*_.-]+)(?<rest>.*)$/i,
  );
  if (!match?.groups) return undefined;

  const rest = match.groups.rest.trim();
  const reasonMatch = rest.match(/--\s*([^;]+)/);
  const ownerMatch = rest.match(/(?:^|;)\s*owner=([^;\s]+)/i);
  const expiryMatch = rest.match(/(?:^|;)\s*expires=(\d{4}-\d{2}-\d{2})(?:;|\s|$)/i);
  const directive: Directive = {
    line,
    targetLine: match.groups.next ? line + 1 : line,
    rulePattern: match.groups.rule,
    reason: reasonMatch?.[1].trim(),
    owner: ownerMatch?.[1],
    expires: expiryMatch?.[1],
  };

  if (config.requireReason !== false && !directive.reason) {
    directive.error = "RepoGuard suppression is missing a reason after `--`.";
    return directive;
  }
  if (config.requireExpiry && !directive.expires) {
    directive.error = "RepoGuard suppression is missing required `expires=YYYY-MM-DD` metadata.";
    return directive;
  }
  if (directive.expires) {
    const expiry = parseExpiry(directive.expires);
    if (!expiry) {
      directive.error = `RepoGuard suppression has an invalid expiry date: ${directive.expires}.`;
      return directive;
    }
    if (expiry.getTime() < startOfUtcDay(now).getTime()) {
      directive.error = `RepoGuard suppression expired on ${directive.expires}.`;
      return directive;
    }
    const maxDays = config.maxExpiryDays ?? 365;
    const maxExpiry = startOfUtcDay(now).getTime() + maxDays * 86_400_000;
    if (expiry.getTime() > maxExpiry) {
      directive.error = `RepoGuard suppression expires more than ${maxDays} days in the future.`;
    }
  }

  return directive;
}

function matchesRule(pattern: string, ruleId: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return ruleId.startsWith(pattern.slice(0, -1));
  return pattern === ruleId;
}

function parseExpiry(value: string): Date | undefined {
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? undefined : date;
}

function startOfUtcDay(value: Date): Date {
  return new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate()));
}
