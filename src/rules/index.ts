import { secretsRule } from "./secrets";
import { promptInjectionRule } from "./prompt-injection";
import { githubActionsRule } from "./github-actions";
import { dangerousCodeRule } from "./dangerous-code";
import { aiGeneratedRule } from "./ai-generated";
import { aiPoisoningRule } from "./ai-poisoning";
import { RepoGuardConfig, Rule } from "../types";

export function getEnabledRules(config: RepoGuardConfig): Rule[] {
  const rules: Rule[] = [];

  if (config.rules?.secrets !== false) rules.push(secretsRule);
  if (config.rules?.promptInjection !== false) rules.push(promptInjectionRule);
  if (config.rules?.githubActions !== false) rules.push(githubActionsRule);
  if (config.rules?.dangerousCode !== false) rules.push(dangerousCodeRule);
  if (config.rules?.aiGenerated !== false) rules.push(aiGeneratedRule);
  if (config.rules?.aiPoisoning !== false) rules.push(aiPoisoningRule);

  return rules;
}
