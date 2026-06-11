import { Rule } from "../types";
import { secretsRule } from "./secrets";
import { promptInjectionRule } from "./prompt-injection";
import { githubActionsRule } from "./github-actions";
import { dangerousCodeRule } from "./dangerous-code";
import { aiGeneratedRule } from "./ai-generated";
import { RepoGuardConfig } from "../types";

export function getEnabledRules(config: RepoGuardConfig): Rule[] {
  const rules: Rule[] = [];
  
  if (config.rules?.secrets) {
    rules.push(secretsRule);
  }
  if (config.rules?.promptInjection) {
    rules.push(promptInjectionRule);
  }
  if (config.rules?.githubActions) {
    rules.push(githubActionsRule);
  }
  if (config.rules?.dangerousCode) {
    rules.push(dangerousCodeRule);
  }
  if (config.rules?.aiGenerated) {
    rules.push(aiGeneratedRule);
  }

  return rules;
}
