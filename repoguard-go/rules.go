package main

import (
	"regexp"
)

// Rule represents a security rule
type Rule struct {
	ID        string
	Name      string
	Severity  string
	FileTypes []string // Empty means all text-like files
	Check     func(filename string, content []byte) []Finding
}

// Finding represents a vulnerability found
type Finding struct {
	RuleID   string
	Severity string
	FilePath string
	Line     int
	Message  string
	Snippet  string
}

// Common patterns compiled at runtime for maximum performance
var (
	AwsKeyRegex       = regexp.MustCompile(`(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)
	AwsSecretRegex    = regexp.MustCompile(`(?i)(?:aws_secret|aws_access_key|aws_secret_key).*=.*['"][a-zA-Z0-9/+]{40}['"]`)
	GithubTokenRegex  = regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}`)
	SlackTokenRegex   = regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}`)
	StripeSecretRegex = regexp.MustCompile(`(?:sk_live|rk_live)_[a-zA-Z0-9]{24}`)
	Chmod777Regex     = regexp.MustCompile(`chmod\s+777`)
	ExecRegex         = regexp.MustCompile(`child_process\.exec\(`)
	EvalRegex         = regexp.MustCompile(`\beval\s*\(`)
	PromptInjRegex    = regexp.MustCompile(`(?i)ignore\s+previous\s+instructions|system\s+prompt|bypass|jailbreak`)
	YamlUnsafeRegex   = regexp.MustCompile(`yaml\.unsafe_load\(`)
	TorchLoadRegex    = regexp.MustCompile(`torch\.load\([^,)]+\)`)

	// Agentic Security (OWASP ASI 2026)
	MemoryPoisonRegex = regexp.MustCompile(`(?i)agent\.updateMemory\(.*user_input.*|vectorStore\.add\(.*req\.body.*`)
	ExcessiveAgency   = regexp.MustCompile(`(?i)agent\.execute\(.*delete.*|agent\.grantAccess\(.*\*\.*`)
)

func getRules() []Rule {
	return []Rule{
		{
			ID:       "secret.aws_key",
			Severity: "CRITICAL",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(AwsKeyRegex, "secret.aws_key", "AWS Access Key leaked", "CRITICAL", filename, content)
			},
		},
		{
			ID:       "secret.github_token",
			Severity: "CRITICAL",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(GithubTokenRegex, "secret.github_token", "GitHub PAT leaked", "CRITICAL", filename, content)
			},
		},
		{
			ID:       "code.chmod_777",
			Severity: "HIGH",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(Chmod777Regex, "code.chmod_777", "Insecure file permissions", "HIGH", filename, content)
			},
		},
		{
			ID:       "prompt.injection",
			Severity: "HIGH",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(PromptInjRegex, "prompt.injection", "Possible prompt injection detected", "HIGH", filename, content)
			},
		},
		{
			ID:       "ai.yaml_poisoning",
			Severity: "CRITICAL",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(YamlUnsafeRegex, "ai.yaml_poisoning", "Unsafe YAML deserialization (Arbitrary Code Execution)", "CRITICAL", filename, content)
			},
		},
		{
			ID:       "ai.torch_poisoning",
			Severity: "HIGH",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(TorchLoadRegex, "ai.torch_poisoning", "Unsafe PyTorch weights loading", "HIGH", filename, content)
			},
		},
		{
			ID:       "asi.memory_poisoning",
			Severity: "CRITICAL",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(MemoryPoisonRegex, "asi.memory_poisoning", "Agent Memory Poisoning vector detected (Unsanitized Input)", "CRITICAL", filename, content)
			},
		},
		{
			ID:       "asi.excessive_agency",
			Severity: "CRITICAL",
			Check: func(filename string, content []byte) []Finding {
				return regexRuleCheck(ExcessiveAgency, "asi.excessive_agency", "Agent Excessive Agency: Unrestricted Tool Access", "CRITICAL", filename, content)
			},
		},
	}
}

func regexRuleCheck(r *regexp.Regexp, ruleId, message, severity, filename string, content []byte) []Finding {
	var findings []Finding
	matches := r.FindAllIndex(content, -1)
	if len(matches) > 0 {
		for _, match := range matches {
			start := match[0]
			end := match[1]
			
			// Calculate line number by counting newlines before the match
			line := 1
			for i := 0; i < start; i++ {
				if content[i] == '\n' {
					line++
				}
			}

			// Extract snippet safely
			snippet := string(content[start:end])
			if len(snippet) > 6 && (severity == "CRITICAL" || severity == "HIGH") {
				// Obfuscate secret snippet
				if ruleId != "prompt.injection" && ruleId != "code.chmod_777" {
					snippet = snippet[0:6] + "************************"
				}
			}

			findings = append(findings, Finding{
				RuleID:   ruleId,
				Severity: severity,
				FilePath: filename,
				Line:     line,
				Message:  message,
				Snippet:  snippet,
			})
		}
	}
	return findings
}
