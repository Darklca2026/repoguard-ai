package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println("RepoGuard AI (Go Engine) - High Performance Security Scanner")
	
	pathPtr := flag.String("path", ".", "Path to scan")
	workersPtr := flag.Int("workers", 8, "Number of concurrent workers")
	autoFixPtr := flag.Bool("autofix", false, "Automatically fix vulnerabilities where possible")
	installHookPtr := flag.Bool("install-hook", false, "Install pre-commit guardrail hook in .git")
	flag.Parse()

	targetPath := *pathPtr
	workers := *workersPtr
	autoFix := *autoFixPtr
	installHook := *installHookPtr

	if installHook {
		installPreCommitHook(targetPath)
		os.Exit(0)
	}

	fmt.Printf("🚀 Starting scan on '%s' with %d workers...\n\n", targetPath, workers)
	
	startTime := time.Now()

	scanner := Scanner{
		Rules:       getRules(),
		MaxFileSize: 1024 * 1024, // 1MB
		AutoFix:     autoFix,
	}

	findings, err := scanner.Run(targetPath, workers)
	if err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)

	for _, f := range findings {
		color := "\033[33m" // Yellow for MEDIUM
		if f.Severity == "CRITICAL" {
			color = "\033[31m" // Red
		} else if f.Severity == "HIGH" {
			color = "\033[35m" // Magenta
		}
		reset := "\033[0m"

		fmt.Printf("%s[%s] %s%s\n", color, f.Severity, f.Message, reset)
		fmt.Printf("  File: %s:%d\n", f.FilePath, f.Line)
		fmt.Printf("  Rule: %s\n", f.RuleID)
		fmt.Printf("  Code: %s\n\n", f.Snippet)
	}

	fmt.Printf("✅ Scan completed in %v\n", duration)
	fmt.Printf("🔍 Total vulnerabilities found: %d\n", len(findings))
	
	if len(findings) > 0 {
		os.Exit(1)
	}
}

func installPreCommitHook(repoPath string) {
	hookPath := repoPath + "/.git/hooks/pre-commit"
	
	// Create directory if it doesn't exist
	os.MkdirAll(repoPath+"/.git/hooks", 0755)

	script := `#!/bin/sh
echo "[RepoGuard] Scanning code before commit..."
./repoguard-go/repoguard.exe -path .
if [ $? -ne 0 ]; then
	echo "[RepoGuard] ❌ Commit BLOCKED! Vulnerabilities found."
	echo "Run './repoguard-go/repoguard.exe -autofix' to automatically resolve them."
	exit 1
fi
echo "[RepoGuard] ✅ Code is safe. Committing..."
`
	err := os.WriteFile(hookPath, []byte(script), 0755)
	if err != nil {
		fmt.Printf("❌ Failed to install Pre-commit Hook: %v\n", err)
		return
	}
	fmt.Println("🛡️ Pre-commit Guardrail successfully installed!")
	fmt.Println("No developer will be able to commit insecure code to this repository.")
}
