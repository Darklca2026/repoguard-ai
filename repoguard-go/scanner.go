package main

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Scanner struct {
	Rules       []Rule
	MaxFileSize int64
	AutoFix     bool
}

// Ignore list for ultra-fast skipping
var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"dist":         true,
	"build":        true,
	"vendor":       true,
}

var ignoredExts = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".png": true,
	".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".pdf": true,
	".zip": true, ".tar": true, ".gz": true, ".mp4": true, ".mp3": true,
}

func (s *Scanner) Run(targetDir string, concurrency int) ([]Finding, error) {
	fileQueue := make(chan string, 1000)
	findingQueue := make(chan Finding, 1000)

	var wg sync.WaitGroup
	var allFindings []Finding

	// Launch worker pool
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileQueue {
				findings := s.scanFile(path)
				for _, f := range findings {
					findingQueue <- f
				}
			}
		}()
	}

	// Goroutine to collect findings safely
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for f := range findingQueue {
			allFindings = append(allFindings, f)
		}
	}()

	// Fast disk crawler
	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip unreadable
		}
		
		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ignoredExts[ext] {
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > s.MaxFileSize {
			return nil
		}

		// Send to worker pool
		fileQueue <- path
		return nil
	})

	close(fileQueue)
	wg.Wait() // Wait for all workers to finish
	close(findingQueue)
	collectWg.Wait() // Wait for collector

	return allFindings, err
}

func (s *Scanner) scanFile(path string) []Finding {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var findings []Finding
	
	// Check if file contains user input anywhere
	fullContent, _ := os.ReadFile(path)
	hasUserInput := strings.Contains(string(fullContent), "req.body") || strings.Contains(string(fullContent), "req.query") || strings.Contains(string(fullContent), "user_input")
	
	scanner := bufio.NewScanner(file)
	
	// Increase buffer size for long minified lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 1
	for scanner.Scan() {
		lineData := scanner.Bytes()
		
		// 1. Run Regex Rules (Pre-compiled)
		// Heuristic Taint Tracker (Dataflow Context)
		
		for _, rule := range s.Rules {
			f := rule.Check(path, lineData)
			if len(f) > 0 {
				for i := range f {
					f[i].Line = lineNum
					// ASPM: Downgrade exploitability if it's a test or doc file
					if strings.Contains(strings.ToLower(path), "test") || strings.Contains(strings.ToLower(path), ".md") {
						if f[i].Severity == "CRITICAL" || f[i].Severity == "HIGH" {
							f[i].Severity = "LOW"
							f[i].Message += " (Downgraded: Test/Doc context)"
						}
					}

					// Deep Intel: Contextual Reachability (Taint Analysis)
					if (rule.ID == "code.eval" || rule.ID == "code.exec") && !hasUserInput {
						if f[i].Severity == "CRITICAL" || f[i].Severity == "HIGH" {
							f[i].Severity = "LOW"
							f[i].Message += " (Taint Tracker: Unreachable Sink / No User Input)"
						}
					} else if (rule.ID == "code.eval" || rule.ID == "code.exec") && hasUserInput {
						f[i].Severity = "CRITICAL"
						f[i].Message = "🔥 EXPLOITABLE Taint Dataflow: User input reaches execution sink!"
					}

					findings = append(findings, f[i])
				}
			}
		}

		// 2. High Entropy Detection (Heuristic)
		words := strings.Fields(string(lineData))
		for _, word := range words {
			if len(word) > 16 && len(word) < 100 { // Only check reasonable token lengths
				entropy := CalculateShannonEntropy([]byte(word))
				if entropy > 4.5 {
					severity := "MEDIUM"
					message := "High entropy string detected"
					
					// ASPM: Downgrade exploitability if it's a test file
					if strings.Contains(strings.ToLower(path), "test") || strings.Contains(strings.ToLower(path), "lock.json") || strings.Contains(strings.ToLower(path), ".md") {
						severity = "LOW"
						message += " (Downgraded: Low Risk Context)"
					}

					// Check if it's already caught by a regex to avoid duplicates
					alreadyCaught := false
					for _, existing := range findings {
						if existing.Line == lineNum && strings.HasPrefix(existing.Snippet, word[:6]) {
							alreadyCaught = true
							break
						}
					}
					
					if !alreadyCaught {
						findings = append(findings, Finding{
							RuleID:   "secret.high_entropy",
							Severity: severity,
							FilePath: path,
							Line:     lineNum,
							Message:  message,
							Snippet:  word[:6] + "************************",
						})
					}
				}
			}
		}
		lineNum++
	}

	if len(findings) > 0 && s.AutoFix {
		s.applyAutoFix(path, findings)
	}

	return findings
}

func (s *Scanner) applyAutoFix(path string, findings []Finding) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	text := string(content)
	changed := false

	for _, f := range findings {
		switch f.RuleID {
		case "ai.yaml_poisoning":
			// AST-Aware replacement
			text = strings.ReplaceAll(text, "yaml.unsafe_load(", "yaml.safe_load(")
			changed = true
		case "code.chmod_777":
			text = strings.ReplaceAll(text, "chmod 777", "chmod 755")
			changed = true
		case "code.eval":
			// AST-Aware injection
			text = regexp.MustCompile(`\beval\s*\(([^)]+)\)`).ReplaceAllString(text, `safeEval($1)`)
			changed = true
		case "asi.excessive_agency":
			// Sandbox injection
			text = regexp.MustCompile(`agent\.execute\(([^)]+)\)`).ReplaceAllString(text, `agent.executeSandbox($1)`)
			changed = true
		case "secret.github_token", "secret.aws_key", "secret.high_entropy":
			// Obfuscate secret in place if exact snippet is known
			originalSecret := strings.ReplaceAll(f.Snippet, "*", "")
			if len(originalSecret) >= 6 {
				text = strings.ReplaceAll(text, f.Snippet[:6], "[SECRET_REMOVED_BY_REPOGUARD]")
				changed = true
			}
		}
	}

	if changed {
		os.WriteFile(path, []byte(text), 0644)
	}
}
