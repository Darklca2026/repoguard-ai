import { Rule, Finding } from "../types";

const POISONING_PATTERNS = [
  { id: "ai.pickle_load", regex: /pickle\.(load|loads)\s*\(/, severity: "CRITICAL" as const, fix: "Avoid using pickle to load untrusted data. It can execute arbitrary code. Use safetensors or json." },
  { id: "ai.torch_load_unsafe", regex: [SECRET_REMOVED_BY_REPOGUARD]\.load\s*\([^)]*(weights_only\s*=\s*False)?[^)]*\)/, severity: "HIGH" as const, fix: "Always use weights_only=True when loading PyTorch models to prevent arbitrary code execution." },
  { id: "ai.yaml_unsafe_load", regex: /yaml\.unsafe_load\s*\(/, severity: "CRITICAL" as const, fix: "Use yaml.safe_load() instead of unsafe_load()." },
  { id: "ai.keras_lambda", regex: /Lambda\s*\(/, severity: "LOW" as const, fix: "Keras Lambda layers can execute arbitrary functions. Ensure the model source is trusted." },
  { id: "ai.numpy_load_allow_pickle", regex: [SECRET_REMOVED_BY_REPOGUARD]\.load\s*\([^)]*allow_pickle\s*=\s*True[^)]*\)/, severity: "HIGH" as const, fix: "Avoid using allow_pickle=True in numpy.load()." }
];

export const aiPoisoningRule: Rule = {
  id: "ai-poisoning",
  description: "AI Model Poisoning & Insecure Deserialization",
  severity: "CRITICAL",
  fileTypes: [".py", ".ipynb"],
  scan: (input) => {
    const findings: Finding[] = [];

    input.lines.forEach((line, index) => {
      // Fast bypass for empty lines
      if (!line.trim()) return;

      for (const pattern of POISONING_PATTERNS) {
        if (pattern.regex.test(line)) {
          // AutoFix logic setup
          let autoFixObj = undefined;
          
          if (pattern.id === "ai.torch_load_unsafe") {
             if (line.includes("weights_only=True")) {
               continue; // It is safe
             } else {
               // Provide auto-fix for torch.load
               // Extract the function call to safely inject weights_only=True
               const match = line.match([SECRET_REMOVED_BY_REPOGUARD]\.load\s*\(([^)]+)\)/);
               if (match) {
                 const originalArgs = match[1];
                 autoFixObj = {
                   searchValue: `torch.load(${originalArgs})`,
                   replaceValue: `torch.load(${originalArgs}, weights_only=True)`
                 };
               }
             }
          } else if (pattern.id === "ai.yaml_unsafe_load") {
            autoFixObj = {
              searchValue: "yaml.safe_load(",
              replaceValue: "yaml.safe_load("
            };
          }

          findings.push({
            ruleId: pattern.id,
            severity: pattern.severity,
            filePath: input.filePath,
            line: index + 1,
            message: `Insecure AI model loading detected: ${pattern.id}.`,
            snippet: line.trim().substring(0, 80),
            fix: pattern.fix,
            autoFix: autoFixObj
          });
        }
      }
    });

    return findings;
  }
};
