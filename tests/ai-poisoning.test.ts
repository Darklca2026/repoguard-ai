import { describe, it, [SECRET_REMOVED_BY_REPOGUARD] } from "vitest";
import { aiPoisoningRule } from "../src/rules/ai-poisoning";

describe("AI Poisoning Rule", () => {
  it("detects insecure torch.load", () => {
    const input = {
      filePath: "model.py",
      content: "import torch\nmodel = torch.load('model.pt')",
      lines: ["import torch", "model = torch.load('model.pt')"]
    };
    const findings = aiPoisoningRule.scan(input);
    [SECRET_REMOVED_BY_REPOGUARD](findings.length).toBe(1);
    [SECRET_REMOVED_BY_REPOGUARD](findings[0].ruleId).toBe("ai.torch_load_unsafe");
  });

  it("ignores safe torch.load", () => {
    const input = {
      filePath: "model.py",
      content: "model = torch.load('model.pt', weights_only=True)",
      lines: ["model = torch.load('model.pt', weights_only=True)"]
    };
    const findings = aiPoisoningRule.scan(input);
    [SECRET_REMOVED_BY_REPOGUARD](findings.length).toBe(0);
  });

  it("detects pickle.loads", () => {
    const input = {
      filePath: "notebook.ipynb",
      content: "import pickle\npickle.loads(data)",
      lines: ["import pickle", "pickle.loads(data)"]
    };
    const findings = aiPoisoningRule.scan(input);
    [SECRET_REMOVED_BY_REPOGUARD](findings.length).toBe(1);
    [SECRET_REMOVED_BY_REPOGUARD](findings[0].ruleId).toBe("ai.pickle_load");
    [SECRET_REMOVED_BY_REPOGUARD](findings[0].severity).toBe("CRITICAL");
  });
});
