import { describe, expect, it } from "vitest";
import { aiPoisoningRule } from "../src/rules/ai-poisoning";

describe("AI Poisoning Rule", () => {
  it("detects insecure torch.load", () => {
    const input = {
      filePath: "model.py",
      content: "import torch\nmodel = torch.load('model.pt')",
      lines: ["import torch", "model = torch.load('model.pt')"],
    };
    const findings = aiPoisoningRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("ai.torch_load_unsafe");
  });

  it("ignores safe torch.load", () => {
    const input = {
      filePath: "model.py",
      content: "model = torch.load('model.pt', weights_only=True)",
      lines: ["model = torch.load('model.pt', weights_only=True)"],
    };
    const findings = aiPoisoningRule.scan(input);
    expect(findings.length).toBe(0);
  });

  it("detects pickle.loads", () => {
    const input = {
      filePath: "notebook.ipynb",
      content: "import pickle\npickle.loads(data)",
      lines: ["import pickle", "pickle.loads(data)"],
    };
    const findings = aiPoisoningRule.scan(input);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("ai.pickle_load");
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("accepts spaced weights_only safety arguments", () => {
    const line = "model = torch.load('model.pt', weights_only = True)";
    expect(aiPoisoningRule.scan({ filePath: "model.py", content: line, lines: [line] })).toEqual([]);
  });

  it("detects remote model code and unsafe Python artifact formats", () => {
    const lines = [
      "model = AutoModel.from_pretrained(repo, trust_remote_code=True)",
      "joblib.load('model.joblib')",
      "dill.loads(payload)",
    ];
    const findings = aiPoisoningRule.scan({ filePath: "model.py", content: lines.join("\n"), lines });
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "ai.trust_remote_code",
      "ai.joblib_load",
      "ai.dill_load",
    ]);
  });
});
