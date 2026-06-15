const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const bundle = path.join(root, "dist", "cli.js");
if (!fs.existsSync(bundle)) throw new Error("dist/cli.js does not exist; run npm run build first");

const source = fs.readFileSync(bundle, "utf8");
const externalPackages = ["commander", "fast-glob", "ignore", "js-yaml", "picocolors", "zod"];
for (const dependency of externalPackages) {
  if (source.includes(`require("${dependency}")`) || source.includes(`require('${dependency}')`)) {
    throw new Error(`Bundle still requires external dependency: ${dependency}`);
  }
}

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "repoguard-bundle-"));
try {
  const standalone = path.join(tempDir, "repoguard-ai.js");
  fs.copyFileSync(bundle, standalone);
  fs.chmodSync(standalone, 0o755);
  const version = execFileSync(process.execPath, [standalone, "--version"], {
    cwd: tempDir,
    encoding: "utf8",
  }).trim();
  const expectedVersion = require(path.join(root, "package.json")).version;
  if (version !== expectedVersion) {
    throw new Error(`Standalone bundle reported ${version}; expected ${expectedVersion}`);
  }
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log("Standalone bundle verification passed.");
