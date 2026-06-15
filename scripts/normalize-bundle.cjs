const fs = require("node:fs");
const path = require("node:path");

const bundle = path.resolve(__dirname, "../dist/cli.js");
const normalized = fs
  .readFileSync(bundle, "utf8")
  .replace(/[ \t]+$/gm, "")
  .replace(/\s*$/, "\n");
fs.writeFileSync(bundle, normalized, { mode: 0o755 });
