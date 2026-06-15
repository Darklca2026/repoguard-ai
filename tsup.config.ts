import { defineConfig } from "tsup";
import packageJson from "./package.json";

export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["cjs"],
  platform: "node",
  target: "node22",
  minify: true,
  clean: true,
  sourcemap: false,
  splitting: false,
  noExternal: [/.*/],
  define: {
    __REPOGUARD_VERSION__: JSON.stringify(packageJson.version),
  },
});
