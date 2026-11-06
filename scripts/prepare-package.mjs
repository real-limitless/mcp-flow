import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

// `prepare` runs on local npm install, git installs, npm pack, and npm publish.
// The Docker build runs `npm ci` before `src/` exists, and a registry install
// already contains `dist/`. Build only when this tree still has TypeScript sources.
if (!existsSync("src/cli.ts") || !existsSync("tsconfig.json")) {
  process.exit(0);
}

const result = spawnSync("npm", ["run", "build"], {
  stdio: "inherit",
  shell: process.platform === "win32",
});
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status === 0 ? 0 : 1);
