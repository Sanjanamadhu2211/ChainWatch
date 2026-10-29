import { execFileSync, spawnSync } from "node:child_process";
import { join } from "node:path";

export const repoRoot = join(__dirname, "..", "..");
export const fixture = (name: string) => join(repoRoot, "tests", "fixtures", name);

/** Builds the CLI once per test file so e2e tests run the real compiled binary. */
export function buildCli(): void {
  execFileSync(
    process.execPath,
    [join(repoRoot, "node_modules", "tsup", "dist", "cli-default.js")],
    {
      cwd: repoRoot,
      stdio: "ignore",
    },
  );
}

export function runCli(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [join(repoRoot, "dist", "index.js"), ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
