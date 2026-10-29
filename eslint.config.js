import js from "@eslint/js";
import tseslint from "typescript-eslint";

// Module boundaries from the implementation plan: imports only flow downwards.
const forbid = (...dirs) => ({
  "no-restricted-imports": [
    "error",
    {
      patterns: dirs.map((d) => ({
        group: [`**/${d}`, `**/${d}/**`],
        message: `This module must not depend on ${d}. See the module boundaries in the plan.`,
      })),
    },
  ],
});

export default tseslint.config(
  { ignores: ["dist", "node_modules", "tests/fixtures", "coverage"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { files: ["src/lockfile/**"], rules: forbid("cli", "reports", "advisories", "risk", "policy") },
  { files: ["src/advisories/**"], rules: forbid("cli", "reports", "lockfile", "risk", "policy") },
  { files: ["src/risk/**"], rules: forbid("cli", "reports", "lockfile", "advisories", "policy") },
  { files: ["src/policy/**"], rules: forbid("cli", "reports", "lockfile", "advisories", "risk") },
  { files: ["src/reports/**"], rules: forbid("cli", "lockfile", "advisories", "risk", "policy") },
  { files: ["src/core/**"], rules: forbid("cli", "reports") },
);
