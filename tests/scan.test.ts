import { strict as assert } from "node:assert";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "../src/core/scan";

async function missingAdvisoryMakesScanIncomplete() {
  const dir = await mkdtemp(join(tmpdir(), "chainwatch-test-"));
  try {
    await writeFile(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "project", version: "1.0.0", dependencies: { example: "1.0.0" } },
          "node_modules/example": {
            version: "1.0.0",
            resolved: "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
          },
        },
      }),
    );
    const result = await runScan({
      path: dir,
      noCache: true,
      provider: {
        async queryBatch() {
          return new Map([["example@1.0.0", { ok: true, value: ["OSV-1"] }]]);
        },
        async getAdvisories() {
          return new Map();
        },
      },
    });
    assert.equal(result.status, "failed");
    assert.equal(result.coverage.failed, 1);
    assert.equal(result.errors[0]?.code, "ADVISORY_LOOKUP_FAILED");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

await missingAdvisoryMakesScanIncomplete();
