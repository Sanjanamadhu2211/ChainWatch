import { mkdtemp, writeFile } from "node:fs/promises";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { ChainwatchError } from "../../src/core/errors";
import { readScanResult, scanResultSchema } from "../../src/reports/schema";
import { renderJson } from "../../src/reports/json";
import { finding, result } from "../helpers/result";

const schemaFile = resolve(__dirname, "../../docs/schema/scan-result.schema.json");
const generated = JSON.stringify(z.toJSONSchema(scanResultSchema), null, 2) + "\n";

describe("scan result schema", () => {
  it("keeps the committed JSON Schema in sync with the zod schema", () => {
    // Regenerate with: UPDATE_SCHEMA=1 npx vitest run tests/unit/scan-result-schema.test.ts
    if (process.env.UPDATE_SCHEMA) writeFileSync(schemaFile, generated);
    expect(readFileSync(schemaFile, "utf8")).toBe(generated);
  });
});

describe("readScanResult", () => {
  const write = async (text: string) => {
    const file = join(await mkdtemp(join(tmpdir(), "chainwatch-")), "scan.json");
    await writeFile(file, text);
    return file;
  };

  it("reads a scan written by renderJson", async () => {
    const r = result({ findings: [finding()] });
    expect(await readScanResult(await write(renderJson(r)))).toEqual(r);
  });

  it("rejects text that is not JSON with exit 2", async () => {
    const error = await readScanResult(await write("{not json")).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ChainwatchError);
    expect((error as ChainwatchError).code).toBe("INVALID_REPORT");
    expect((error as ChainwatchError).exitCode).toBe(2);
  });

  it("rejects unknown fields so a typo cannot pass silently", async () => {
    const json = JSON.parse(renderJson(result()));
    json.surprise = true;
    await expect(readScanResult(await write(JSON.stringify(json)))).rejects.toThrow(
      /not a chainwatch scan result: .*surprise/,
    );
  });

  it("rejects a missing file", async () => {
    await expect(readScanResult(join(tmpdir(), "chainwatch-missing.json"))).rejects.toMatchObject({
      code: "INVALID_REPORT",
      exitCode: 2,
    });
  });
});
