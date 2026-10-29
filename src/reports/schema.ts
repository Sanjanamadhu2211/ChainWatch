import { readFile } from "node:fs/promises";
import { z } from "zod";
import { ChainwatchError } from "../core/errors";
import type { ScanResult } from "../core/types";

const count = z.number().int().nonnegative();
const strings = z.array(z.string());
const risk = z.enum(["critical", "high", "medium", "low", "unknown"]);

const finding = z.strictObject({
  id: z.string(),
  package: z.strictObject({ ecosystem: z.literal("npm"), name: z.string(), version: z.string() }),
  advisoryId: z.string(),
  aliases: strings,
  summary: z.string().optional(),
  installedVersion: z.string(),
  nodeIds: strings,
  direct: z.boolean(),
  dev: z.boolean(),
  optional: z.boolean(),
  upstreamSeverity: z.strictObject({
    cvssScore: z.number().optional(),
    label: z.string().optional(),
    source: z.enum(["cvss-vector", "label", "none"]),
  }),
  fixedVersions: strings,
  suggestedAction: z.string(),
  dependencyPaths: z.array(strings),
  dependencyPathCount: count,
  riskScore: z.number().nullable(),
  riskLevel: risk,
  factors: z.array(
    z.strictObject({ name: z.string(), contribution: z.number(), reason: z.string() }),
  ),
  references: strings,
});

/** The contract for scan.json. Committed as docs/schema/scan-result.schema.json. */
export const scanResultSchema: z.ZodType<ScanResult> = z.strictObject({
  schemaVersion: z.literal("1.0"),
  toolVersion: z.string(),
  scanId: z.string(),
  startedAt: z.string(),
  completedAt: z.string(),
  rootPath: z.string(),
  status: z.enum(["complete", "partial", "failed"]),
  coverage: z.strictObject({
    packagesScanned: count,
    queried: count,
    failed: count,
    skipped: count,
  }),
  advisoryData: z.strictObject({
    provider: z.literal("osv"),
    freshLookups: count,
    cacheHits: count,
    staleCacheHits: count,
    oldestFetchedAt: z.string().optional(),
  }),
  findings: z.array(finding),
  policy: z
    .strictObject({
      passed: z.boolean(),
      failOn: z.enum(["critical", "high", "medium", "low", "none"]),
      failingFindingIds: strings,
      ignoredFindingIds: strings,
      warnings: strings,
    })
    .optional(),
  warnings: strings,
  errors: z.array(z.strictObject({ code: z.string(), message: z.string() })),
});

/** Reads a scan.json file. Bad files are exit 2 (invalid input), never a crash. */
export async function readScanResult(file: string): Promise<ScanResult> {
  let json: unknown;
  try {
    json = JSON.parse(await readFile(file, "utf8"));
  } catch {
    throw new ChainwatchError("INVALID_REPORT", `${file} is not readable JSON`, 2);
  }
  const parsed = scanResultSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const where = issue?.path.join(".") || "(root)";
    throw new ChainwatchError(
      "INVALID_REPORT",
      `${file} is not a chainwatch scan result: ${where} ${issue?.message ?? "is invalid"}`,
      2,
    );
  }
  return parsed.data;
}
