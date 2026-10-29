import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { ConfigError } from "../core/errors";

const date = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "must be a date like 2026-12-31")
  .refine((s) => {
    const d = new Date(`${s}T00:00:00Z`);
    // Round-tripping catches impossible dates such as 2026-02-31. The refine also runs
    // after a failed regex, so an invalid Date must not throw here.
    return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(s);
  }, "is not a real date");

const weight = z.number().min(0).max(1);

// Every object is strict: a typo such as `falOn` is an error, never a silently ignored setting.
export const configSchema = z.strictObject({
  version: z.literal(1),
  scan: z
    .strictObject({
      lockfiles: z.array(z.string().min(1)).min(1).default(["package-lock.json"]),
      includeDevDependencies: z.boolean().default(true),
    })
    .prefault({}),
  advisories: z
    .strictObject({
      provider: z.literal("osv").default("osv"),
      cacheTtlSeconds: z.number().int().min(0).default(3600),
    })
    .prefault({}),
  risk: z
    .strictObject({
      weights: z
        .strictObject({ severity: weight.default(0.8), exposure: weight.default(0.2) })
        .refine((w) => Math.abs(w.severity + w.exposure - 1) < 1e-6, "weights must sum to 1")
        .prefault({}),
    })
    .prefault({}),
  policy: z
    .strictObject({
      failOn: z.enum(["critical", "high", "medium", "low", "none"]).default("high"),
      unknownSeverity: z.enum(["report", "fail"]).default("report"),
      ignore: z
        .array(
          z.strictObject({
            advisoryId: z.string().min(1),
            reason: z.string().min(1),
            expires: date,
          }),
        )
        .default([]),
    })
    .prefault({}),
});

export type Config = z.infer<typeof configSchema>;

export const DEFAULT_CONFIG_NAMES = ["chainwatch.yaml", "chainwatch.yml"];

export function parseConfig(text: string, source = "configuration"): Config {
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (e) {
    throw new ConfigError(`${source} is not valid YAML: ${(e as Error).message}`);
  }
  const result = configSchema.safeParse(raw);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  ${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new ConfigError(`${source} is invalid:\n${lines.join("\n")}`);
  }
  return result.data;
}

export function defaultConfig(): Config {
  return configSchema.parse({ version: 1 });
}

/**
 * Loads the file given with --config (which must exist), else chainwatch.yaml / chainwatch.yml
 * in the project root, else the defaults.
 */
export async function loadConfig(rootPath: string, explicitPath?: string): Promise<Config> {
  if (explicitPath !== undefined) {
    return parseConfig(await readConfigFile(explicitPath), explicitPath);
  }
  for (const name of DEFAULT_CONFIG_NAMES) {
    const path = join(rootPath, name);
    try {
      return parseConfig(await readFile(path, "utf8"), path);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
  }
  return defaultConfig();
}

async function readConfigFile(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    throw new ConfigError(`Could not read the configuration file ${path}`);
  }
}
