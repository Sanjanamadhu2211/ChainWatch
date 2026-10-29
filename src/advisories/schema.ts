import { z } from "zod";
import type { Advisory } from "../core/types";

// Upstream data is validated at the boundary; everything past this file works with `Advisory`.

export const queryBatchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string(), modified: z.string().optional() })).optional(),
      next_page_token: z.string().optional(),
    }),
  ),
});

const osvEvent = z.object({
  introduced: z.string().optional(),
  fixed: z.string().optional(),
  last_affected: z.string().optional(),
  limit: z.string().optional(),
});

const osvVulnSchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  withdrawn: z.string().optional(),
  modified: z.string().optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
  database_specific: z.object({ severity: z.string().optional() }).loose().optional(),
  affected: z
    .array(
      z.object({
        package: z.object({ name: z.string(), ecosystem: z.string() }).optional(),
        ranges: z.array(z.object({ type: z.string(), events: z.array(osvEvent) })).optional(),
        versions: z.array(z.string()).optional(),
      }),
    )
    .optional(),
  references: z.array(z.object({ url: z.string() })).optional(),
});

const RANGE_TYPES = new Set(["SEMVER", "ECOSYSTEM", "GIT"]);

/** Turns a raw OSV vulnerability record into the normalized Advisory, keeping only npm entries. */
export function parseOsvVuln(json: unknown): Advisory {
  const v = osvVulnSchema.parse(json);
  const label = v.database_specific?.severity;
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    ...(v.summary ? { summary: v.summary } : {}),
    ...(v.withdrawn ? { withdrawn: v.withdrawn } : {}),
    severity: {
      cvssVectors: (v.severity ?? []).map((s) => ({ type: s.type, vector: s.score })),
      ...(label ? { label: label.toUpperCase() } : {}),
    },
    affected: (v.affected ?? [])
      .filter((a) => a.package?.ecosystem === "npm")
      .map((a) => ({
        packageName: (a.package as { name: string }).name,
        versions: a.versions ?? [],
        ranges: (a.ranges ?? [])
          .filter((r) => RANGE_TYPES.has(r.type))
          .map((r) => ({ type: r.type as "SEMVER" | "ECOSYSTEM" | "GIT", events: r.events })),
      })),
    references: (v.references ?? []).map((r) => r.url),
    ...(v.modified ? { modifiedAt: v.modified } : {}),
  };
}

/** Schema for normalized advisories, used to validate the on-disk cache. */
export const advisorySchema: z.ZodType<Advisory> = z.object({
  id: z.string(),
  aliases: z.array(z.string()),
  summary: z.string().optional(),
  withdrawn: z.string().optional(),
  severity: z.object({
    cvssVectors: z.array(z.object({ type: z.string(), vector: z.string() })),
    label: z.string().optional(),
  }),
  affected: z.array(
    z.object({
      packageName: z.string(),
      versions: z.array(z.string()),
      ranges: z.array(
        z.object({ type: z.enum(["SEMVER", "ECOSYSTEM", "GIT"]), events: z.array(osvEvent) }),
      ),
    }),
  ),
  references: z.array(z.string()),
  modifiedAt: z.string().optional(),
});
