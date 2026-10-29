import type { Finding, PolicyResult } from "../core/types";
import type { Config } from "./config";

export const FAIL_ON_LEVELS = ["critical", "high", "medium", "low", "none"] as const;
export type FailOn = (typeof FAIL_ON_LEVELS)[number];

const SEVERITY: Record<Exclude<Finding["riskLevel"], "unknown">, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface EvaluateOptions {
  /** Effective level: the --fail-on flag if given, else the configured failOn. */
  failOn: FailOn;
  /** Exception expiry is judged against this day (UTC). */
  now: Date;
}

/**
 * Decides which findings fail the scan. An exception applies through its expiry day
 * (inclusive); after that the finding counts again and a warning says so.
 */
export function evaluatePolicy(
  findings: Finding[],
  policy: Config["policy"],
  options: EvaluateOptions,
): PolicyResult {
  const today = options.now.toISOString().slice(0, 10);
  const warnings = policy.ignore
    .filter((e) => e.expires < today)
    .map((e) => `exception for ${e.advisoryId} expired on ${e.expires}; its findings count again`);
  const threshold = options.failOn === "none" ? undefined : SEVERITY[options.failOn];

  const failingFindingIds: string[] = [];
  const ignoredFindingIds: string[] = [];
  for (const f of findings) {
    const excepted = policy.ignore.some(
      (e) =>
        e.expires >= today && (f.advisoryId === e.advisoryId || f.aliases.includes(e.advisoryId)),
    );
    if (excepted) {
      ignoredFindingIds.push(f.id);
    } else if (threshold !== undefined) {
      const fails =
        f.riskLevel === "unknown"
          ? policy.unknownSeverity === "fail"
          : SEVERITY[f.riskLevel] >= threshold;
      if (fails) failingFindingIds.push(f.id);
    }
  }

  return {
    passed: failingFindingIds.length === 0,
    failOn: options.failOn,
    failingFindingIds,
    ignoredFindingIds,
    warnings,
  };
}
