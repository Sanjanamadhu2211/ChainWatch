import type { Finding, ScanResult } from "../core/types";

/** Escapes control characters so advisory and package text cannot change the terminal. */
export function printable(line: string): string {
  return line.replace(/\p{Cc}/gu, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export function riskTag(f: Pick<Finding, "riskLevel" | "riskScore">): string {
  return f.riskScore === null
    ? "UNKNOWN (no score)"
    : `${f.riskLevel.toUpperCase()} (score ${f.riskScore})`;
}

/** " (GHSA-x, CVE-y)" after an advisory id, or nothing when there are no aliases. */
export function aliasText(f: Pick<Finding, "aliases">): string {
  return f.aliases.length ? ` (${f.aliases.join(", ")})` : "";
}

export function fixedText(f: Pick<Finding, "fixedVersions">): string {
  return f.fixedVersions.length ? f.fixedVersions.join(", ") : "no fixed version listed";
}

/** " (+2 more)" when the package is reached by more paths than the one shown. */
export function morePathsText(f: Pick<Finding, "dependencyPathCount">): string {
  return f.dependencyPathCount > 1 ? ` (+${f.dependencyPathCount - 1} more)` : "";
}

export function coverageText(result: ScanResult): string {
  const { packagesScanned, queried, skipped, failed } = result.coverage;
  return (
    `Checked ${queried} of ${packagesScanned} installed packages ` +
    `(${skipped} skipped, ${failed} could not be checked)`
  );
}

export function advisoryDataText(result: ScanResult): string {
  const { freshLookups, cacheHits, staleCacheHits } = result.advisoryData;
  return (
    `Advisory data: ${freshLookups} fetched from OSV, ${cacheHits} from cache` +
    (staleCacheHits ? ` (${staleCacheHits} past their TTL)` : "")
  );
}

/** Says so when the scan did not check everything, since silence would look like a clean result. */
export function noFindingsText(result: ScanResult): string {
  return result.status === "complete"
    ? "No known vulnerabilities found."
    : "No vulnerabilities found in the packages that were checked.";
}

/** The policy decision. Empty for saved scans that predate policy. */
export function policyLines(result: ScanResult): string[] {
  const p = result.policy;
  if (!p) return [];
  const lines =
    p.failOn === "none"
      ? ["Policy: not gating (fail-on is none)."]
      : [
          `Policy: ${p.passed ? "passed" : "failed"} at fail-on ${p.failOn}; ` +
            `${p.failingFindingIds.length} finding(s) fail the policy.`,
        ];
  if (p.ignoredFindingIds.length) {
    lines.push(`${p.ignoredFindingIds.length} finding(s) ignored by exceptions in the config.`);
  }
  return [...lines, ...p.warnings.map((w) => `warning: ${w}`)];
}

/** Warnings, errors and a closing note when the scan is not complete. */
export function problemLines(result: ScanResult): string[] {
  const lines = [
    ...result.warnings.map((w) => `warning: ${w}`),
    ...result.errors.map((e) => `error [${e.code}]: ${e.message}`),
  ];
  if (result.status !== "complete") {
    lines.push("", `The scan is ${result.status}: this is NOT a clean result.`);
  }
  return lines;
}
