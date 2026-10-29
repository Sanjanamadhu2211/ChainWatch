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
