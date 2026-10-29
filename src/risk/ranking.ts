import type { Finding } from "../core/types";

/**
 * Highest risk first. Unknown-risk findings come after every scored one. Ties break on package
 * name, version, then advisory id so the order is identical from run to run.
 */
export function rankFindings<T extends Pick<Finding, "riskScore" | "package" | "advisoryId">>(
  findings: T[],
): T[] {
  const byKey = (a: T, b: T) =>
    a.package.name.localeCompare(b.package.name) ||
    a.package.version.localeCompare(b.package.version, undefined, { numeric: true }) ||
    a.advisoryId.localeCompare(b.advisoryId);
  return [...findings].sort((a, b) => {
    if (a.riskScore === null && b.riskScore === null) return byKey(a, b);
    if (a.riskScore === null) return 1;
    if (b.riskScore === null) return -1;
    return b.riskScore - a.riskScore || byKey(a, b);
  });
}
