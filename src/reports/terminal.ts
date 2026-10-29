import type { Finding, ScanResult } from "../core/types";
import { printable, problemLines, riskTag } from "./text";

function renderFinding(f: Finding): string[] {
  const lines = [
    `${riskTag(f)}  ${f.package.name}@${f.package.version}  ${f.advisoryId}${f.aliases.length ? ` (${f.aliases.join(", ")})` : ""}`,
  ];
  if (f.summary) lines.push(`  ${f.summary}`);
  const path = f.dependencyPaths[0];
  if (path)
    lines.push(
      `  Path: ${path.join(" -> ")}${f.dependencyPathCount > 1 ? ` (+${f.dependencyPathCount - 1} more)` : ""}`,
    );
  lines.push(
    `  Fixed in: ${f.fixedVersions.length ? f.fixedVersions.join(", ") : "no fixed version listed"}`,
  );
  lines.push(`  Action: ${f.suggestedAction}`);
  return lines;
}

function renderExplanation(f: Finding): string[] {
  const aliases = f.aliases.length ? ` (${f.aliases.join(", ")})` : "";
  const lines = [
    `${riskTag(f)} - ${f.package.name}@${f.package.version}`,
    `Advisory: ${f.advisoryId}${aliases}`,
  ];
  if (f.summary) lines.push(`Summary: ${f.summary}`);
  lines.push("", "Why it is prioritized:");
  for (const factor of f.factors) {
    lines.push(`  + ${factor.name}: ${factor.reason} (contributes ${factor.contribution})`);
  }
  const plural = f.dependencyPathCount > 1 ? "s" : "";
  lines.push(
    "",
    `Dependency path${plural} (${f.dependencyPaths.length} of ${f.dependencyPathCount}):`,
  );
  for (const path of f.dependencyPaths) lines.push(`  ${path.join(" -> ")}`);
  lines.push("", "Recommended action:", `  ${f.suggestedAction}`);
  lines.push("", "Limitations:", "  Runtime reachability has not been evaluated.");
  return lines;
}

export function renderTerminal(result: ScanResult): string {
  const { coverage, advisoryData } = result;
  const out = [
    `Checked ${coverage.queried} of ${coverage.packagesScanned} installed packages ` +
      `(${coverage.skipped} skipped, ${coverage.failed} could not be checked)`,
    `Advisory data: ${advisoryData.freshLookups} fetched from OSV, ${advisoryData.cacheHits} from cache` +
      (advisoryData.staleCacheHits ? ` (${advisoryData.staleCacheHits} past their TTL)` : ""),
    "",
  ];
  if (result.findings.length === 0) {
    out.push(
      result.status === "complete"
        ? "No known vulnerabilities found."
        : "No vulnerabilities found in the packages that were checked.",
    );
  } else {
    out.push(`${result.findings.length} finding(s):`, "");
    for (const f of result.findings) out.push(...renderFinding(f), "");
  }
  out.push(...problemLines(result));
  return out.map(printable).join("\n");
}

/** `matches` are the findings for `spec`, already in ranked order. */
export function renderExplain(result: ScanResult, matches: Finding[], spec: string): string {
  const out: string[] = [];
  if (matches.length === 0) {
    out.push(
      `No known vulnerabilities found for ${spec}` +
        (result.status === "complete" ? "." : " in the packages that were checked."),
    );
  }
  matches.forEach((f, i) => {
    if (i > 0) out.push("");
    out.push(...renderExplanation(f));
  });
  const problems = problemLines(result);
  if (problems.length) out.push("", ...problems);
  return out.map(printable).join("\n");
}
