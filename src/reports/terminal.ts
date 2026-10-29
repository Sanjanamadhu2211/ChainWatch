import type { Finding, ScanResult } from "../core/types";

function renderFinding(f: Finding): string[] {
  const lines = [
    `${f.package.name}@${f.package.version}  ${f.advisoryId}${f.aliases.length ? ` (${f.aliases.join(", ")})` : ""}`,
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
  for (const w of result.warnings) out.push(`warning: ${w}`);
  for (const e of result.errors) out.push(`error [${e.code}]: ${e.message}`);
  if (result.status !== "complete") {
    out.push("", `The scan is ${result.status}: this is NOT a clean result.`);
  }
  return out.join("\n");
}
