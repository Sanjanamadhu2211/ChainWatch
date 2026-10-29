import type { Finding, ScanResult } from "../core/types";
import {
  advisoryDataText,
  aliasText,
  coverageText,
  fixedText,
  morePathsText,
  noFindingsText,
  policyLines,
  printable,
  problemLines,
  riskTag,
} from "./text";

function renderFinding(f: Finding): string[] {
  const lines = [
    `${riskTag(f)}  ${f.package.name}@${f.package.version}  ${f.advisoryId}${aliasText(f)}`,
  ];
  if (f.summary) lines.push(`  ${f.summary}`);
  const path = f.dependencyPaths[0];
  if (path) lines.push(`  Path: ${path.join(" -> ")}${morePathsText(f)}`);
  lines.push(`  Fixed in: ${fixedText(f)}`, `  Action: ${f.suggestedAction}`);
  return lines;
}

function renderExplanation(f: Finding): string[] {
  const lines = [
    `${riskTag(f)} - ${f.package.name}@${f.package.version}`,
    `Advisory: ${f.advisoryId}${aliasText(f)}`,
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
  const out = [coverageText(result), advisoryDataText(result), ""];
  if (result.findings.length === 0) {
    out.push(noFindingsText(result));
  } else {
    out.push(`${result.findings.length} finding(s):`, "");
    for (const f of result.findings) out.push(...renderFinding(f), "");
  }
  const policy = policyLines(result);
  if (policy.length) out.push(...policy, "");
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
