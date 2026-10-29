import type { Finding, ScanResult } from "../core/types";
import { printable, problemLines, riskTag } from "./text";

const ENTITY: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Every piece of scan text goes through here. Scripts never run: there are none and CSP forbids them. */
function esc(text: string): string {
  return printable(text).replace(/[&<>"']/g, (c) => ENTITY[c] ?? c);
}

/** Only https links become anchors; anything else (javascript:, data:, http:) is shown as plain text. */
function reference(ref: string): string {
  let url: URL;
  try {
    url = new URL(ref);
  } catch {
    return esc(ref);
  }
  return url.protocol === "https:"
    ? `<a href="${esc(url.href)}" rel="noopener noreferrer">${esc(ref)}</a>`
    : esc(ref);
}

function renderFinding(f: Finding): string {
  const aliases = f.aliases.length ? ` (${esc(f.aliases.join(", "))})` : "";
  const path = f.dependencyPaths[0];
  const more = f.dependencyPathCount > 1 ? ` (+${f.dependencyPathCount - 1} more)` : "";
  const refs = f.references.length
    ? `<ul class="refs">${f.references.map((r) => `<li>${reference(r)}</li>`).join("")}</ul>`
    : "";
  return [
    `<article class="finding ${esc(f.riskLevel)}">`,
    `<h3>${esc(riskTag(f))} &middot; ${esc(f.package.name)}@${esc(f.package.version)} &middot; ${esc(f.advisoryId)}${aliases}</h3>`,
    f.summary ? `<p>${esc(f.summary)}</p>` : "",
    path ? `<p>Path: <code>${esc(path.join(" -> "))}</code>${esc(more)}</p>` : "",
    `<p>Fixed in: ${esc(f.fixedVersions.length ? f.fixedVersions.join(", ") : "no fixed version listed")}</p>`,
    `<p>Action: ${esc(f.suggestedAction)}</p>`,
    refs,
    "</article>",
  ].join("\n");
}

export function renderHtml(result: ScanResult): string {
  const { coverage, advisoryData } = result;
  const findings =
    result.findings.length === 0
      ? `<p>${
          result.status === "complete"
            ? "No known vulnerabilities found."
            : "No vulnerabilities found in the packages that were checked."
        }</p>`
      : `<p>${result.findings.length} finding(s):</p>\n${result.findings.map(renderFinding).join("\n")}`;
  const problems = problemLines(result);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>chainwatch report</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 56rem; padding: 0 1rem; color: #1b1b1b; }
.finding { border-left: 4px solid #888; padding: 0.25rem 1rem; margin: 1rem 0; }
.finding.critical, .finding.high { border-color: #b00020; }
.finding.medium { border-color: #b26a00; }
.finding.low { border-color: #2e7d32; }
.problems { color: #b00020; }
code { word-break: break-all; }
</style>
</head>
<body>
<h1>chainwatch scan report</h1>
<p>Status: <strong>${esc(result.status)}</strong></p>
<p>Checked ${coverage.queried} of ${coverage.packagesScanned} installed packages (${coverage.skipped} skipped, ${coverage.failed} could not be checked).</p>
<p>Advisory data: ${advisoryData.freshLookups} fetched from OSV, ${advisoryData.cacheHits} from cache${advisoryData.staleCacheHits ? ` (${advisoryData.staleCacheHits} past their TTL)` : ""}.</p>
${findings}
${problems.length ? `<section class="problems">${problems.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<footer><p>Scan ${esc(result.scanId)} of ${esc(result.rootPath)} at ${esc(result.completedAt)}, chainwatch ${esc(result.toolVersion)}.</p></footer>
</body>
</html>
`;
}
