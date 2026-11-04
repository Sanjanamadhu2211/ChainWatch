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
  const path = f.dependencyPaths[0];
  const refs = f.references.length
    ? `<ul class="refs">${f.references.map((r) => `<li>${reference(r)}</li>`).join("")}</ul>`
    : "";
  return [
    `<article class="finding ${esc(f.riskLevel)}">`,
    `<h3>${esc(riskTag(f))} &middot; ${esc(f.package.name)}@${esc(f.package.version)} &middot; ${esc(f.advisoryId)}${esc(aliasText(f))}</h3>`,
    f.summary ? `<p>${esc(f.summary)}</p>` : "",
    path ? `<p>Path: <code>${esc(path.join(" -> "))}</code>${esc(morePathsText(f))}</p>` : "",
    `<p>Fixed in: ${esc(fixedText(f))}</p>`,
    `<p>Action: ${esc(f.suggestedAction)}</p>`,
    refs,
    "</article>",
  ].join("\n");
}

export function renderHtml(result: ScanResult): string {
  const levels = ["critical", "high", "medium", "low", "unknown"] as const;
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  for (const finding of result.findings) counts[finding.riskLevel]!++;
  const breakdown = levels
    .map(
      (level) =>
        `<div class="metric ${level}"><span>${level[0]!.toUpperCase() + level.slice(1)}</span> <strong>${counts[level]}</strong></div>`,
    )
    .join("\n");
  const findings =
    result.findings.length === 0
      ? `<div class="empty">${esc(noFindingsText(result))}</div>`
      : result.findings.map(renderFinding).join("\n");
  const policy = policyLines(result);
  const problems = problemLines(result);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ChainWatch scan report</title>
<style>
:root { color-scheme: light dark; --bg: #f3f6f5; --surface: #fff; --text: #172c28; --muted: #526960; --border: #d5e1db; --accent: #176551; --critical: #a1222c; --medium: #845800; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 1rem/1.55 system-ui, sans-serif; }
.topbar { border-bottom: 1px solid var(--border); background: var(--surface); }
.topbar-inner, main, footer { width: min(100% - 2rem, 72rem); margin: auto; }
.topbar-inner { padding: 1rem 0; font-weight: 750; letter-spacing: -.03em; }
.brand-mark { display: inline-grid; place-items: center; width: 2rem; height: 2rem; margin-right: .6rem; border-radius: .45rem; background: var(--accent); color: #fff; }
main { padding: 2.5rem 0 3rem; }
.eyebrow { margin: 0 0 .35rem; color: var(--accent); font-size: .75rem; font-weight: 750; text-transform: uppercase; letter-spacing: .1em; }
h1 { margin: 0; font-size: clamp(2rem, 4vw, 2.9rem); letter-spacing: -.05em; line-height: 1.15; }
h2 { margin: 0 0 1rem; font-size: 1.15rem; letter-spacing: -.02em; }
.intro { display: flex; justify-content: space-between; align-items: start; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.status { padding: .4rem .8rem; border: 1px solid var(--border); border-radius: 999px; background: var(--surface); font-size: .85rem; font-weight: 700; }
.status.partial, .status.failed { color: var(--critical); border-color: currentColor; }
.overview, .finding, .empty, .policy, .problems { background: var(--surface); border: 1px solid var(--border); border-radius: .75rem; }
.overview { padding: 1.4rem; margin-bottom: 2rem; }
.coverage { color: var(--muted); margin: .3rem 0; }
.metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .75rem; margin-top: 1.4rem; }
.metric { padding: .8rem; border: 1px solid var(--border); border-radius: .5rem; }
.metric span { display: block; color: var(--muted); font-size: .8rem; font-weight: 650; }
.metric strong { display: block; font-size: 1.6rem; line-height: 1.2; font-variant-numeric: tabular-nums; }
.metric.critical strong, .metric.high strong { color: var(--critical); }
.metric.medium strong { color: var(--medium); }
.finding { border-left: 4px solid var(--muted); padding: 1rem 1.25rem; margin: .75rem 0; overflow-wrap: anywhere; }
.finding.critical, .finding.high { border-left-color: var(--critical); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--accent); }
.finding h3 { margin: 0 0 .7rem; font-size: 1rem; }
.finding p { margin: .45rem 0; }
.refs { padding-left: 1.25rem; margin-bottom: 0; }
a { color: var(--accent); text-underline-offset: .15em; }
code { overflow-wrap: anywhere; }
.empty, .policy, .problems { padding: 1rem 1.25rem; margin: 1rem 0; }
.policy p, .problems p { margin: .25rem 0; }
.problems { border-left: 4px solid var(--critical); }
footer { padding: 0 0 2rem; color: var(--muted); font-size: .8rem; overflow-wrap: anywhere; }
@media (max-width: 600px) { main { padding-top: 1.5rem; } .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (prefers-color-scheme: dark) { :root { --bg: #111c19; --surface: #1b2c26; --text: #e5f0e9; --muted: #b3c8ba; --border: #3a5045; --accent: #9ed9b9; --critical: #ffb0b0; --medium: #f5d285; } .brand-mark { color: #10251a; } }
@media print { :root { color-scheme: light; --bg: #fff; --surface: #fff; --text: #111; --muted: #444; --border: #aaa; --accent: #174b3d; --critical: #8d1820; --medium: #704900; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner"><span class="brand-mark" aria-hidden="true">C</span>ChainWatch</div></header>
<main>
<div class="intro"><div><p class="eyebrow">Dependency security</p><h1>Scan report</h1></div><div class="status ${esc(result.status)}">Status: ${esc(result.status[0]!.toUpperCase() + result.status.slice(1))}</div></div>
${problems.length ? `<section class="problems">${problems.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section class="overview" aria-labelledby="overview-title"><h2 id="overview-title">Scan overview</h2>
<p class="coverage">${esc(coverageText(result))}.</p><p class="coverage">${esc(advisoryDataText(result))}.</p>
<div class="metrics" aria-label="Findings by risk level">${breakdown}</div></section>
${policy.length ? `<section class="policy" aria-label="Policy result">${policy.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section aria-labelledby="findings-title"><h2 id="findings-title">Findings <span>(${result.findings.length})</span></h2>${findings}</section>
</main>
<footer><p>Scan ${esc(result.scanId)} of ${esc(result.rootPath)} at ${esc(result.completedAt)} &middot; ChainWatch ${esc(result.toolVersion)}</p></footer>
</body>
</html>
`;
}
