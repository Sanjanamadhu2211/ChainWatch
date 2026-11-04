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
    ? `<details class="references"><summary>Advisory references (${f.references.length})</summary><ul class="refs">${f.references.map((r) => `<li>${reference(r)}</li>`).join("")}</ul></details>`
    : "";
  return [
    `<article class="finding ${esc(f.riskLevel)}">`,
    `<div class="finding-header"><div><p class="advisory">${esc(f.advisoryId)}${esc(aliasText(f))}</p><h3>${esc(f.package.name)}<span class="version">@${esc(f.package.version)}</span></h3></div><span class="risk">${esc(riskTag(f))}</span></div>`,
    f.summary ? `<p class="finding-summary">${esc(f.summary)}</p>` : "",
    path
      ? `<p class="finding-path"><strong>Dependency path</strong><code>${esc(path.join(" → "))}</code>${esc(morePathsText(f))}</p>`
      : "",
    `<div class="remediation"><p><strong>Fixed in</strong> ${esc(fixedText(f))}</p><p><strong>Recommended action</strong> ${esc(f.suggestedAction)}</p></div>`,
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
:root { color-scheme: light dark; --bg: #fff; --text: #202329; --muted: #60666f; --border: #d9dce1; --link: #2357a5; --danger: #a82e35; --warning: #805800; --soft: #f6f7f8; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.topbar { border-bottom: 1px solid var(--border); }
.topbar-inner, main, footer { width: min(100% - 3rem, 68rem); margin: auto; }
.topbar-inner { display: flex; align-items: center; padding: 1rem 0; font-size: .95rem; font-weight: 700; letter-spacing: -.02em; }
main { padding: 2.5rem 0 3rem; }
.intro { display: flex; justify-content: space-between; align-items: end; flex-wrap: wrap; gap: 1rem; padding-bottom: 1.35rem; border-bottom: 1px solid var(--border); }
h1 { margin: 0; font-size: 1.8rem; line-height: 1.2; font-weight: 650; letter-spacing: -.035em; }
h2 { margin: 0 0 .7rem; font-size: .95rem; font-weight: 650; }
.status { padding: .2rem .5rem; border: 1px solid var(--border); border-radius: .25rem; color: var(--muted); font-size: .75rem; font-weight: 600; }
.status.partial, .status.failed { color: var(--danger); border-color: currentColor; }
.overview { padding: 1.6rem 0; border-bottom: 1px solid var(--border); }
.coverage { margin: .2rem 0; color: var(--muted); font-size: .875rem; }
.metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); margin-top: 1.5rem; }
.metric { padding: 0 1rem; border-left: 1px solid var(--border); }
.metric:first-child { padding-left: 0; border-left: 0; }
.metric span { display: block; color: var(--muted); font-size: .75rem; }
.metric strong { display: block; margin-top: .3rem; font-size: 1.35rem; line-height: 1.2; font-weight: 650; font-variant-numeric: tabular-nums; }
.metric.critical strong, .metric.high strong { color: var(--danger); }
.metric.medium strong { color: var(--warning); }
.policy, .problems { padding: .8rem 0; border-bottom: 1px solid var(--border); font-size: .875rem; }
.policy p, .problems p { margin: .2rem 0; }
.problems { color: var(--danger); }
.findings-section { margin-top: 2.2rem; }
.findings-section > h2 { margin-bottom: .8rem; }
.findings-section > h2 span { color: var(--muted); font-weight: 400; }
.finding { padding: 1.3rem 0 1.5rem; border-top: 1px solid var(--border); overflow-wrap: anywhere; }
.finding-header { display: flex; align-items: start; justify-content: space-between; flex-wrap: wrap; gap: .75rem; }
.advisory { margin: 0 0 .25rem; color: var(--muted); font-size: .75rem; }
.finding h3 { margin: 0; font-size: 1rem; font-weight: 650; }
.version { color: var(--muted); font-weight: 400; }
.risk { padding: .12rem .45rem; border: 1px solid currentColor; border-radius: .2rem; color: var(--muted); font-size: .7rem; font-weight: 650; }
.finding.critical .risk, .finding.high .risk { color: var(--danger); }
.finding.medium .risk { color: var(--warning); }
.finding-summary { margin: .7rem 0; }
.finding-path { margin: 1rem 0; padding: .7rem .85rem; border-left: 2px solid var(--border); background: var(--soft); font-size: .82rem; }
.finding-path strong, .remediation strong { display: block; margin-bottom: .2rem; color: var(--muted); font-size: .75rem; font-weight: 600; }
.finding-path code { display: block; overflow-wrap: anywhere; }
.remediation { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 2fr); gap: 2rem; margin-top: 1rem; }
.remediation p { margin: 0; font-size: .875rem; }
.references { margin-top: 1rem; color: var(--link); font-size: .8rem; }
.references summary { cursor: pointer; }
.refs { padding-left: 1.25rem; margin: .5rem 0 0; }
a { color: var(--link); text-underline-offset: .15em; }
a:focus-visible, summary:focus-visible { outline: 2px solid var(--link); outline-offset: 3px; }
.empty { padding: 1rem 0; border-top: 1px solid var(--border); color: var(--muted); }
footer { padding: 0 0 2rem; color: var(--muted); font-size: .75rem; overflow-wrap: anywhere; }
@media (max-width: 600px) { .topbar-inner, main, footer { width: calc(100% - 2rem); } main { padding-top: 1.75rem; } .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem 0; } .metric:nth-child(4) { padding-left: 0; border-left: 0; } .remediation { grid-template-columns: 1fr; gap: .8rem; } }
@media (prefers-color-scheme: dark) { :root { --bg: #16181c; --text: #e7e9ed; --muted: #aab0ba; --border: #3c424b; --link: #a6c7ff; --danger: #ff9da3; --warning: #f0cb81; --soft: #22262c; } }
@media print { :root { color-scheme: light; --bg: #fff; --text: #111; --muted: #444; --border: #aaa; --link: #174a8f; --danger: #8d1820; --warning: #704900; --soft: #f5f5f5; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner">ChainWatch</div></header>
<main>
<div class="intro"><h1>Scan results</h1><div class="status ${esc(result.status)}">Status: ${esc(result.status[0]!.toUpperCase() + result.status.slice(1))}</div></div>
${problems.length ? `<section class="problems">${problems.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section class="overview" aria-labelledby="overview-title"><h2 id="overview-title">Coverage</h2>
<p class="coverage">${esc(coverageText(result))}.</p><p class="coverage">${esc(advisoryDataText(result))}.</p>
<div class="metrics" aria-label="Findings by risk level">${breakdown}</div></section>
${policy.length ? `<section class="policy" aria-label="Policy result">${policy.map((l) => `<p>${esc(l)}</p>`).join("")}</section>` : ""}
<section class="findings-section" aria-labelledby="findings-title"><h2 id="findings-title">Findings <span>(${result.findings.length})</span></h2>${findings}</section>
</main>
<footer><p>Project: ${esc(result.rootPath)}<br>Scan ID: ${esc(result.scanId)} &middot; ${esc(result.completedAt)} &middot; ChainWatch ${esc(result.toolVersion)}</p></footer>
</body>
</html>
`;
}
